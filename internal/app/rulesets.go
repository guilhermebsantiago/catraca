package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// What loaded a ruleset, as /readyz?verbose, the metrics and the log name
// it.
const (
	sourceStart  = "start"
	sourceWatch  = "watch"
	sourceSignal = "signal"
	sourceAPI    = "api"
)

const (
	// watchSettle is how long a changed ruleset file must keep the same
	// content before the watch loads it, so that a file still being
	// written, or a burst of saves, loads once and whole.
	watchSettle = 2 * time.Second
	// gateRetry is how often a precision gate that could not run is tried
	// again while the watch is off; with the watch on, each look tries it.
	gateRetry = 5 * time.Second
	// gateTimeout bounds the audit database query behind the gate.
	gateTimeout = 10 * time.Second
)

// gateUnavailable is the gate's verdict on a rule whose labels could not be
// read.
const gateUnavailable = "unavailable"

// rulesetLoader loads the ruleset file into the holder decisions read it
// from: at start, on SIGHUP, on POST /v1/rules/reload, and when the watch
// sees the file change. A load reads the file once, parses and compiles it
// as catraca rules check does, puts the rules it would newly enforce
// through the precision gate (see gateCheck), and swaps the result in
// atomically. A file that does not load leaves the current ruleset
// serving.
//
// The watch polls the file's content instead of waiting for file system
// events. A Kubernetes ConfigMap volume changes a file by swapping a
// symlink, ..data, to a new directory: a watch on the file never sees it,
// and a watch on the directory sees events on other names. Editors replace
// a file by renaming another over it, and network and FUSE file systems
// may send no events at all. Reading a file of a few kilobytes every few
// seconds and comparing its hash costs next to nothing, behaves the same
// everywhere and needs no dependency.
type rulesetLoader struct {
	path string
	// interval is rules.watch_interval; 0 turns the watch off.
	interval time.Duration
	holder   *rules.Holder
	// policy is gate.on_load.
	policy string
	gate   precision.Gate
	// stats reads the labeled outcomes of every rule, for the gate.
	stats func(context.Context) ([]precision.RuleStats, error)
	hooks []config.Hook
	// entities are the names of engine.entities, for LintEntities.
	entities []string
	log      *slog.Logger
	loads    *prometheus.CounterVec
	now      func() time.Time

	// mu serializes loads and the watch's looks, and guards the fields
	// below it.
	mu sync.Mutex
	// loadedHash is the hash of what the last load read, whether it loaded
	// or not, so that a broken file is reported once rather than at every
	// look. pendingHash is other content the watch has seen since
	// pendingSince, waiting for it to settle.
	loadedHash   string
	pendingHash  string
	pendingSince time.Time
	// file is the last ruleset that loaded, as written, and regate says
	// that the gate could not run on it and holds rules until it does.
	file   *rules.Ruleset
	regate bool

	// status is what /readyz?verbose and the metrics show. It is replaced
	// whole, never changed in place.
	status atomic.Pointer[api.RulesetStatus]
}

// labels reads the labeled outcomes of rules since a time; the audit log
// is one.
type labels interface {
	RuleStats(ctx context.Context, since time.Time) ([]precision.RuleStats, error)
}

func newRulesetLoader(cfg *config.Config, holder *rules.Holder, lb labels, reg prometheus.Registerer, log *slog.Logger) *rulesetLoader {
	l := &rulesetLoader{
		path:     cfg.Rules.Path,
		interval: cfg.Rules.WatchInterval,
		holder:   holder,
		policy:   cfg.Gate.OnLoad,
		gate:     cfg.Gate.Precision(),
		// Labels count over all time, as in catraca rules gate.
		stats:    func(ctx context.Context) ([]precision.RuleStats, error) { return lb.RuleStats(ctx, time.Time{}) },
		hooks:    cfg.Hooks,
		entities: cfg.Engine.EntityNames(),
		log:      log,
		loads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_ruleset_loads_total",
			Help: "Ruleset loads at start and on reload, by result (ok or error).",
		}, []string{"result"}),
		now: time.Now,
	}
	l.loads.WithLabelValues("ok")
	l.loads.WithLabelValues("error")
	l.status.Store(&api.RulesetStatus{Path: l.path, Gate: l.policy})
	reg.MustRegister(l.loads, rulesetLoadCollector{l})
	return l
}

// Status describes the current ruleset for /readyz?verbose.
func (l *rulesetLoader) Status() api.RulesetStatus { return *l.status.Load() }

// reload reads the ruleset file and loads it; source says what asked.
func (l *rulesetLoader) reload(ctx context.Context, source string) (*rules.Ruleset, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(l.path)
	return l.load(ctx, source, data, err)
}

// load makes data, read from the ruleset file with readErr, the current
// ruleset if it parses and compiles, with the rules the gate holds back in
// shadow mode. Otherwise it logs why and changes nothing. l.mu is held.
func (l *rulesetLoader) load(ctx context.Context, source string, data []byte, readErr error) (*rules.Ruleset, error) {
	l.loadedHash, l.pendingHash = contentHash(data, readErr), ""
	prev := l.holder.Current()
	var file, rs *rules.Ruleset
	var holds []api.GateHold
	var unavailable bool
	err := readErr
	if err == nil {
		file, err = rules.ParseFile(data, l.path)
	}
	if err == nil {
		rs, holds, unavailable, err = l.gated(ctx, file, prev, false)
	}
	if err != nil {
		l.loads.WithLabelValues("error").Inc()
		attrs := []any{"path", l.path, "source", source, "error", err}
		if prev != nil {
			attrs = append(attrs, "serving_version", prev.Version())
		}
		l.log.Error("ruleset did not load", attrs...)
		st := l.Status()
		st.FailedAt = l.now()
		l.status.Store(&st)
		return nil, err
	}
	l.loads.WithLabelValues("ok").Inc()
	l.file = file
	l.swap(source, file, rs, holds, unavailable)

	attrs := []any{"path", l.path, "source", source, "version", rs.Version(), "rules", len(rs.Rules()), "enforced", enforced(rs)}
	if rs != file {
		attrs = append(attrs, "file_version", file.Version(), "held", ruleIDs(holds))
	}
	if prev != nil {
		attrs = append(attrs, "previous_version", prev.Version())
	}
	l.log.Info("ruleset loaded", attrs...)
	for _, w := range file.Lint() {
		l.log.Warn("ruleset warning", "warning", w.String())
	}
	for _, w := range file.LintEntities(l.entities) {
		l.log.Warn("ruleset warning", "warning", w.String())
	}
	for _, m := range MissingHooks(file, l.hooks) {
		l.log.Warn("ruleset warning", "warning", m)
	}
	return rs, nil
}

// retryGate runs the gate again on the file last loaded, when it could not
// run then, and swaps in what it decides once it can run. l.mu is held.
func (l *rulesetLoader) retryGate(ctx context.Context) {
	prev := l.holder.Current()
	rs, holds, unavailable, err := l.gated(ctx, l.file, prev, true)
	switch {
	case err != nil:
		l.log.Error("the precision gate ran again, but the ruleset could not be built", "path", l.path, "error", err)
		return
	case unavailable:
		// Still not: the rules stay held, and the first attempt logged why.
		return
	}
	st := l.Status()
	l.swap(st.Source, l.file, rs, holds, false)
	l.log.Info("the precision gate ran now that the audit database answers", "path", l.path,
		"version", rs.Version(), "previous_version", prev.Version(), "held", ruleIDs(holds))
}

// gated returns the ruleset to decide with for file: file itself, or a copy
// with the rules the gate holds in shadow mode. holds are the rules that
// did not pass, held or not, and unavailable says the gate could not run.
// retrying says the gate could not run before, which was logged then.
func (l *rulesetLoader) gated(ctx context.Context, file, prev *rules.Ruleset, retrying bool) (rs *rules.Ruleset, holds []api.GateHold, unavailable bool, err error) {
	holds, unavailable = l.gateCheck(ctx, file, prev, retrying)
	if len(holds) == 0 || l.policy != config.GateEnforce {
		return file, holds, unavailable, nil
	}
	rs, err = file.WithShadow(ruleIDs(holds)...)
	return rs, holds, unavailable, err
}

// swap makes rs current and records it for /readyz?verbose and the
// metrics. l.mu is held.
func (l *rulesetLoader) swap(source string, file, rs *rules.Ruleset, holds []api.GateHold, unavailable bool) {
	st := &api.RulesetStatus{Version: rs.Version(), Path: l.path, Source: source, LoadedAt: l.now(), Gate: l.policy}
	if rs != file {
		st.FileVersion = file.Version()
	}
	if l.policy == config.GateEnforce {
		st.Held = holds
	} else {
		st.Ungated = holds
	}
	l.regate = unavailable && l.policy == config.GateEnforce
	l.holder.Store(rs)
	l.status.Store(st)
}

// gateCheck puts through the precision gate the rules file would make
// enforce that the server does not enforce now: rules new in enforce mode
// or switched to it from shadow, and rules prev holds in shadow mode for
// the gate. A rule prev enforces already keeps enforcing: it passed the
// gate when it started, or enforced before this server did, and only a
// change of mode, not of condition, starts a promotion. A rule with an
// override is not checked, as in catraca rules gate. It returns the
// checked rules that did not pass, and all of them with unavailable set
// when the audit database could not answer, which it logs unless
// retrying.
func (l *rulesetLoader) gateCheck(ctx context.Context, file, prev *rules.Ruleset, retrying bool) (holds []api.GateHold, unavailable bool) {
	if l.policy == config.GateOff {
		return nil, false
	}
	var candidates []precision.RuleInfo
	for _, r := range file.Rules() {
		if r.Mode != decision.Enforce || r.Override != nil {
			continue
		}
		if prev != nil {
			if p, ok := prev.Rule(r.ID); ok && p.Mode == decision.Enforce {
				continue
			}
		}
		candidates = append(candidates, precision.RuleInfo{ID: r.ID, Mode: r.Mode})
	}
	if len(candidates) == 0 {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(ctx, gateTimeout)
	defer cancel()
	stats, err := l.stats(ctx)
	if err != nil {
		for _, c := range candidates {
			holds = append(holds, api.GateHold{Rule: c.ID, Status: gateUnavailable})
		}
		switch {
		case retrying:
		case l.policy == config.GateEnforce:
			l.log.Warn("the precision gate cannot read the labels in the audit database, so the rules it would check stay in shadow mode until it can; it is tried again every few seconds",
				"rules", ruleIDs(holds), "error", err)
		default:
			l.log.Warn("the precision gate cannot read the labels in the audit database; these rules enforce without it",
				"rules", ruleIDs(holds), "error", err)
		}
		return holds, true
	}
	for _, res := range l.gate.EvaluateRules(candidates, stats) {
		if res.Status == precision.Passes {
			continue
		}
		holds = append(holds, api.GateHold{Rule: res.RuleID, Status: string(res.Status)})
		attrs := []any{"rule", res.RuleID, "status", res.Status, "labeled", res.Labeled, "true_positives", res.TruePositives,
			"precision_lower", res.Lower, "min_labeled", l.gate.MinLabeled, "min_precision", l.gate.MinPrecision}
		if l.policy == config.GateEnforce {
			l.log.Warn(fmt.Sprintf("rule %s stays in shadow mode: it has not passed the precision gate; label its matches (GET /v1/rules/%s/review) or give it an override, then reload", res.RuleID, res.RuleID), attrs...)
		} else {
			l.log.Warn(fmt.Sprintf("rule %s enforces without having passed the precision gate", res.RuleID), attrs...)
		}
	}
	return holds, false
}

// wait is how long the watch waits before its first look.
func (l *rulesetLoader) wait() time.Duration {
	if l.interval > 0 {
		return l.interval
	}
	return gateRetry
}

// check is one look of the watch, at now. With the watch on, it loads the
// file when its content differs from what the last load read and has stayed
// the same for watchSettle. Then it runs the gate again if it could not run
// at the last load. It returns how long to wait before the next look.
func (l *rulesetLoader) check(ctx context.Context, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := l.wait()
	if l.interval > 0 {
		data, err := os.ReadFile(l.path)
		switch h := contentHash(data, err); {
		case h == l.loadedHash:
			// Unchanged, or changed back before it settled.
			l.pendingHash = ""
		case h != l.pendingHash:
			l.pendingHash, l.pendingSince = h, now
			return min(next, watchSettle)
		case now.Sub(l.pendingSince) < watchSettle:
			return min(next, watchSettle-now.Sub(l.pendingSince))
		default:
			_, _ = l.load(ctx, sourceWatch, data, err)
			return next
		}
	}
	if l.regate && l.file != nil {
		l.retryGate(ctx)
	}
	return next
}

// contentHash identifies what reading the ruleset file gave: its content,
// or the error.
func contentHash(data []byte, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func enforced(rs *rules.Ruleset) int {
	n := 0
	for _, r := range rs.Rules() {
		if r.Mode == decision.Enforce {
			n++
		}
	}
	return n
}

func ruleIDs(holds []api.GateHold) []string {
	ids := make([]string, len(holds))
	for i, h := range holds {
		ids[i] = h.Rule
	}
	return ids
}

// watchRules runs the ruleset watch, and the retries of a gate that could
// not run, until the returned function is called.
func (a *App) watchRules() (stop func()) {
	l := a.rulesets
	if l.interval > 0 {
		a.log.Info("watching the ruleset file for changes", "path", l.path, "interval", l.interval)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTimer(l.wait())
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-timer.C:
				timer.Reset(l.check(ctx, now))
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

var (
	rulesetLoadedDesc = prometheus.NewDesc("catraca_ruleset_loaded_timestamp_seconds",
		"When the current ruleset was loaded, in Unix seconds, labeled by what loaded it: start, watch, signal or api. Absent while no ruleset is loaded.",
		[]string{"source"}, nil)
	rulesetGateDesc = prometheus.NewDesc("catraca_ruleset_gate_failures",
		"Rules the ruleset file enforces that had not passed the precision gate when it loaded, by gate status: held in shadow mode with gate.on_load enforce, enforcing with warn.",
		[]string{"status"}, nil)
)

// gateStatuses are the values of the status label of
// catraca_ruleset_gate_failures, each exported even at 0.
var gateStatuses = []string{string(precision.InsufficientLabels), string(precision.BelowPrecision), gateUnavailable}

// rulesetLoadCollector exports where the current ruleset came from and
// what the gate held back, at scrape time.
type rulesetLoadCollector struct{ l *rulesetLoader }

func (rulesetLoadCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- rulesetLoadedDesc
	ch <- rulesetGateDesc
}

func (c rulesetLoadCollector) Collect(ch chan<- prometheus.Metric) {
	st := c.l.Status()
	if st.Version == "" {
		return
	}
	ch <- prometheus.MustNewConstMetric(rulesetLoadedDesc, prometheus.GaugeValue, float64(st.LoadedAt.UnixNano())/1e9, st.Source)
	count := map[string]int{}
	for _, holds := range [][]api.GateHold{st.Held, st.Ungated} {
		for _, h := range holds {
			count[h.Status]++
		}
	}
	for _, s := range gateStatuses {
		ch <- prometheus.MustNewConstMetric(rulesetGateDesc, prometheus.GaugeValue, float64(count[s]), s)
	}
}
