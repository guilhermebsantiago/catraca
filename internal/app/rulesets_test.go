package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// fakeLabels stands in for the audit database's labels.
type fakeLabels struct {
	mu    sync.Mutex
	stats []precision.RuleStats
	err   error
	calls int
}

func (f *fakeLabels) RuleStats(context.Context, time.Time) ([]precision.RuleStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.stats, f.err
}

func (f *fakeLabels) set(err error, stats ...precision.RuleStats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats, f.err = stats, err
}

func (f *fakeLabels) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// proven are labels that pass the test gate (2 labeled, lower bound 0.3).
func proven(rule string) precision.RuleStats {
	return precision.RuleStats{RuleID: rule, Mode: decision.Shadow, Matches: 3, Labeled: 3, TruePositives: 3}
}

// disproven are labels well below it.
func disproven(rule string) precision.RuleStats {
	return precision.RuleStats{RuleID: rule, Mode: decision.Enforce, Matches: 10, Labeled: 10, FalsePositives: 10}
}

type loaderTest struct {
	t      *testing.T
	l      *rulesetLoader
	holder *rules.Holder
	labels *fakeLabels
	path   string
	logs   *lockedBuffer
	now    time.Time
}

// newLoaderTest returns a loader of a ruleset file in a temporary
// directory, with gate.on_load policy, a gate of 2 labels and a lower bound
// of 0.3, and the watch every interval (0 for off). Nothing is loaded yet.
func newLoaderTest(t *testing.T, policy string, interval time.Duration) *loaderTest {
	t.Helper()
	lt := &loaderTest{t: t, holder: &rules.Holder{}, labels: &fakeLabels{}, logs: &lockedBuffer{},
		path: filepath.Join(t.TempDir(), "rules.yaml"), now: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	cfg := &config.Config{
		Rules: config.Rules{Path: lt.path, WatchInterval: interval},
		Gate:  config.Gate{MinLabeled: 2, MinPrecision: 0.3, OnLoad: policy},
	}
	log := slog.New(slog.NewJSONHandler(lt.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	lt.l = newRulesetLoader(cfg, lt.holder, lt.labels, prometheus.NewRegistry(), log)
	lt.l.now = func() time.Time { return lt.now }
	return lt
}

func (lt *loaderTest) write(content string) {
	lt.t.Helper()
	if err := os.WriteFile(lt.path, []byte(content), 0o600); err != nil {
		lt.t.Fatal(err)
	}
}

func (lt *loaderTest) reload(source string) (*rules.Ruleset, error) {
	return lt.l.reload(context.Background(), source)
}

// check is a look of the watch at the test's clock moved by d.
func (lt *loaderTest) check(d time.Duration) time.Duration {
	lt.now = lt.now.Add(d)
	return lt.l.check(context.Background(), lt.now)
}

// mode returns the mode the current ruleset gives rule id.
func (lt *loaderTest) mode(id string) decision.Mode {
	lt.t.Helper()
	r, ok := lt.holder.Current().Rule(id)
	if !ok {
		lt.t.Fatalf("rule %s is not in the current ruleset", id)
	}
	return r.Mode
}

func (lt *loaderTest) loads(result string) float64 {
	lt.t.Helper()
	var m dto.Metric
	if err := lt.l.loads.WithLabelValues(result).Write(&m); err != nil {
		lt.t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func (lt *loaderTest) version() string {
	if rs := lt.holder.Current(); rs != nil {
		return rs.Version()
	}
	return ""
}

// gateRules has an enforced rule without an override (a), one with an
// override (b) and a shadow rule (c), whose mode is %s.
const gateRules = `version: 1
rules:
  - id: a
    when: event.type == "send"
    action: block
    mode: enforce
    on_error: open
    reason: a
  - id: b
    when: event.type == "account"
    action: block
    mode: enforce
    on_error: open
    reason: b
    override: {by: alice, reason: a fact, at: 2026-10-15}
  - id: c
    when: event.type == "feedback"
    action: flag
    mode: %s
    on_error: open
    reason: c
`

func gateFile(cMode string) string {
	return strings.Replace(gateRules, "%s", cMode, 1)
}

func holds(st api.RulesetStatus) map[string]string {
	out := map[string]string{}
	for _, h := range append(append([]api.GateHold{}, st.Held...), st.Ungated...) {
		out[h.Rule] = h.Status
	}
	return out
}

// TestGateHoldsUnprovenRules walks a rule through the gate: held in shadow
// mode while it lacks labels, enforced once they prove it, kept enforcing
// when a later load changes something else, and a rule newly switched to
// enforce held in turn.
func TestGateHoldsUnprovenRules(t *testing.T) {
	lt := newLoaderTest(t, config.GateEnforce, 0)
	lt.write(gateFile("shadow"))
	file, err := rules.ParseFile([]byte(gateFile("shadow")), lt.path)
	if err != nil {
		t.Fatal(err)
	}

	rs, err := lt.reload(sourceStart)
	if err != nil {
		t.Fatal(err)
	}
	if lt.mode("a") != decision.Shadow || lt.mode("b") != decision.Enforce || rs != lt.holder.Current() {
		t.Errorf("at start: a %s, b %s; want a held in shadow, b enforcing on its override", lt.mode("a"), lt.mode("b"))
	}
	st := lt.l.Status()
	if want := map[string]string{"a": "insufficient_labels"}; !equalMaps(holds(st), want) || len(st.Ungated) != 0 {
		t.Errorf("held %v, want %v", holds(st), want)
	}
	if st.FileVersion != file.Version() || st.Version == file.Version() || st.Version != rs.Version() || st.Source != sourceStart {
		t.Errorf("status %+v, want the file's version apart from the one decisions use", st)
	}
	if !strings.Contains(lt.logs.String(), "rule a stays in shadow mode: it has not passed the precision gate") {
		t.Errorf("no log says why a is held:\n%s", lt.logs)
	}

	// Labels prove a: the next load lets it enforce.
	lt.labels.set(nil, proven("a"))
	if _, err := lt.reload(sourceAPI); err != nil {
		t.Fatal(err)
	}
	if st := lt.l.Status(); lt.mode("a") != decision.Enforce || len(st.Held) != 0 || st.FileVersion != "" || st.Version != file.Version() {
		t.Errorf("after the labels: a %s, status %+v; want a enforcing and the file's version", lt.mode("a"), st)
	}

	// A rule that enforces keeps enforcing when the file changes elsewhere,
	// even though its precision has since fallen below the gate.
	lt.labels.set(nil, disproven("a"))
	lt.write(strings.Replace(gateFile("shadow"), "reason: c", "reason: c, reworded", 1))
	if _, err := lt.reload(sourceAPI); err != nil {
		t.Fatal(err)
	}
	if lt.mode("a") != decision.Enforce || len(lt.l.Status().Held) != 0 {
		t.Errorf("a %s, held %v; want a still enforcing", lt.mode("a"), lt.l.Status().Held)
	}

	// c switches from shadow to enforce without labels: it is held, a and b
	// are not.
	lt.write(gateFile("enforce"))
	if _, err := lt.reload(sourceSignal); err != nil {
		t.Fatal(err)
	}
	if lt.mode("c") != decision.Shadow || lt.mode("a") != decision.Enforce || lt.mode("b") != decision.Enforce {
		t.Errorf("modes a %s, b %s, c %s; want c held alone", lt.mode("a"), lt.mode("b"), lt.mode("c"))
	}
	if want := map[string]string{"c": "insufficient_labels"}; !equalMaps(holds(lt.l.Status()), want) {
		t.Errorf("held %v, want %v", holds(lt.l.Status()), want)
	}

	// A rule held for being below precision says so.
	lt.labels.set(nil, disproven("c"))
	if _, err := lt.reload(sourceAPI); err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"c": "below_precision"}; !equalMaps(holds(lt.l.Status()), want) || lt.mode("c") != decision.Shadow {
		t.Errorf("held %v, want %v", holds(lt.l.Status()), want)
	}
	if lt.loads("ok") != 5 || lt.loads("error") != 0 {
		t.Errorf("loads ok %v, error %v; want 5 and 0", lt.loads("ok"), lt.loads("error"))
	}
}

func TestGateWarnLetsRulesEnforce(t *testing.T) {
	lt := newLoaderTest(t, config.GateWarn, 0)
	lt.write(gateFile("enforce"))
	rs, err := lt.reload(sourceStart)
	if err != nil {
		t.Fatal(err)
	}
	st := lt.l.Status()
	if lt.mode("a") != decision.Enforce || lt.mode("c") != decision.Enforce || st.FileVersion != "" || st.Version != rs.Version() {
		t.Errorf("a %s, c %s, status %+v; want the file as written", lt.mode("a"), lt.mode("c"), st)
	}
	if want := map[string]string{"a": "insufficient_labels", "c": "insufficient_labels"}; !equalMaps(holds(st), want) || len(st.Held) != 0 {
		t.Errorf("ungated %v, held %v; want %v ungated", st.Ungated, st.Held, want)
	}
	if !strings.Contains(lt.logs.String(), "rule a enforces without having passed the precision gate") {
		t.Errorf("no warning for a:\n%s", lt.logs)
	}
}

func TestGateOffReadsNoLabels(t *testing.T) {
	lt := newLoaderTest(t, config.GateOff, 0)
	lt.write(gateFile("enforce"))
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	if lt.mode("a") != decision.Enforce || lt.labels.count() != 0 || len(holds(lt.l.Status())) != 0 {
		t.Errorf("a %s, %d label reads, holds %v; want the file as written and no reads", lt.mode("a"), lt.labels.count(), holds(lt.l.Status()))
	}
}

// TestGateUnavailable checks that rules the gate cannot check while the
// audit database does not answer stay in shadow mode, and that the gate
// runs again on its own until it can, without loading the file again.
func TestGateUnavailable(t *testing.T) {
	lt := newLoaderTest(t, config.GateEnforce, 0)
	lt.labels.set(errors.New("audit: the database is not open yet"))
	lt.write(gateFile("shadow"))
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"a": gateUnavailable}; lt.mode("a") != decision.Shadow || !equalMaps(holds(lt.l.Status()), want) {
		t.Fatalf("a %s, held %v; want a held as %v", lt.mode("a"), holds(lt.l.Status()), want)
	}
	loaded := lt.l.Status().LoadedAt

	// Still unavailable: nothing changes, and nothing more is logged.
	logged := lt.logs.String()
	if next := lt.check(5 * time.Second); next != gateRetry {
		t.Errorf("next look in %v, want %v", next, gateRetry)
	}
	if lt.labels.count() != 2 || lt.l.Status().LoadedAt != loaded || lt.logs.String() != logged {
		t.Errorf("%d label reads, status %+v, new logs %q; want a second read and no change", lt.labels.count(), lt.l.Status(), strings.TrimPrefix(lt.logs.String(), logged))
	}

	// The database answers and proves a: a enforces, without a new load of
	// the file.
	lt.labels.set(nil, proven("a"))
	lt.check(5 * time.Second)
	st := lt.l.Status()
	if lt.mode("a") != decision.Enforce || len(st.Held) != 0 || st.Source != sourceStart || !st.LoadedAt.After(loaded) {
		t.Errorf("a %s, status %+v; want a enforcing", lt.mode("a"), st)
	}
	if lt.loads("ok") != 1 || !strings.Contains(lt.logs.String(), "the precision gate ran now that the audit database answers") {
		t.Errorf("loads %v, logs:\n%s", lt.loads("ok"), lt.logs)
	}
	// Done: later looks read no labels.
	reads := lt.labels.count()
	lt.check(5 * time.Second)
	if lt.labels.count() != reads {
		t.Errorf("the gate ran again after it could: %d reads, want %d", lt.labels.count(), reads)
	}
}

// TestGateUnavailableThenUnproven checks a rule that waited for the audit
// database and then lacks labels: it stays held, for the right reason, and
// the gate does not keep running.
func TestGateUnavailableThenUnproven(t *testing.T) {
	lt := newLoaderTest(t, config.GateEnforce, time.Minute)
	lt.labels.set(errors.New("down"))
	lt.write(gateFile("shadow"))
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	lt.labels.set(nil)
	lt.check(time.Minute)
	if want := map[string]string{"a": "insufficient_labels"}; lt.mode("a") != decision.Shadow || !equalMaps(holds(lt.l.Status()), want) {
		t.Errorf("a %s, held %v; want %v", lt.mode("a"), holds(lt.l.Status()), want)
	}
	reads := lt.labels.count()
	lt.check(time.Minute)
	if lt.labels.count() != reads {
		t.Errorf("%d label reads, want %d", lt.labels.count(), reads)
	}
}

const watchRules = `version: 1
rules:
  - id: burst
    when: account.sends_1m > %s
    reason: r
`

func watched(threshold string) string { return strings.Replace(watchRules, "%s", threshold, 1) }

// TestWatchReloadsChangedFile checks the watch: a change loads once it has
// stayed the same for watchSettle, a burst of changes loads once, a change
// undone before it settles loads nothing, and an unchanged file is never
// loaded again.
func TestWatchReloadsChangedFile(t *testing.T) {
	lt := newLoaderTest(t, config.GateEnforce, 5*time.Second)
	lt.write(watched("10"))
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	v1 := lt.version()

	if next := lt.check(5 * time.Second); next != 5*time.Second || lt.loads("ok") != 1 {
		t.Fatalf("unchanged: next %v, loads %v", next, lt.loads("ok"))
	}

	lt.write(watched("20"))
	if next := lt.check(5 * time.Second); next != watchSettle || lt.version() != v1 {
		t.Fatalf("first sight of a change: next %v, version %s; want a look in %v and no load", next, lt.version(), watchSettle)
	}
	if next := lt.check(time.Second); next != time.Second || lt.version() != v1 {
		t.Fatalf("change not settled: next %v, version %s", next, lt.version())
	}
	if next := lt.check(time.Second); next != 5*time.Second || lt.version() == v1 {
		t.Fatalf("settled change: next %v, version %s; want it loaded", next, lt.version())
	}
	v2 := lt.version()
	if st := lt.l.Status(); st.Source != sourceWatch || st.LoadedAt != lt.now || lt.loads("ok") != 2 {
		t.Errorf("status %+v, loads %v", st, lt.loads("ok"))
	}
	lt.check(5 * time.Second)
	if lt.loads("ok") != 2 {
		t.Errorf("an unchanged file loaded again: loads %v", lt.loads("ok"))
	}

	// A burst of saves: each one restarts the wait, and only the last
	// loads.
	lt.write(watched("30"))
	lt.check(5 * time.Second)
	lt.write(watched("40"))
	lt.check(1500 * time.Millisecond)
	lt.write(watched("50"))
	lt.check(1500 * time.Millisecond)
	if lt.version() != v2 {
		t.Fatalf("a change loaded before it settled")
	}
	lt.check(2 * time.Second)
	if want, _ := rules.ParseFile([]byte(watched("50")), lt.path); lt.version() != want.Version() || lt.loads("ok") != 3 {
		t.Errorf("version %s, loads %v; want the last save loaded once", lt.version(), lt.loads("ok"))
	}

	// A change undone before it settles loads nothing.
	lt.write(watched("60"))
	lt.check(5 * time.Second)
	lt.write(watched("50"))
	lt.check(time.Second)
	lt.check(5 * time.Second)
	if lt.loads("ok") != 3 {
		t.Errorf("an undone change loaded: loads %v", lt.loads("ok"))
	}
}

// TestWatchKeepsServingThroughBrokenFiles checks that a file that does not
// parse, or disappears, leaves the ruleset serving, is reported once, and
// that the next good content loads.
func TestWatchKeepsServingThroughBrokenFiles(t *testing.T) {
	lt := newLoaderTest(t, config.GateEnforce, 5*time.Second)
	lt.write(watched("10"))
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	v1 := lt.version()

	lt.write(watched("10 &&"))
	lt.check(5 * time.Second)
	lt.check(watchSettle)
	if lt.version() != v1 || lt.loads("error") != 1 {
		t.Fatalf("broken file: version %s, errors %v; want v1 serving and one error", lt.version(), lt.loads("error"))
	}
	if st := lt.l.Status(); st.FailedAt != lt.now || st.Version != v1 {
		t.Errorf("status %+v, want the failure recorded and v1 serving", st)
	}
	for range 3 {
		lt.check(5 * time.Second)
	}
	if lt.loads("error") != 1 || strings.Count(lt.logs.String(), "ruleset did not load") != 1 {
		t.Errorf("a broken file was reported %v times, want once", lt.loads("error"))
	}

	if err := os.Remove(lt.path); err != nil {
		t.Fatal(err)
	}
	lt.check(5 * time.Second)
	lt.check(watchSettle)
	if lt.version() != v1 || lt.loads("error") != 2 {
		t.Errorf("missing file: version %s, errors %v", lt.version(), lt.loads("error"))
	}

	lt.write(watched("20"))
	lt.check(5 * time.Second)
	lt.check(watchSettle)
	if lt.version() == v1 || lt.l.Status().FailedAt != (time.Time{}) {
		t.Errorf("the fixed file did not load: version %s, status %+v", lt.version(), lt.l.Status())
	}
}

// TestWatchFollowsConfigMapSwap checks the watch against the layout of a
// Kubernetes ConfigMap volume: the file is a symlink into ..data, itself a
// symlink to a timestamped directory, and an update writes a new directory
// and renames a new ..data over the old one, never touching the file the
// path names.
func TestWatchFollowsConfigMapSwap(t *testing.T) {
	dir := t.TempDir()
	version := func(name, content string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "rules.yaml"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	version("..2026_10_23_12_00_00.1", watched("10"))
	if err := os.Symlink("..2026_10_23_12_00_00.1", filepath.Join(dir, "..data")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "rules.yaml"), filepath.Join(dir, "rules.yaml")); err != nil {
		t.Fatal(err)
	}

	lt := newLoaderTest(t, config.GateEnforce, 5*time.Second)
	lt.l.path = filepath.Join(dir, "rules.yaml")
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	v1 := lt.version()

	// The kubelet's atomic writer: a new directory, a new link, a rename.
	version("..2026_10_23_12_01_00.2", watched("20"))
	if err := os.Symlink("..2026_10_23_12_01_00.2", filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("renaming over a directory symlink fails on Windows: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "..2026_10_23_12_00_00.1")); err != nil {
		t.Fatal(err)
	}

	lt.check(5 * time.Second)
	lt.check(watchSettle)
	want, _ := rules.ParseFile([]byte(watched("20")), lt.l.path)
	if lt.version() == v1 || lt.version() != want.Version() || lt.l.Status().Source != sourceWatch {
		t.Errorf("version %s after the swap, want %s from the watch", lt.version(), want.Version())
	}
}

// TestWatchRetriesGateWhileOff checks that with the watch off, its looks
// still run a gate that could not run, but never read the file.
func TestWatchRetriesGateWhileOff(t *testing.T) {
	lt := newLoaderTest(t, config.GateEnforce, 0)
	lt.labels.set(errors.New("down"))
	lt.write(gateFile("shadow"))
	if _, err := lt.reload(sourceStart); err != nil {
		t.Fatal(err)
	}
	lt.write(gateFile("enforce"))
	lt.labels.set(nil, proven("a"))
	if next := lt.check(gateRetry); next != gateRetry {
		t.Errorf("next look in %v, want %v", next, gateRetry)
	}
	if lt.mode("a") != decision.Enforce || lt.mode("c") != decision.Shadow || lt.loads("ok") != 1 {
		t.Errorf("a %s, c %s, loads %v; want a released and the edited file not loaded", lt.mode("a"), lt.mode("c"), lt.loads("ok"))
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
