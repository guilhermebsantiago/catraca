// Package engine decides events. For each event it computes the signals
// under a deadline, evaluates the current ruleset, combines the enforced
// matches into one action and hands the decision to the audit log and, when
// enforced rules call for effects, to the hooks. A broken or slow store
// degrades detection; it never blocks everyone.
package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

const (
	// DefaultDeadline bounds Catalog.Observe when Options.Deadline is zero.
	DefaultDeadline = 10 * time.Millisecond
	// DefaultRecordQueue is the number of decisions that may wait for the
	// Recorder when Options.RecordQueue is zero.
	DefaultRecordQueue = 4096
)

var (
	// ErrInvalidEvent wraps the reason an event was rejected. Nothing was
	// observed for it.
	ErrInvalidEvent = errors.New("invalid event")
	// ErrNoRuleset means the rule source has no ruleset loaded.
	ErrNoRuleset = errors.New("engine: no ruleset loaded")
)

// Recorder receives every decision, for example to write the audit log.
// Record is called from one background goroutine, in decision order, with a
// context that is never canceled. While it blocks, decisions wait in a
// bounded queue; when the queue is full they are dropped and counted in
// catraca_records_dropped_total, so a slow audit database never slows sends.
// The decision shares its slices with the one Decide returns, so neither
// side may modify them.
type Recorder interface {
	Record(ctx context.Context, ev event.Event, d decision.Decision)
}

// Dispatcher triggers the effects of enforced matches, such as a webhook
// that revokes a key. Dispatch is called synchronously by Decide, only for
// decisions with enforced effects (decision.Decision.Effects: never those
// of shadow matches or of rules that matched only by failing closed), with
// a context that is not canceled when the caller goes away. It should
// persist the work, for example to an outbox, and deliver it in the
// background.
type Dispatcher interface {
	Dispatch(ctx context.Context, ev event.Event, d decision.Decision)
}

// RuleSource provides the ruleset to decide with. *rules.Holder is one.
type RuleSource interface {
	Current() *rules.Ruleset
}

// Options configure an Engine. Catalog and Rules are required.
type Options struct {
	Catalog signal.Catalog
	Rules   RuleSource
	// Recorder, when set, receives every decision.
	Recorder Recorder
	// Dispatcher, when set, receives decisions with enforced effects.
	Dispatcher Dispatcher
	// Deadline bounds Catalog.Observe; zero means DefaultDeadline. When it
	// expires the decision is degraded and rules run on the signals Observe
	// returned.
	Deadline time.Duration
	// RecordQueue is how many decisions may wait for the Recorder; zero
	// means DefaultRecordQueue.
	RecordQueue int
	// Registerer receives the engine's metrics. When nil the metrics are
	// kept but not registered anywhere.
	Registerer prometheus.Registerer
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// Logger receives store failures and dropped records, at most once per
	// second each. Nil discards them.
	Logger *slog.Logger
}

// Engine decides events. It is safe for concurrent use.
type Engine struct {
	catalog    signal.Catalog
	rules      RuleSource
	dispatcher Dispatcher
	deadline   time.Duration
	now        func() time.Time
	log        *slog.Logger
	metrics    *metrics
	records    *recordQueue
	ids        idSource

	observeLog, dropLog limiter
}

// New returns an Engine. When a Recorder is set it starts the goroutine that
// feeds it; call Close to stop it.
func New(opts Options) (*Engine, error) {
	if opts.Catalog == nil {
		return nil, errors.New("engine: Options.Catalog is required")
	}
	if opts.Rules == nil {
		return nil, errors.New("engine: Options.Rules is required")
	}
	if opts.Deadline < 0 || opts.RecordQueue < 0 {
		return nil, errors.New("engine: Options.Deadline and Options.RecordQueue must not be negative")
	}
	m, err := newMetrics(opts.Registerer)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		catalog:    opts.Catalog,
		rules:      opts.Rules,
		dispatcher: opts.Dispatcher,
		deadline:   cmp.Or(opts.Deadline, DefaultDeadline),
		now:        opts.Now,
		log:        opts.Logger,
		metrics:    m,
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if opts.Recorder != nil {
		e.records = newRecordQueue(opts.Recorder, cmp.Or(opts.RecordQueue, DefaultRecordQueue))
	}
	return e, nil
}

// Decide decides one event:
//
//  1. validate and normalize it and assign its id (an id the platform sent
//     is kept);
//  2. for key_leak events, mark the key leaked;
//  3. observe the signals under the deadline, marking the decision degraded
//     when the catalog fails;
//  4. evaluate every rule: the most severe enforced match is the action,
//     shadow matches are recorded, and rules that cannot be evaluated follow
//     on_error;
//  5. queue the decision for the Recorder and, when enforced rules that
//     matched have effects, call the Dispatcher.
//
// Decide returns an error only when nothing was observed, so the caller may
// retry: the event is invalid (ErrInvalidEvent), no ruleset is loaded
// (ErrNoRuleset), or a leaked key could not be recorded.
func (e *Engine) Decide(ctx context.Context, ev event.Event) (decision.Decision, error) {
	start := e.now()
	if err := ev.Validate(); err != nil {
		return decision.Decision{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	rs := e.rules.Current()
	if rs == nil {
		return decision.Decision{}, ErrNoRuleset
	}
	ev = detach(ev)
	ev.Normalize(start)
	if ev.ID == "" {
		ev.ID = e.ids.next(start)
	}

	// The key is marked before Observe so that this event's own signals,
	// and every later one, see key.leaked.
	if ev.Type == event.KeyLeak {
		if err := e.catalog.MarkLeaked(ctx, ev.APIKeyID); err != nil {
			return decision.Decision{}, fmt.Errorf("engine: mark key %s leaked: %w", ev.APIKeyID, err)
		}
	}

	octx, cancel := context.WithTimeout(ctx, e.deadline)
	set, err := e.catalog.Observe(octx, ev)
	cancel()
	degraded := err != nil
	if degraded && e.observeLog.allow(start) {
		e.log.Warn("signals unavailable; deciding degraded", "error", err, "event_type", ev.Type)
	}

	out := rs.Apply(set)
	d := decision.Decision{
		ID:             e.ids.next(start),
		EventID:        ev.ID,
		Time:           start,
		Action:         out.Action,
		RetryAfter:     out.RetryAfter,
		Matches:        out.Matches,
		Shadow:         out.Shadow,
		Errors:         out.Errors,
		Degraded:       degraded,
		RulesetVersion: rs.Version(),
	}
	elapsed := e.now().Sub(start)
	d.LatencyMicros = elapsed.Microseconds()
	e.metrics.observe(d, elapsed)

	if e.records != nil && !e.records.push(recordJob{context.WithoutCancel(ctx), ev, d}) {
		e.metrics.dropped.Inc()
		if e.dropLog.allow(start) {
			e.log.Warn("recorder queue is full; dropping decisions from the audit log", "decision_id", d.ID)
		}
	}
	if e.dispatcher != nil && len(d.Effects()) > 0 {
		e.dispatcher.Dispatch(context.WithoutCancel(ctx), ev, d)
	}
	return d, nil
}

// Close stops the Recorder goroutine after it records the decisions already
// queued, or returns ctx's error when ctx ends first. Decisions made during
// or after Close are not recorded. Close does not close the Catalog.
func (e *Engine) Close(ctx context.Context) error {
	if e.records == nil {
		return nil
	}
	return e.records.close(ctx)
}

// detach copies the parts of ev that Normalize modifies in place, so
// deciding never rewrites the caller's slices.
func detach(ev event.Event) event.Event {
	ev.To = slices.Clone(ev.To)
	if ev.Feedback != nil {
		f := *ev.Feedback
		ev.Feedback = &f
	}
	return ev
}

// limiter lets one log line through per second, so an outage that fails
// every decision does not flood the logs.
type limiter struct {
	last atomic.Int64
}

func (l *limiter) allow(now time.Time) bool {
	last := l.last.Load()
	if now.UnixNano()-last < int64(time.Second) {
		return false
	}
	return l.last.CompareAndSwap(last, now.UnixNano())
}
