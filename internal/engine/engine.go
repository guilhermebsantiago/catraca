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
	"github.com/guilhermebsantiago/catraca/internal/monotime"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

const (
	// DefaultDeadline bounds Catalog.Observe when Options.Deadline is zero.
	DefaultDeadline = 10 * time.Millisecond
	// DefaultRecordQueue is the number of decisions that may wait for the
	// Recorder when Options.RecordQueue is zero.
	DefaultRecordQueue = 4096
	// DefaultMaxFutureSkew is Options.MaxFutureSkew when it is zero: room for
	// ordinary drift between the platform's clocks and Catraca's, yet a time
	// this far ahead pushes only a few seconds out of the 1 minute window.
	DefaultMaxFutureSkew = 5 * time.Second
	// DefaultMaxEventAge is Options.MaxEventAge when it is zero: the longest
	// counter window, so every event a counter can still use is accepted,
	// however late it arrives.
	DefaultMaxEventAge = 7 * 24 * time.Hour
)

var (
	// ErrInvalidEvent wraps the reason an event was rejected. Nothing was
	// observed for it. It is event.ErrInvalid, so packages that do not import
	// the engine can recognize it.
	ErrInvalidEvent = event.ErrInvalid
	// ErrNoRuleset means the rule source has no ruleset loaded.
	ErrNoRuleset = errors.New("engine: no ruleset loaded")
)

// Recorder receives every decision, for example to write the audit log.
// Record is called from one background goroutine, in decision order, with a
// context that is never canceled. While it blocks, decisions wait in a
// bounded queue; when the queue is full they are dropped and counted in
// catraca_records_dropped_total, so a slow audit database never slows sends.
// Engine.Sync waits for the decisions made so far to reach Record. The
// decision shares its slices with the one Decide returns, so neither side
// may modify them.
type Recorder interface {
	Record(ctx context.Context, ev event.Event, d decision.Decision)
}

// Dispatcher triggers the effects of enforced matches, such as a webhook
// that revokes a key. Dispatch is called synchronously by Decide, only for
// decisions with enforced effects (decision.Decision.Effects: never those
// of shadow matches or of rules that matched only by failing closed), with
// a context that is not canceled when the caller goes away but ends with
// the dispatch budget (Options.DispatchTimeout). It should persist the work,
// for example to an outbox, deliver it in the background, and return by
// the end of the budget: work not persisted by then it should go on with in
// the background, and count and log what it loses, because Decide answers
// regardless.
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
	// Deadline bounds Catalog.Observe and, for key_leak events,
	// Catalog.MarkLeaked, each; zero means DefaultDeadline. When it expires
	// during Observe the decision is degraded and rules run on the signals
	// Observe returned; during MarkLeaked, Decide returns an error.
	Deadline time.Duration
	// DispatchTimeout is how long Decide waits for the Dispatcher, the
	// dispatch budget; zero means Deadline. A decision with effects costs
	// at most this much more than one without, however slow the outbox.
	DispatchTimeout time.Duration
	// RecordQueue is how many decisions may wait for the Recorder; zero
	// means DefaultRecordQueue.
	RecordQueue int
	// Registerer receives the engine's metrics. When nil the metrics are
	// kept but not registered anywhere.
	Registerer prometheus.Registerer
	// MaxFutureSkew is how far ahead of the clock (Now) an event's time may
	// be. A later time is replaced by the clock's: the event cannot have
	// happened yet, and counted in the future it would push every window it
	// touches past the events that arrive next, hiding them until the clock
	// catches up. Zero means DefaultMaxFutureSkew.
	MaxFutureSkew time.Duration
	// MaxEventAge is how far behind the clock an event's time may be. An
	// older event is rejected with ErrInvalidEvent: no counter reaches back
	// to it, and all it could still change are first-seen times, making an
	// account or key look older than it is. A key_leak event is never
	// refused for its age; it takes the clock's time instead. Zero means
	// DefaultMaxEventAge.
	MaxEventAge time.Duration
	// TrustEventTime turns both bounds off, so event times are used as sent.
	// Replays set it: their events are historical, and the clock that
	// matters is the events' own.
	TrustEventTime bool
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// Logger receives store failures, dropped records and event times ahead
	// of the clock, at most once per second each. Nil discards them.
	Logger *slog.Logger
}

// Engine decides events. It is safe for concurrent use.
type Engine struct {
	catalog    signal.Catalog
	rules      RuleSource
	dispatcher Dispatcher
	deadline   time.Duration
	// dispatchTimeout bounds the wait for the dispatcher.
	dispatchTimeout time.Duration
	// maxFuture and maxAge bound event times; trustTime turns the bounds off.
	maxFuture, maxAge time.Duration
	trustTime         bool
	now               func() time.Time
	// fakeClock is set when Options.Now is, so tests that control the
	// clock also control the measured latency.
	fakeClock bool
	log       *slog.Logger
	metrics   *metrics
	records   *recordQueue
	ids       idSource

	observeLog, dropLog, futureLog limiter
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
	if opts.Deadline < 0 || opts.DispatchTimeout < 0 || opts.RecordQueue < 0 || opts.MaxFutureSkew < 0 || opts.MaxEventAge < 0 {
		return nil, errors.New("engine: Options.Deadline, DispatchTimeout, RecordQueue, MaxFutureSkew and MaxEventAge must not be negative")
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
		maxFuture:  cmp.Or(opts.MaxFutureSkew, DefaultMaxFutureSkew),
		maxAge:     cmp.Or(opts.MaxEventAge, DefaultMaxEventAge),
		trustTime:  opts.TrustEventTime,
		now:        opts.Now,
		fakeClock:  opts.Now != nil,
		log:        opts.Logger,
		metrics:    m,
	}
	e.dispatchTimeout = cmp.Or(opts.DispatchTimeout, e.deadline)
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
//  1. validate and normalize it, and bound its time to the clock (see
//     Options.MaxFutureSkew and Options.MaxEventAge);
//  2. for key_leak events, mark the key leaked, under the deadline;
//  3. observe the signals under the deadline, marking the decision degraded
//     when the catalog fails, and also uncounted when it failed rather than
//     answered late; an event whose id counted already does not count
//     again, and its decision is marked duplicate; then give the event an
//     id if the platform sent none;
//  4. evaluate every rule: the most severe enforced match is the action,
//     shadow matches are recorded, and rules that cannot be evaluated follow
//     on_error;
//  5. queue the decision for the Recorder and, when enforced rules that
//     matched have effects, call the Dispatcher, for at most the dispatch
//     budget (Options.DispatchTimeout).
//
// Decide returns an error only when nothing was observed, so the caller may
// retry: the event is invalid (ErrInvalidEvent), no ruleset is loaded
// (ErrNoRuleset), or a leaked key could not be recorded.
func (e *Engine) Decide(ctx context.Context, ev event.Event) (decision.Decision, error) {
	start := e.now()
	mono := monotime.Now()
	if err := ev.Validate(); err != nil {
		return decision.Decision{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	rs := e.rules.Current()
	if rs == nil {
		return decision.Decision{}, ErrNoRuleset
	}
	ev = detach(ev)
	ev.Normalize(start)
	if err := e.boundTime(&ev, start); err != nil {
		return decision.Decision{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}

	// The key is marked before Observe so that this event's own signals,
	// and every later one, see key.leaked. The write has the deadline
	// Observe has: with the store unreachable, the client's own dial and
	// read timeouts would hold the request for seconds. The catalog
	// remembers the key either way, and the error tells the caller to send
	// the event again.
	if ev.Type == event.KeyLeak {
		mctx, cancel := context.WithTimeout(ctx, e.deadline)
		err := e.catalog.MarkLeaked(mctx, ev.APIKeyID)
		cancel()
		if err != nil {
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
	// The catalog counts an event with an id once per id, so the id is
	// generated only now: the platform's id makes its retries count once,
	// and a generated one, which never repeats, would only cost the store
	// an entry.
	if ev.ID == "" {
		ev.ID = e.ids.next(start)
	}

	out := rs.Apply(set)
	d := decision.Decision{
		ID:             e.ids.next(start),
		EventID:        ev.ID,
		Time:           start.UTC(),
		Action:         out.Action,
		RetryAfter:     out.RetryAfter,
		Matches:        out.Matches,
		Shadow:         out.Shadow,
		Errors:         out.Errors,
		Degraded:       degraded,
		Uncounted:      degraded && !late(err),
		Duplicate:      set.Duplicate,
		RulesetVersion: rs.Version(),
	}
	elapsed := monotime.Since(mono)
	if e.fakeClock {
		elapsed = e.now().Sub(start)
	}
	d.LatencyMicros = elapsed.Microseconds()
	e.metrics.observe(d, elapsed)
	if d.Duplicate {
		e.metrics.duplicates.WithLabelValues(string(ev.Type)).Inc()
	}

	if e.records != nil && !e.records.push(recordJob{ctx: context.WithoutCancel(ctx), ev: ev, d: d}) {
		e.metrics.dropped.Inc()
		if e.dropLog.allow(start) {
			e.log.Warn("recorder queue is full; dropping decisions from the audit log", "decision_id", d.ID)
		}
	}
	if e.dispatcher != nil && len(d.Effects()) > 0 {
		// The decision is made and the platform waits for it: effects get
		// a budget of their own, not the caller's patience. A dispatcher
		// that runs out of it finishes the work in the background.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.dispatchTimeout)
		e.dispatcher.Dispatch(dctx, ev, d)
		cancel()
	}
	return d, nil
}

// Sync returns once every decision Decide returned before the call has been
// handed to the Recorder, or dropped because the queue was full, or with
// ctx's error when ctx ends first. Decide queues decisions for the Recorder
// without waiting, so a caller that answered a decision and is then asked
// for it, such as a read of the audit log sent right after the response,
// calls Sync first to see it. Sync does not wait for the Recorder to finish
// whatever it does with a decision, such as writing it to a database. It
// returns at once without a Recorder, and after Close once the queue is
// drained.
func (e *Engine) Sync(ctx context.Context) error {
	if e.records == nil {
		return nil
	}
	return e.records.sync(ctx)
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

// late reports whether err, from Observe, says the store did not answer by
// the deadline rather than that it failed. The Redis store's round trip goes
// on in the background past the deadline and its writes still apply, so
// such an event most likely counts; one the store failed on may not.
func late(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

// boundTime keeps ev's time within reach of the clock, now. Counters slide
// with event time and first-seen times keep the earliest one, so a single
// event far off the clock could otherwise empty an account's windows for
// days, or make it look years old for as long as it keeps sending.
func (e *Engine) boundTime(ev *event.Event, now time.Time) error {
	if e.trustTime {
		return nil
	}
	// Sub saturates, so times centuries away compare correctly too.
	if ahead := ev.Time.Sub(now); ahead > e.maxFuture {
		e.metrics.outOfBounds.WithLabelValues(boundFuture).Inc()
		if e.futureLog.allow(now) {
			e.log.Warn("event time is ahead of the clock; using the clock's",
				"event_type", ev.Type, "account_id", ev.AccountID, "time", ev.Time, "ahead", ahead)
		}
		ev.Time = now.UTC()
		return nil
	}
	if now.Sub(ev.Time) > e.maxAge {
		e.metrics.outOfBounds.WithLabelValues(boundPast).Inc()
		if ev.Type == event.KeyLeak {
			// A key is leaked however long ago it was found: refusing the
			// report would leave it usable. Its time only feeds first-seen.
			ev.Time = now.UTC()
			return nil
		}
		return fmt.Errorf("event: time %s is more than %s in the past; no counter reaches back that far",
			ev.Time.Format(time.RFC3339), e.maxAge)
	}
	return nil
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
