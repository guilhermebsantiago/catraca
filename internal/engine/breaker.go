package engine

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Defaults for the fields of BreakerOptions left at zero.
const (
	// DefaultBreakerFailures is the fewest store calls in a row that must
	// fail or miss the deadline before the breaker opens, so that a few
	// failures spread over a quiet period do not open it.
	DefaultBreakerFailures = 20
	// DefaultBreakerWindow is how long store calls must keep failing, with
	// none succeeding, before the breaker opens. An overload makes calls
	// miss the deadline too, but the HTTP layer's adaptive limit brings it
	// under control within a few rounds of the deadline, after which calls
	// succeed again; an outage never does. Half a second tells them apart,
	// and the decisions an outage holds meanwhile wait no longer than the
	// deadline, most of them shed by that limit anyway.
	DefaultBreakerWindow = 500 * time.Millisecond
	// DefaultBreakerCooldown is how long the breaker stays open before it
	// probes the store. The probes cost a few decisions a deadline each, so
	// it can be short; a degraded second costs detection.
	DefaultBreakerCooldown = 2 * time.Second
	// DefaultBreakerProbes is how many calls the half-open breaker lets
	// through, all of which must succeed for it to close.
	DefaultBreakerProbes = 5
)

var (
	// ErrBreakerOpen is returned, wrapped, by Decide for a key_leak event
	// while the store breaker is open: the leak could not be written, so the
	// caller should send the event again. The catalog still remembers the
	// key in memory.
	ErrBreakerOpen = errors.New("engine: the store breaker is open")
	// ErrWithoutStore is returned, wrapped, by DecideWithoutStore for a
	// key_leak event, whose leak it could not write.
	ErrWithoutStore = errors.New("engine: decided without the store")
)

// BreakerOptions configure the circuit breaker around the store calls
// Decide makes: Catalog.Observe and, for key_leak events,
// Catalog.MarkLeaked.
//
// While the store keeps failing or timing out, every decision would wait
// its whole deadline only to be degraded, and every round trip that
// outlives its deadline holds a connection to a store that is already
// struggling. Once store calls have failed or missed the deadline for
// Window, with none succeeding, and at least Failures of them, the breaker
// opens: for Cooldown, decisions skip the store and are degraded at once,
// exactly as when the store misses the deadline (each rule's on_error
// applies, known leaked keys stay blocked), and key_leak events fail at
// once with ErrBreakerOpen. Then it lets Probes calls through: when they
// all succeed it closes, and when one fails it opens for another Cooldown.
type BreakerOptions struct {
	// Failures is the fewest store calls in a row that must fail or miss
	// the deadline to open the breaker. Zero means DefaultBreakerFailures.
	Failures int
	// Window is how long they must keep failing, with none succeeding.
	// Zero means DefaultBreakerWindow.
	Window time.Duration
	// Cooldown is how long the breaker stays open before it probes the
	// store. Zero means DefaultBreakerCooldown.
	Cooldown time.Duration
	// Probes is how many calls the half-open breaker lets through. Zero
	// means DefaultBreakerProbes.
	Probes int
}

// breakerState is the state of the breaker, also the value of the state
// label of catraca_store_breaker_state.
type breakerState int32

const (
	breakerClosed breakerState = iota
	breakerOpen
	breakerHalfOpen
)

var breakerStates = []breakerState{breakerClosed, breakerOpen, breakerHalfOpen}

func (s breakerState) String() string {
	switch s {
	case breakerOpen:
		return "open"
	case breakerHalfOpen:
		return "half_open"
	}
	return "closed"
}

// callResult is what a store call says about the store.
type callResult int

const (
	callOK callResult = iota
	callFailed
	// callIgnored is a call cut short by its caller, which says nothing
	// about the store.
	callIgnored
)

// storeCall is one store call of a decision, as the breaker saw it.
type storeCall struct {
	// gen is the breaker's generation when the call started. A call that
	// ends after a transition is not counted: it is about a state that no
	// longer holds.
	gen   uint64
	probe bool
	// skip is set for a call that does not reach the store, because the
	// breaker is open or the decision was shed; cause says which.
	skip  bool
	cause error
}

// skipped is the context of the store calls that are skipped. It is
// already done, so the catalog answers from what it knows without a round
// trip, as it does when the deadline runs out: both stores return at once
// for a done context.
var skipped = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

// storeContext returns the context for one store call of a decision and
// the call to hand to storeDone with its result. The context is ctx under
// the deadline, or skipped when the decision is made without the store or
// the breaker does not let the call through.
func (e *Engine) storeContext(ctx context.Context, withoutStore bool) (context.Context, storeCall, context.CancelFunc) {
	if withoutStore {
		return skipped, storeCall{skip: true, cause: ErrWithoutStore}, func() {}
	}
	call, ok := e.breaker.begin()
	if !ok {
		return skipped, call, func() {}
	}
	sctx, cancel := context.WithTimeout(ctx, e.deadline)
	return sctx, call, cancel
}

// storeDone tells the breaker how a store call went. A call that failed
// after ctx, the caller's context, ended is not counted: the caller gave up
// first, which says nothing about the store.
func (e *Engine) storeDone(ctx context.Context, call storeCall, err error) {
	res := callOK
	if err != nil {
		res = callFailed
		if ctx.Err() != nil {
			res = callIgnored
		}
	}
	e.breaker.end(call, res, err)
}

// breaker is the circuit breaker described by BreakerOptions. A closed
// breaker, the usual case, costs a few atomic operations per call; the
// lock is taken only to change state and while the breaker is not closed.
type breaker struct {
	threshold int64
	window    time.Duration
	cooldown  time.Duration
	probes    int
	now       func() time.Time
	log       *slog.Logger

	state    atomic.Int32
	gen      atomic.Uint64
	failures atomic.Int64 // in a row, while closed
	// runStart is when the first of those failures ended, in Unix
	// nanoseconds.
	runStart atomic.Int64

	mu       sync.Mutex
	openedAt time.Time // when it last opened
	since    time.Time // when it opened from closed, for the log line that closes it
	admitted int       // probes let through while half-open
	passed   int       // probes that succeeded while half-open

	stateGauge     *prometheus.GaugeVec
	transitions    *prometheus.CounterVec
	shortCircuited prometheus.Counter
}

func newBreaker(opts BreakerOptions, now func() time.Time, log *slog.Logger, reg prometheus.Registerer) (*breaker, error) {
	if opts.Failures < 0 || opts.Window < 0 || opts.Cooldown < 0 || opts.Probes < 0 {
		return nil, errors.New("engine: Options.Breaker fields must not be negative")
	}
	b := &breaker{
		threshold: int64(cmp.Or(opts.Failures, DefaultBreakerFailures)),
		window:    cmp.Or(opts.Window, DefaultBreakerWindow),
		cooldown:  cmp.Or(opts.Cooldown, DefaultBreakerCooldown),
		probes:    cmp.Or(opts.Probes, DefaultBreakerProbes),
		now:       now,
		log:       log,
		stateGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "catraca_store_breaker_state",
			Help: "1 for the state the store breaker is in (closed, open or half_open), 0 for the others.",
		}, []string{"state"}),
		transitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_store_breaker_transitions_total",
			Help: "Changes of the store breaker's state, by the state it left and the one it entered.",
		}, []string{"from", "to"}),
		shortCircuited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "catraca_short_circuited_decisions_total",
			Help: "Decisions that skipped the store because its breaker was open: degraded at once, or, for key_leak events, failed at once.",
		}),
	}
	for _, s := range breakerStates {
		b.stateGauge.WithLabelValues(s.String())
	}
	b.stateGauge.WithLabelValues(breakerClosed.String()).Set(1)
	for _, t := range [][2]breakerState{
		{breakerClosed, breakerOpen}, {breakerOpen, breakerHalfOpen},
		{breakerHalfOpen, breakerOpen}, {breakerHalfOpen, breakerClosed},
	} {
		b.transitions.WithLabelValues(t[0].String(), t[1].String())
	}
	if reg != nil {
		for _, c := range []prometheus.Collector{b.stateGauge, b.transitions, b.shortCircuited} {
			if err := reg.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// begin admits a store call, or returns false when the call must be
// skipped because the breaker is open, or half-open with its probes already
// let through.
func (b *breaker) begin() (storeCall, bool) {
	if breakerState(b.state.Load()) == breakerClosed {
		return storeCall{gen: b.gen.Load()}, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch breakerState(b.state.Load()) {
	case breakerClosed:
		return storeCall{gen: b.gen.Load()}, true
	case breakerOpen:
		if b.now().Sub(b.openedAt) < b.cooldown {
			b.shortCircuited.Inc()
			return storeCall{skip: true, cause: ErrBreakerOpen}, false
		}
		b.transition(breakerHalfOpen, nil)
	}
	if b.admitted >= b.probes {
		b.shortCircuited.Inc()
		return storeCall{skip: true, cause: ErrBreakerOpen}, false
	}
	b.admitted++
	return storeCall{gen: b.gen.Load(), probe: true}, true
}

// end counts the result of a call begin admitted. err is the call's error,
// logged when it opens the breaker.
func (b *breaker) end(c storeCall, res callResult, err error) {
	if c.skip {
		return
	}
	if !c.probe {
		if b.gen.Load() != c.gen || res == callIgnored {
			return
		}
		if res == callOK {
			if b.failures.Load() != 0 {
				b.failures.Store(0)
			}
			return
		}
		// The clock is read only at the start of a run and once it is long
		// enough to count, not for every failure.
		n := b.failures.Add(1)
		if n == 1 {
			b.runStart.Store(b.now().UnixNano())
		}
		if n >= b.threshold && b.now().UnixNano()-b.runStart.Load() >= int64(b.window) {
			b.mu.Lock()
			if breakerState(b.state.Load()) == breakerClosed && b.gen.Load() == c.gen && b.failures.Load() >= b.threshold {
				b.transition(breakerOpen, err)
			}
			b.mu.Unlock()
		}
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gen.Load() != c.gen {
		return
	}
	switch res {
	case callIgnored:
		// Another call may probe in its place.
		b.admitted--
	case callOK:
		b.passed++
		if b.passed >= b.probes {
			b.transition(breakerClosed, nil)
		}
	default:
		b.transition(breakerOpen, err)
	}
}

// transition moves the breaker to state to, with b.mu held, and logs it.
// err is the failure that opens it, if any.
func (b *breaker) transition(to breakerState, err error) {
	from := breakerState(b.state.Load())
	now := b.now()
	b.gen.Add(1)
	b.state.Store(int32(to))
	b.admitted, b.passed = 0, 0
	b.stateGauge.WithLabelValues(from.String()).Set(0)
	b.stateGauge.WithLabelValues(to.String()).Set(1)
	b.transitions.WithLabelValues(from.String(), to.String()).Inc()

	switch to {
	case breakerOpen:
		b.openedAt = now
		if from == breakerClosed {
			b.since = now
			b.log.Warn("store breaker opened: store calls keep failing or missing the deadline; deciding degraded without the store",
				"failures_in_a_row", b.failures.Load(), "failing_for", now.Sub(time.Unix(0, b.runStart.Load())),
				"cooldown", b.cooldown, "error", err)
		} else {
			b.log.Warn("store breaker opened again: a probe failed",
				"cooldown", b.cooldown, "open_for", now.Sub(b.since), "error", err)
		}
	case breakerHalfOpen:
		b.log.Info("store breaker half-open: probing the store", "probes", b.probes)
	case breakerClosed:
		b.failures.Store(0)
		b.log.Info("store breaker closed: the store answers again", "open_for", now.Sub(b.since))
	}
}
