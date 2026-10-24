package engine

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// latencyBuckets resolve the 10 ms default deadline finely: most decisions
// should land below 1 ms, and anything past the deadline is an outlier.
var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.0075, 0.01, 0.015, 0.025, 0.05, 0.1,
}

type metrics struct {
	decisions   *prometheus.CounterVec
	matches     *prometheus.CounterVec
	errors      *prometheus.CounterVec
	degraded    prometheus.Counter
	latency     prometheus.Histogram
	dropped     prometheus.Counter
	outOfBounds *prometheus.CounterVec
	duplicates  *prometheus.CounterVec
	storeCalls  *prometheus.HistogramVec
	// storeCall holds the series of storeCalls for each call and result, so
	// a decision does not look its labels up.
	storeCall [len(storeOps)][len(storeResults)]prometheus.Observer
}

// storeOp is a store call a decision makes. storeOps are the values of the
// call label of catraca_store_call_duration_seconds.
type storeOp uint8

const (
	opObserve storeOp = iota
	opMarkLeaked
)

var storeOps = [...]string{opObserve: "observe", opMarkLeaked: "mark_leaked"}

// storeResult is how a store call ended. storeResults are the values of the
// result label of catraca_store_call_duration_seconds.
type storeResult uint8

const (
	resultOK storeResult = iota
	resultError
	// resultTimeout is a call that missed the deadline.
	resultTimeout
)

var storeResults = [...]string{resultOK: "ok", resultError: "error", resultTimeout: "timeout"}

// Values of the bound label of catraca_event_times_out_of_bounds_total.
const (
	boundFuture = "future"
	boundPast   = "past"
)

func newMetrics(reg prometheus.Registerer) (*metrics, error) {
	m := &metrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_decisions_total",
			Help: "Decisions made, by action.",
		}, []string{"action"}),
		matches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_rule_matches_total",
			Help: "Rule matches, by rule and mode, including rules that matched because they fail closed.",
		}, []string{"rule", "mode"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_rule_errors_total",
			Help: "Rules that could not be evaluated, by rule.",
		}, []string{"rule"}),
		degraded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "catraca_degraded_decisions_total",
			Help: "Decisions made without some signals: the store failed or missed the deadline, or was skipped because its breaker was open or admission control shed the decision.",
		}),
		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "catraca_decision_duration_seconds",
			Help:    "Time to decide an event, from validation to the combined action.",
			Buckets: latencyBuckets,
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "catraca_records_dropped_total",
			Help: "Decisions not handed to the recorder because its queue was full.",
		}),
		outOfBounds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_event_times_out_of_bounds_total",
			Help: "Events whose time was too far ahead of the server's clock (future: the clock's time was used) or behind it (past: rejected, or the clock's time for key_leak).",
		}, []string{"bound"}),
		duplicates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_duplicate_events_total",
			Help: "Events that had counted already under the same id, such as retries, and did not count again, by event type.",
		}, []string{"type"}),
		// A store call is bounded by the deadline, so it shares the
		// decision's buckets.
		storeCalls: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "catraca_store_call_duration_seconds",
			Help:    "Time the store took over a call of a decision, by call (observe, mark_leaked) and result (ok, error, or timeout when it missed the deadline). Calls the breaker skipped, and calls whose caller went away first, are not counted.",
			Buckets: latencyBuckets,
		}, []string{"call", "result"}),
	}
	// Every action starts at zero so dashboards and alerts see the series
	// before the first block happens.
	for _, a := range []decision.Action{decision.Allow, decision.Flag, decision.Throttle, decision.Hold, decision.Block} {
		m.decisions.WithLabelValues(string(a))
	}
	m.outOfBounds.WithLabelValues(boundFuture)
	m.outOfBounds.WithLabelValues(boundPast)
	for _, t := range []event.Type{event.Send, event.Feedback, event.Account, event.KeyLeak} {
		m.duplicates.WithLabelValues(string(t))
	}
	for op, call := range storeOps {
		for res, result := range storeResults {
			m.storeCall[op][res] = m.storeCalls.WithLabelValues(call, result)
		}
	}
	if reg == nil {
		return m, nil
	}
	for _, c := range []prometheus.Collector{m.decisions, m.matches, m.errors, m.degraded, m.latency, m.dropped, m.outOfBounds, m.duplicates, m.storeCalls} {
		if err := reg.Register(c); err != nil {
			var already prometheus.AlreadyRegisteredError
			if errors.As(err, &already) {
				return nil, errors.New("engine: metrics are already registered; give each engine its own prometheus.Registerer")
			}
			return nil, err
		}
	}
	return m, nil
}

// observe counts a decision. With tracing on, traced is set, and the span in
// ctx, when sampled, becomes the exemplar of the decision's latency.
func (m *metrics) observe(ctx context.Context, traced bool, d decision.Decision, elapsed time.Duration) {
	m.decisions.WithLabelValues(string(d.Action)).Inc()
	for _, match := range d.Matches {
		m.matches.WithLabelValues(match.RuleID, string(match.Mode)).Inc()
	}
	for _, match := range d.Shadow {
		m.matches.WithLabelValues(match.RuleID, string(match.Mode)).Inc()
	}
	for _, re := range d.Errors {
		m.errors.WithLabelValues(re.RuleID).Inc()
	}
	if d.Degraded {
		m.degraded.Inc()
	}
	if traced {
		observeTraced(m.latency, elapsed.Seconds(), trace.SpanContextFromContext(ctx))
		return
	}
	m.latency.Observe(elapsed.Seconds())
}

// observeTraced observes v with the trace of sc as its exemplar when sc was
// sampled, so a slow bucket links to a trace that was kept. Prometheus reads
// exemplars only in the OpenMetrics format, which the server offers while
// tracing is on.
func observeTraced(o prometheus.Observer, v float64, sc trace.SpanContext) {
	if eo, ok := o.(prometheus.ExemplarObserver); ok && sc.IsSampled() {
		eo.ObserveWithExemplar(v, prometheus.Labels{"trace_id": sc.TraceID().String()})
		return
	}
	o.Observe(v)
}
