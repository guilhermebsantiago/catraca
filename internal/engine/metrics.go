package engine

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// latencyBuckets resolve the 10 ms default deadline finely: most decisions
// should land below 1 ms, and anything past the deadline is an outlier.
var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.0075, 0.01, 0.015, 0.025, 0.05, 0.1,
}

type metrics struct {
	decisions *prometheus.CounterVec
	matches   *prometheus.CounterVec
	errors    *prometheus.CounterVec
	degraded  prometheus.Counter
	latency   prometheus.Histogram
	dropped   prometheus.Counter
}

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
			Help: "Decisions made without some signals because the catalog failed or timed out.",
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
	}
	// Every action starts at zero so dashboards and alerts see the series
	// before the first block happens.
	for _, a := range []decision.Action{decision.Allow, decision.Flag, decision.Throttle, decision.Hold, decision.Block} {
		m.decisions.WithLabelValues(string(a))
	}
	if reg == nil {
		return m, nil
	}
	for _, c := range []prometheus.Collector{m.decisions, m.matches, m.errors, m.degraded, m.latency, m.dropped} {
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

func (m *metrics) observe(d decision.Decision, elapsed time.Duration) {
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
	m.latency.Observe(elapsed.Seconds())
}
