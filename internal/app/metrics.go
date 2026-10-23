package app

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/hooks"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// registerStats exports the counters the audit log and the hooks keep
// themselves, read at scrape time, and what is known about the build and
// the ruleset.
func (a *App) registerStats() {
	db := a.audit
	hookStats := func() hooks.Stats {
		if a.hooks == nil {
			return hooks.Stats{}
		}
		return a.hooks.Stats()
	}
	counter := func(name, help string, f func() uint64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, func() float64 { return float64(f()) })
	}
	a.registry.MustRegister(
		counter("catraca_audit_recorded_total", "Decisions written to the audit log.",
			func() uint64 { return db.RecorderStats().Recorded }),
		counter("catraca_audit_dropped_total", "Decisions never queued for the audit log: its buffer was full or it was closed.",
			func() uint64 { return db.RecorderStats().Dropped }),
		counter("catraca_audit_failed_total", "Decisions queued for the audit log that could not be written.",
			func() uint64 { return db.RecorderStats().Failed }),
		counter("catraca_audit_rejected_total", "Decisions the audit database refused one at a time while it wrote the rest of their batch; also counted as failed.",
			func() uint64 { return db.RecorderStats().Rejected }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "catraca_audit_queued",
			Help: "Decisions waiting to be written to the audit log.",
		}, func() float64 { return float64(db.RecorderStats().Queued) }),
		retentionDeleted("decisions", func() uint64 { return db.RetentionStats().Decisions }),
		retentionDeleted("outbox", func() uint64 { return db.RetentionStats().Deliveries }),
		counter("catraca_audit_retention_errors_total", "Audit retention runs that failed to delete expired rows.",
			func() uint64 { return db.RetentionStats().Errors }),
		// go_sql_* with db_name="audit": connections open, in use and idle,
		// and how often and how long callers waited for one.
		auditDBStats{db},

		counter("catraca_hooks_enqueued_total", "Effect webhook deliveries written to the outbox.",
			func() uint64 { return hookStats().Enqueued }),
		counter("catraca_hooks_enqueue_errors_total", "Effect webhook deliveries that could not be written to the outbox.",
			func() uint64 { return hookStats().EnqueueErrors }),
		counter("catraca_hooks_delivered_total", "Effect webhook deliveries answered with a 2xx status.",
			func() uint64 { return hookStats().Delivered }),
		counter("catraca_hooks_retries_total", "Failed effect webhook attempts that will be retried.",
			func() uint64 { return hookStats().Retried }),
		counter("catraca_hooks_dead_total", "Effect webhook deliveries given up after their last attempt.",
			func() uint64 { return hookStats().Dead }),

		&rulesetCollector{holder: a.holder},
	)
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "catraca_build_info",
		Help: "Always 1, labeled with the build version and the Go version.",
	}, []string{"version", "goversion"})
	version := a.version
	if version == "" {
		version = "unknown"
	}
	build.WithLabelValues(version, runtime.Version()).Set(1)
	a.registry.MustRegister(build)
}

// retentionDeleted counts the rows audit retention deleted from one table.
func retentionDeleted(table string, f func() uint64) prometheus.Collector {
	return prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "catraca_audit_retention_deleted_total",
		Help:        "Rows deleted by audit retention, by table: decisions (with their matches and labels) and outbox.",
		ConstLabels: prometheus.Labels{"table": table},
	}, func() float64 { return float64(f()) })
}

var (
	rulesetInfo = prometheus.NewDesc("catraca_ruleset_info",
		"Always 1, labeled with the version of the ruleset decisions are made with. Absent while no ruleset is loaded.",
		[]string{"version"}, nil)
	rulesetRules = prometheus.NewDesc("catraca_ruleset_rules",
		"Rules in the current ruleset, by mode.", []string{"mode"}, nil)
)

// rulesetCollector describes the current ruleset at scrape time, so a reload
// shows up without bookkeeping.
type rulesetCollector struct {
	holder *rules.Holder
}

func (c *rulesetCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- rulesetInfo
	ch <- rulesetRules
}

func (c *rulesetCollector) Collect(ch chan<- prometheus.Metric) {
	rs := c.holder.Current()
	if rs == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(rulesetInfo, prometheus.GaugeValue, 1, rs.Version())
	count := map[decision.Mode]int{decision.Enforce: 0, decision.Shadow: 0}
	for _, r := range rs.Rules() {
		count[r.Mode]++
	}
	for mode, n := range count {
		ch <- prometheus.MustNewConstMetric(rulesetRules, prometheus.GaugeValue, float64(n), string(mode))
	}
}

// auditDBStats exports the audit database's connection pool stats once it
// is open: a Postgres database that was unreachable at start opens after the
// metrics are registered.
type auditDBStats struct{ log *auditLog }

// Describe sends nothing, which makes this an unchecked collector, so its
// metrics can appear only once the database is open.
func (auditDBStats) Describe(chan<- *prometheus.Desc) {}

func (c auditDBStats) Collect(ch chan<- prometheus.Metric) {
	if db := c.log.current(); db != nil {
		collectors.NewDBStatsCollector(db.SQL(), "audit").Collect(ch)
	}
}
