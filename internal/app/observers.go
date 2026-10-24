package app

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/hooks"
	"github.com/guilhermebsantiago/catraca/internal/secretscan"
)

// Buckets of the histograms below. Each covers what its operation may take,
// up to its timeout or bound, with a bucket at the threshold of the SLO it
// feeds, if any (docs/slo.md).
var (
	// An audit batch is a transaction of up to 256 decisions; an attempt
	// times out at 10s.
	auditWriteBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	// A webhook attempt times out at the hook's timeout, 10s by default.
	hookAttemptBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	// A delivery is retried for up to its hook's max_age, a day by
	// default; the freshness SLO counts those delivered within a minute.
	hookLatencyBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800, 3600, 21600, 86400}
	// An attempt at a report is two calls of at most 10s each.
	scanAttemptBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	// A report is retried for up to a day by default; the processing SLO
	// counts those done within five minutes.
	scanLatencyBuckets = []float64{0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 21600, 86400}
)

// observers are the metrics that the audit log, the hooks and secret
// scanning report through their callbacks, as they happen, rather than as
// counters read at scrape time. With tracing on, a sampled span in the
// callback's context becomes the exemplar of its histogram.
type observers struct {
	traced bool

	auditWrite   *prometheus.HistogramVec
	hookAttempts *prometheus.CounterVec
	hookDuration *prometheus.HistogramVec
	hookLatency  *prometheus.HistogramVec
	scanDuration *prometheus.HistogramVec
	scanLatency  *prometheus.HistogramVec
}

// newObservers registers the metrics of cfg's audit log, hooks and, when
// it is enabled, secret scanning, with a series for every configured hook
// and every outcome, so dashboards and alerts see them before the first
// event.
func newObservers(cfg *config.Config, reg prometheus.Registerer, traced bool) *observers {
	o := &observers{
		traced: traced,
		auditWrite: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "catraca_audit_write_duration_seconds",
			Help:    "Time an attempt to write a batch of decisions to the audit database took, by result: ok, refused (the database refused a value, and the batch's decisions are written one at a time next) or error.",
			Buckets: auditWriteBuckets,
		}, []string{"result"}),
		hookAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_hooks_attempts_total",
			Help: "Effect webhook delivery attempts, by hook and by what became of the delivery: delivered, retry or dead.",
		}, []string{"hook", "outcome"}),
		hookDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "catraca_hooks_attempt_duration_seconds",
			Help:    "Time an effect webhook request took, until the receiver's answer or the error, by hook.",
			Buckets: hookAttemptBuckets,
		}, []string{"hook"}),
		hookLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "catraca_hooks_delivery_latency_seconds",
			Help:    "Time from when an effect webhook delivery was queued until a receiver answered it with a 2xx, by hook: the effect's delay, retries and backoff included.",
			Buckets: hookLatencyBuckets,
		}, []string{"hook"}),
		scanDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "catraca_secret_scanning_attempt_duration_seconds",
			Help:    "Time an attempt at a leaked-key report took, resolving the token and deciding its key_leak event, by outcome: leaked, not_found, retry, resolve_failed or decide_failed.",
			Buckets: scanAttemptBuckets,
		}, []string{"outcome"}),
		scanLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "catraca_secret_scanning_report_latency_seconds",
			Help:    "Time from when a leaked-key report was queued (it arrived, or was requeued) until it was done (leaked, not_found) or given up (resolve_failed, decide_failed), by outcome.",
			Buckets: scanLatencyBuckets,
		}, []string{"outcome"}),
	}
	for _, r := range []audit.WriteResult{audit.WriteOK, audit.WriteRefused, audit.WriteFailed} {
		o.auditWrite.WithLabelValues(string(r))
	}
	for _, h := range cfg.Hooks {
		for _, out := range []hooks.Outcome{hooks.OutcomeDelivered, hooks.OutcomeRetry, hooks.OutcomeDead} {
			o.hookAttempts.WithLabelValues(h.Name, string(out))
		}
		o.hookDuration.WithLabelValues(h.Name)
		o.hookLatency.WithLabelValues(h.Name)
	}
	reg.MustRegister(o.auditWrite, o.hookAttempts, o.hookDuration, o.hookLatency)
	if cfg.SecretScanning.GitHub.Enabled {
		for _, out := range []secretscan.Outcome{secretscan.OutcomeLeaked, secretscan.OutcomeNotFound, secretscan.OutcomeRetry,
			secretscan.OutcomeResolveFailed, secretscan.OutcomeDecideFailed} {
			o.scanDuration.WithLabelValues(string(out))
			if out != secretscan.OutcomeRetry {
				o.scanLatency.WithLabelValues(string(out))
			}
		}
		reg.MustRegister(o.scanDuration, o.scanLatency)
	}
	return o
}

// batchWrite is audit.Options.OnBatchWrite.
func (o *observers) batchWrite(ctx context.Context, w audit.BatchWrite) {
	o.observe(ctx, o.auditWrite.WithLabelValues(string(w.Result)), w.Duration)
}

// hookAttempt is hooks.Config.OnAttempt.
func (o *observers) hookAttempt(ctx context.Context, r hooks.AttemptResult) {
	o.hookAttempts.WithLabelValues(r.Hook, string(r.Outcome)).Inc()
	o.observe(ctx, o.hookDuration.WithLabelValues(r.Hook), r.Duration)
	if r.Outcome == hooks.OutcomeDelivered {
		o.observe(ctx, o.hookLatency.WithLabelValues(r.Hook), r.SinceQueued)
	}
}

// scanAttempt is secretscan.Config.OnAttempt.
func (o *observers) scanAttempt(ctx context.Context, r secretscan.AttemptResult) {
	o.observe(ctx, o.scanDuration.WithLabelValues(string(r.Outcome)), r.Duration)
	if r.Outcome != secretscan.OutcomeRetry {
		o.observe(ctx, o.scanLatency.WithLabelValues(string(r.Outcome)), r.SinceQueued)
	}
}

// observe observes d, with the sampled span in ctx as its exemplar when
// tracing is on, so a slow bucket links to a trace that was kept.
func (o *observers) observe(ctx context.Context, h prometheus.Observer, d time.Duration) {
	if o.traced {
		if sc := trace.SpanContextFromContext(ctx); sc.IsSampled() {
			if eo, ok := h.(prometheus.ExemplarObserver); ok {
				eo.ObserveWithExemplar(d.Seconds(), prometheus.Labels{"trace_id": sc.TraceID().String()})
				return
			}
		}
	}
	h.Observe(d.Seconds())
}
