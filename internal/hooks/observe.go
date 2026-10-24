package hooks

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

// Outcome is what became of a delivery after an attempt. The values are
// few and fixed, so they can label a metric.
type Outcome string

const (
	// OutcomeDelivered means the receiver answered with a 2xx.
	OutcomeDelivered Outcome = "delivered"
	// OutcomeRetry means the attempt failed and the delivery will be tried
	// again after a backoff.
	OutcomeRetry Outcome = "retry"
	// OutcomeDead means the attempt failed and the delivery was given up:
	// it was its hook's last attempt, or the next would be past max_age.
	OutcomeDead Outcome = "dead"
)

// AttemptResult describes one attempt at a delivery, for Config.OnAttempt.
type AttemptResult struct {
	// Hook is the hook's name, the effect it carries out.
	Hook    string
	Outcome Outcome
	// StatusCode is the receiver's status, 0 when it did not answer.
	StatusCode int
	// Duration is how long the request took, until the response or the
	// error.
	Duration time.Duration
	// SinceQueued is, for a delivered one, how long after it was queued it
	// was delivered: the effect's delay, retries and backoff included.
	SinceQueued time.Duration
}

// tracerName is the instrumentation scope of the dispatcher's spans.
const tracerName = "github.com/guilhermebsantiago/catraca/internal/hooks"

// traceContext writes the W3C traceparent header of an attempt's span.
var traceContext propagation.TraceContext

// startAttempt starts the span of an attempt at del, with tracing on. An
// attempt starts a trace of its own: the decision that queued the delivery
// may be long over, on another process.
func (d *Dispatcher) startAttempt(ctx context.Context, h Hook, del audit.Delivery) (context.Context, trace.Span) {
	if d.tracer == nil {
		return ctx, nil
	}
	return d.tracer.Start(ctx, "catraca.hooks.deliver", trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(
		attribute.String("catraca.hook", h.Name),
		attribute.String("catraca.decision.id", del.DecisionID),
		attribute.Int64("catraca.delivery.id", del.ID),
		attribute.Int("catraca.delivery.attempt", del.Attempts),
		attribute.String("http.request.method", "POST"),
	))
}

// attempted reports an attempt to OnAttempt and ends its span, if any. The
// span keeps the status code, not the error, which may quote the
// receiver's answer.
func (d *Dispatcher) attempted(ctx context.Context, span trace.Span, r AttemptResult) {
	d.cfg.OnAttempt(ctx, r)
	if span == nil {
		return
	}
	span.SetAttributes(attribute.String("catraca.delivery.outcome", string(r.Outcome)))
	if r.StatusCode != 0 {
		span.SetAttributes(attribute.Int("http.response.status_code", r.StatusCode))
	}
	if r.Outcome != OutcomeDelivered {
		span.SetStatus(codes.Error, "the receiver did not answer with a 2xx")
	}
	span.End()
}

// traceEnqueue starts the span of an outbox write, a child of the decision
// whose effects it writes, with tracing on. The returned function ends it.
func (d *Dispatcher) traceEnqueue(ctx context.Context, ds []audit.Delivery) (context.Context, func(error)) {
	if d.tracer == nil {
		return ctx, func(error) {}
	}
	ctx, span := d.tracer.Start(ctx, "catraca.hooks.enqueue",
		trace.WithAttributes(attribute.StringSlice("catraca.effects", effectNames(ds))))
	return ctx, func(err error) {
		if err != nil {
			span.SetStatus(codes.Error, "the outbox write failed")
		}
		span.End()
	}
}
