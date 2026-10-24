package secretscan

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

// AttemptResult describes one attempt at a leaked-key report, for
// Config.OnAttempt. An attempt that Shutdown aborts is not reported.
type AttemptResult struct {
	// Outcome is OutcomeLeaked or OutcomeNotFound for a report done,
	// OutcomeResolveFailed or OutcomeDecideFailed for one given up, and
	// OutcomeRetry for one that will be tried again.
	Outcome Outcome
	// Duration is how long the attempt took: resolving the token, deciding
	// its key_leak event and recording the outcome.
	Duration time.Duration
	// SinceQueued is, for a report done or given up, how long ago it
	// became pending: when it arrived, or when it was requeued. It is zero
	// for OutcomeRetry.
	SinceQueued time.Duration
}

// tracerName is the instrumentation scope of the workers' spans.
const tracerName = "github.com/guilhermebsantiago/catraca/internal/secretscan"

// traceContext writes the W3C traceparent header of the resolver's
// requests.
var traceContext propagation.TraceContext

// startAttempt starts the span of an attempt at rep, with tracing on, and
// returns the attempt's context, a child of the handler's base context. An
// attempt starts a trace of its own: the batch that brought the report was
// answered before any attempt, maybe on another process. Neither the token
// nor the URL it was found at is recorded.
func (h *Handler) startAttempt(rep audit.LeakReport) (context.Context, trace.Span) {
	if h.tracer == nil {
		return h.base, nil
	}
	return h.tracer.Start(h.base, "catraca.secretscan.process_report", trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.Int64("catraca.report.id", rep.ID),
			attribute.Int("catraca.report.attempt", rep.Attempts),
			attribute.String("catraca.secret.type", rep.Type),
			attribute.String("catraca.secret.source", rep.Source),
		))
}

// attempted reports an attempt to OnAttempt and ends its span, if any.
func (h *Handler) attempted(ctx context.Context, span trace.Span, rep audit.LeakReport, outcome Outcome, took time.Duration) {
	if outcome != "" {
		r := AttemptResult{Outcome: outcome, Duration: took}
		if outcome != OutcomeRetry {
			r.SinceQueued = max(0, h.now().Sub(rep.QueuedAt))
		}
		h.onAttempt(ctx, r)
	}
	if span == nil {
		return
	}
	switch outcome {
	case "":
		span.SetStatus(codes.Error, "aborted by shutdown")
	case OutcomeLeaked, OutcomeNotFound:
		span.SetAttributes(attribute.String("catraca.report.outcome", string(outcome)))
	default:
		span.SetAttributes(attribute.String("catraca.report.outcome", string(outcome)))
		span.SetStatus(codes.Error, string(outcome))
	}
	span.End()
}

// traceResolve starts the span of a resolver call, with tracing on, and
// returns the function that ends it with the call's error.
func (h *Handler) traceResolve(ctx context.Context) (context.Context, func(error)) {
	if h.tracer == nil {
		return ctx, func(error) {}
	}
	ctx, span := h.tracer.Start(ctx, "catraca.secretscan.resolve", trace.WithSpanKind(trace.SpanKindClient))
	return ctx, func(err error) {
		switch {
		case err == nil:
		case errors.Is(err, ErrNotFound):
			span.SetAttributes(attribute.Bool("catraca.secret.found", false))
		default:
			// The resolver's answer may quote what it was sent.
			span.SetStatus(codes.Error, "the resolver failed")
		}
		span.End()
	}
}
