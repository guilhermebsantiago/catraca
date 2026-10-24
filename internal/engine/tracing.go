package engine

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/monotime"
)

// tracerName is the instrumentation scope of the engine's spans.
const tracerName = "github.com/guilhermebsantiago/catraca/internal/engine"

// storeSpans are the names of the spans of each store call.
var storeSpans = [...]string{opObserve: "catraca.store.observe", opMarkLeaked: "catraca.store.mark_leaked"}

// decideInSpan decides ev, in a span of its own when tracing is on. The span
// says what was decided and why, never about whom: no account, key, address
// or content of the event leaves the server in a trace. Its ids, which
// Catraca generates, find the decision in the audit log.
func (e *Engine) decideInSpan(ctx context.Context, ev event.Event, withoutStore bool) (decision.Decision, error) {
	if e.tracer == nil {
		return e.decide(ctx, ev, withoutStore)
	}
	ctx, span := e.tracer.Start(ctx, "catraca.decide")
	defer span.End()
	d, err := e.decide(ctx, ev, withoutStore)
	if err != nil {
		// The error's text may quote the event, so only its kind is kept.
		span.SetStatus(codes.Error, failure(err))
		return d, err
	}
	if !span.IsRecording() {
		return d, nil
	}
	attrs := []attribute.KeyValue{
		// The type is one of a few known values once the event is valid.
		attribute.String("catraca.event.type", string(ev.Type)),
		attribute.String("catraca.decision.id", d.ID),
		attribute.String("catraca.decision.action", string(d.Action)),
		attribute.Bool("catraca.decision.degraded", d.Degraded),
		attribute.Bool("catraca.decision.uncounted", d.Uncounted),
		attribute.Bool("catraca.decision.duplicate", d.Duplicate),
		attribute.Bool("catraca.decision.without_store", withoutStore),
		attribute.String("catraca.ruleset.version", d.RulesetVersion),
	}
	if len(d.Matches) > 0 {
		attrs = append(attrs, attribute.StringSlice("catraca.decision.rules", matchedRules(d.Matches)))
	}
	if len(d.Shadow) > 0 {
		attrs = append(attrs, attribute.StringSlice("catraca.decision.shadow_rules", matchedRules(d.Shadow)))
	}
	if len(d.Errors) > 0 {
		ids := make([]string, len(d.Errors))
		for i, re := range d.Errors {
			ids[i] = re.RuleID
		}
		attrs = append(attrs, attribute.StringSlice("catraca.decision.errored_rules", ids))
	}
	span.SetAttributes(attrs...)
	return d, nil
}

func matchedRules(ms []decision.Match) []string {
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.RuleID
	}
	return ids
}

// failure names the kind of error Decide returned, for a span's status.
func failure(err error) string {
	switch {
	case errors.Is(err, ErrInvalidEvent):
		return "invalid event"
	case errors.Is(err, ErrNoRuleset):
		return "no ruleset loaded"
	case errors.Is(err, ErrBreakerOpen):
		return "the store breaker is open"
	case errors.Is(err, ErrWithoutStore):
		return "decided without the store"
	}
	return "the store failed"
}

// startStoreSpan starts the span of a store call. It is a client span: the
// store is usually Redis, on the other end of a connection.
func (e *Engine) startStoreSpan(ctx context.Context, op storeOp) (context.Context, trace.Span) {
	return e.tracer.Start(ctx, storeSpans[op], trace.WithSpanKind(trace.SpanKindClient))
}

// measureStore records a store call that reached the store: its duration
// and, with tracing on, its span. A call whose caller went away first ends
// its span but is not measured, as the breaker does not count it.
func (e *Engine) measureStore(call storeCall, res callResult, err error) {
	elapsed := monotime.Since(call.start)
	result := resultOK
	if res != callOK {
		result = resultError
		if late(err) {
			result = resultTimeout
		}
	}
	if res != callIgnored {
		o := e.metrics.storeCall[call.op][result]
		if call.span != nil {
			observeTraced(o, elapsed.Seconds(), call.span.SpanContext())
		} else {
			o.Observe(elapsed.Seconds())
		}
	}
	if call.span == nil {
		return
	}
	switch {
	case res == callIgnored:
		call.span.SetStatus(codes.Error, "the caller went away")
	case result != resultOK:
		// The store's error may name keys, which hold account ids.
		call.span.SetStatus(codes.Error, storeResults[result])
	}
	call.span.SetAttributes(attribute.String("catraca.store.result", storeResults[result]))
	call.span.End()
}
