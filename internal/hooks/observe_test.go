package hooks

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// attempts records what OnAttempt is told.
type attempts struct {
	mu  sync.Mutex
	got []AttemptResult
	// sampled says, for each, whether its context held a sampled span.
	sampled []bool
}

func (a *attempts) record(ctx context.Context, r AttemptResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, r)
	a.sampled = append(a.sampled, trace.SpanContextFromContext(ctx).IsSampled())
}

func TestAttemptsAreReported(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 500, 200)
	var seen attempts
	d, clk := newTestDispatcher(t, db, Config{
		Hooks:      []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret, MaxAttempts: 2}},
		MinBackoff: time.Second, MaxBackoff: time.Minute,
		OnAttempt: seen.record,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	clk.Advance(90 * time.Second)
	deliverDue(t, d)

	if len(seen.got) != 2 {
		t.Fatalf("OnAttempt got %d attempts, want 2: %+v", len(seen.got), seen.got)
	}
	first, second := seen.got[0], seen.got[1]
	if first.Hook != "revoke_key" || first.Outcome != OutcomeRetry || first.StatusCode != 500 || first.SinceQueued != 0 {
		t.Errorf("first attempt = %+v, want a retry after a 500", first)
	}
	if second.Outcome != OutcomeDelivered || second.StatusCode != 200 || second.SinceQueued != 90*time.Second {
		t.Errorf("second attempt = %+v, want delivered 90s after it was queued", second)
	}
	if first.Duration <= 0 || second.Duration <= 0 {
		t.Errorf("durations %v and %v, want both positive", first.Duration, second.Duration)
	}
	if slices.Contains(seen.sampled, true) {
		t.Error("an attempt's context holds a span with tracing off")
	}
	// Without tracing there is no trace to propagate.
	for _, r := range rcv.got() {
		if tp := r.header.Get("traceparent"); tp != "" {
			t.Errorf("request carries traceparent %q with tracing off", tp)
		}
	}
}

func TestDeadAttemptIsReported(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 500)
	var seen attempts
	d, _ := newTestDispatcher(t, db, Config{
		Hooks:     []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret, MaxAttempts: 1}},
		OnAttempt: seen.record,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	if len(seen.got) != 1 || seen.got[0].Outcome != OutcomeDead {
		t.Errorf("OnAttempt got %+v, want one dead attempt", seen.got)
	}
}

// Each attempt is a trace of its own, which the receiver joins through the
// traceparent header; the outbox write is part of the decision's trace.
func TestAttemptsAreTracedAndPropagated(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 200)
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	var seen attempts
	d, _ := newTestDispatcher(t, db, Config{
		Hooks:          []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret, Headers: map[string]string{"traceparent": "from-config"}}},
		OnAttempt:      seen.record,
		TracerProvider: tp,
	})
	ctx, decide := tp.Tracer("test").Start(context.Background(), "catraca.decide")
	d.Dispatch(ctx, sendEvent(), leakDecision("d1"))
	decide.End()
	deliverDue(t, d)

	var enqueue, deliver sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		switch s.Name() {
		case "catraca.hooks.enqueue":
			enqueue = s
		case "catraca.hooks.deliver":
			deliver = s
		}
	}
	if enqueue == nil || deliver == nil {
		t.Fatalf("spans %v, want an enqueue and a deliver span", sr.Ended())
	}
	if enqueue.Parent().SpanID() != decide.SpanContext().SpanID() {
		t.Error("the outbox write is not part of the decision's trace")
	}
	if deliver.SpanKind() != trace.SpanKindClient || deliver.Parent().IsValid() {
		t.Errorf("deliver span: kind %v, parent %v; want a client span that starts a trace", deliver.SpanKind(), deliver.Parent())
	}
	reqs := rcv.got()
	if len(reqs) != 1 {
		t.Fatalf("receiver got %d requests", len(reqs))
	}
	want := deliver.SpanContext()
	got := reqs[0].header.Get("traceparent")
	if !strings.Contains(got, want.TraceID().String()) || !strings.Contains(got, want.SpanID().String()) {
		t.Errorf("traceparent = %q, want the attempt's trace %s and span %s", got, want.TraceID(), want.SpanID())
	}
	if len(seen.sampled) != 1 || !seen.sampled[0] {
		t.Error("OnAttempt did not get the attempt's span, for the exemplar")
	}
	for _, kv := range deliver.Attributes() {
		if v := kv.Value.String(); strings.Contains(v, "acct-1") || strings.Contains(v, "key-1") || strings.Contains(v, rcv.srv.URL) {
			t.Errorf("deliver span: %s = %q", kv.Key, v)
		}
	}
}
