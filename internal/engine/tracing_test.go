package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// histogramCount returns the number of observations of the histogram series
// with exactly these labels.
func histogramCount(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) uint64 {
	t.Helper()
	for _, m := range family(t, reg, name).GetMetric() {
		if len(m.GetLabel()) != len(labels) {
			continue
		}
		match := true
		for _, l := range m.GetLabel() {
			if labels[l.GetName()] != l.GetValue() {
				match = false
			}
		}
		if match {
			return m.GetHistogram().GetSampleCount()
		}
	}
	t.Fatalf("%s has no series %v", name, labels)
	return 0
}

func TestStoreCallsAreMeasured(t *testing.T) {
	h := newHarness(t, Options{Deadline: 20 * time.Millisecond})
	count := func(call, result string) uint64 {
		return histogramCount(t, h.reg, "catraca_store_call_duration_seconds", map[string]string{"call": call, "result": result})
	}
	// Every series exists before the first call.
	for _, call := range storeOps {
		for _, result := range storeResults {
			if n := count(call, result); n != 0 {
				t.Errorf("%s/%s = %d before any call", call, result, n)
			}
		}
	}

	h.decide(t, sendEvent())
	if n := count("observe", "ok"); n != 1 {
		t.Errorf("observe/ok = %d after a decision, want 1", n)
	}

	h.cat.mu.Lock()
	h.cat.err = errors.New("redis: connection refused")
	h.cat.mu.Unlock()
	h.decide(t, sendEvent())
	if n := count("observe", "error"); n != 1 {
		t.Errorf("observe/error = %d after a failed call, want 1", n)
	}

	h.cat.mu.Lock()
	h.cat.err, h.cat.hang = nil, true
	h.cat.mu.Unlock()
	h.decide(t, sendEvent())
	if n := count("observe", "timeout"); n != 1 {
		t.Errorf("observe/timeout = %d after a call past the deadline, want 1", n)
	}

	h.cat.mu.Lock()
	h.cat.hang = false
	h.cat.mu.Unlock()
	h.decide(t, event.Event{Type: event.KeyLeak, AccountID: "acct_1", APIKeyID: "key_1"})
	if n := count("mark_leaked", "ok"); n != 1 {
		t.Errorf("mark_leaked/ok = %d after a key_leak, want 1", n)
	}

	// A decision made without the store makes no store call.
	if _, err := h.eng.DecideWithoutStore(context.Background(), sendEvent()); err != nil {
		t.Fatal(err)
	}
	if n := count("observe", "ok") + count("observe", "error") + count("observe", "timeout"); n != 4 {
		t.Errorf("observe calls = %d after a decision without the store, want still 4", n)
	}
}

// A call whose caller went away first says nothing about the store, as for
// the breaker.
func TestStoreCallOfGoneCallerIsNotMeasured(t *testing.T) {
	h := newHarness(t, Options{})
	h.cat.hang = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.eng.Decide(ctx, sendEvent()); err != nil {
		t.Fatal(err)
	}
	for _, result := range storeResults {
		if n := histogramCount(t, h.reg, "catraca_store_call_duration_seconds", map[string]string{"call": "observe", "result": result}); n != 0 {
			t.Errorf("observe/%s = %d for a call the caller abandoned", result, n)
		}
	}
}

func newRecorder() (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	sr := tracetest.NewSpanRecorder()
	return sr, sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
}

func spanNamed(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i] = s.Name()
	}
	t.Fatalf("no span %q among %v", name, names)
	return nil
}

func attrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := map[attribute.Key]attribute.Value{}
	for _, kv := range s.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

func TestDecideIsTracedWithoutPersonalData(t *testing.T) {
	sr, tp := newRecorder()
	h := newHarness(t, Options{TracerProvider: tp})
	ev := event.Event{
		Type: event.Send, AccountID: "acct_person_7", APIKeyID: "key_person_7", IP: "203.0.113.77",
		From: "maria@example.com", To: []string{"joao@example.org"}, Subject: "Olá Maria",
	}
	d := h.decide(t, ev)

	spans := sr.Ended()
	decide := spanNamed(t, spans, "catraca.decide")
	observe := spanNamed(t, spans, "catraca.store.observe")
	if observe.Parent().SpanID() != decide.SpanContext().SpanID() {
		t.Error("the store call's span is not a child of the decision's")
	}
	if observe.SpanKind() != trace.SpanKindClient {
		t.Errorf("store span kind = %v, want client", observe.SpanKind())
	}
	a := attrs(decide)
	for key, want := range map[attribute.Key]string{
		"catraca.event.type":      "send",
		"catraca.decision.id":     d.ID,
		"catraca.decision.action": string(d.Action),
		"catraca.ruleset.version": d.RulesetVersion,
	} {
		if got := a[key].AsString(); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := attrs(observe)["catraca.store.result"].AsString(); got != "ok" {
		t.Errorf("store result = %q, want ok", got)
	}
	for _, s := range spans {
		for _, kv := range s.Attributes() {
			v := kv.Value.String()
			for _, personal := range []string{"acct_person_7", "key_person_7", "203.0.113.77", "maria", "joao", "Olá"} {
				if strings.Contains(v, personal) {
					t.Errorf("span %s: %s = %q carries %q", s.Name(), kv.Key, v, personal)
				}
			}
		}
	}
}

func TestDecideSpanOfARefusedEvent(t *testing.T) {
	sr, tp := newRecorder()
	h := newHarness(t, Options{TracerProvider: tp})
	// An unknown type, which could be anything a client sends, is not
	// recorded.
	if _, err := h.eng.Decide(context.Background(), event.Event{Type: "maria@example.com", AccountID: "acct_1"}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("err = %v, want ErrInvalidEvent", err)
	}
	s := spanNamed(t, sr.Ended(), "catraca.decide")
	if s.Status().Code != codes.Error || s.Status().Description != "invalid event" {
		t.Errorf("status = %+v, want an error saying invalid event", s.Status())
	}
	if _, ok := attrs(s)["catraca.event.type"]; ok {
		t.Error("the span of an invalid event records its type")
	}
}

func TestStoreSpanOfAFailedCall(t *testing.T) {
	sr, tp := newRecorder()
	h := newHarness(t, Options{TracerProvider: tp})
	h.cat.err = errors.New("redis: catraca:acct:acct_person_7 is busy")
	d := h.decide(t, sendEvent())
	if !d.Degraded {
		t.Fatal("decision not degraded")
	}
	s := spanNamed(t, sr.Ended(), "catraca.store.observe")
	if s.Status().Code != codes.Error || strings.Contains(s.Status().Description, "acct_person_7") {
		t.Errorf("status = %+v, want an error that does not quote the store", s.Status())
	}
	if got := attrs(spanNamed(t, sr.Ended(), "catraca.decide"))["catraca.decision.degraded"]; !got.AsBool() {
		t.Error("decide span does not say the decision was degraded")
	}
}

func TestDecisionLatencyHasExemplar(t *testing.T) {
	_, tp := newRecorder()
	h := newHarness(t, Options{TracerProvider: tp})
	ctx, span := tp.Tracer("test").Start(context.Background(), "request")
	if _, err := h.eng.Decide(ctx, sendEvent()); err != nil {
		t.Fatal(err)
	}
	span.End()
	want := span.SpanContext().TraceID().String()
	for _, name := range []string{"catraca_decision_duration_seconds", "catraca_store_call_duration_seconds"} {
		found := false
		for _, m := range family(t, h.reg, name).GetMetric() {
			for _, b := range m.GetHistogram().GetBucket() {
				for _, l := range b.GetExemplar().GetLabel() {
					if l.GetName() == "trace_id" && l.GetValue() == want {
						found = true
					}
				}
			}
		}
		if !found {
			t.Errorf("%s has no exemplar for trace %s", name, want)
		}
	}
}

// With tracing off, nothing in a decision's context is a span, and the
// histograms keep no exemplars.
func TestNoTracingNoExemplar(t *testing.T) {
	h := newHarness(t, Options{})
	_, tp := newRecorder()
	ctx, span := tp.Tracer("test").Start(context.Background(), "request")
	defer span.End()
	if _, err := h.eng.Decide(ctx, sendEvent()); err != nil {
		t.Fatal(err)
	}
	for _, m := range family(t, h.reg, "catraca_decision_duration_seconds").GetMetric() {
		for _, b := range m.GetHistogram().GetBucket() {
			if b.GetExemplar() != nil {
				t.Fatalf("exemplar %v with tracing off", b.GetExemplar())
			}
		}
	}
}
