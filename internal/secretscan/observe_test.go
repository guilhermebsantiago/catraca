package secretscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// attemptLog records what OnAttempt is told.
type attemptLog struct {
	mu  sync.Mutex
	got []AttemptResult
}

func (l *attemptLog) record(_ context.Context, r AttemptResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, r)
}

func (l *attemptLog) all() []AttemptResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]AttemptResult(nil), l.got...)
}

func TestAttemptsAreReported(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{keys: map[string]Key{"recovers": {APIKeyID: "key_1"}}, failures: map[string]int{"recovers": 1}}
	var log attemptLog
	h, db := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, OnAttempt: log.record})
	send(t, h, key, batch(t, match{Token: "recovers"}, match{Token: "stranger"}))
	settled(t, db)

	by := map[Outcome][]AttemptResult{}
	for _, r := range log.all() {
		by[r.Outcome] = append(by[r.Outcome], r)
		if r.Duration <= 0 {
			t.Errorf("%s attempt took %v", r.Outcome, r.Duration)
		}
	}
	if len(by[OutcomeRetry]) != 1 || len(by[OutcomeLeaked]) != 1 || len(by[OutcomeNotFound]) != 1 || len(log.all()) != 3 {
		t.Fatalf("attempts %+v, want a retry, a leak and a token not found", log.all())
	}
	if by[OutcomeRetry][0].SinceQueued != 0 {
		t.Errorf("a retry reports %v since queued, want 0", by[OutcomeRetry][0].SinceQueued)
	}
	for _, o := range []Outcome{OutcomeLeaked, OutcomeNotFound} {
		if by[o][0].SinceQueued <= 0 {
			t.Errorf("%s reports %v since queued, want how long the report took", o, by[o][0].SinceQueued)
		}
	}
}

// spanDecider is a Decider that keeps the span of each call's context.
type spanDecider struct {
	mu    sync.Mutex
	spans []trace.SpanContext
}

func (d *spanDecider) Decide(ctx context.Context, ev event.Event) (decision.Decision, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.spans = append(d.spans, trace.SpanContextFromContext(ctx))
	return decision.Decision{ID: "dec_" + ev.ID, Action: decision.Block}, nil
}

// An attempt is a trace: the resolver's request carries its traceparent,
// and the decision joins it, without the token or where it was found.
func TestAttemptsAreTraced(t *testing.T) {
	var (
		mu          sync.Mutex
		traceparent string
	)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		traceparent = r.Header.Get("traceparent")
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"api_key_id": "key_1", "account_id": "acct_1"})
	}))
	t.Cleanup(platform.Close)
	httpResolver, err := NewHTTPResolver(HTTPResolverConfig{URL: platform.URL, Secret: "resolver-secret-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	sr := tracetest.NewSpanRecorder()
	dec := &spanDecider{}
	h, db := newTestHandler(t, Config{
		Decider: dec, Resolver: httpResolver, KeysURL: keys.URL,
		TracerProvider: sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)),
	})
	const token, url = "acme_live_secret_7", "https://github.com/maria/dotfiles/blob/main/.env"
	send(t, h, key, batch(t, match{Token: token, Type: "acme_api_key", URL: url, Source: "content"}))
	settled(t, db)
	shutdown(t, h)

	var attempt, resolve sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		switch s.Name() {
		case "catraca.secretscan.process_report":
			attempt = s
		case "catraca.secretscan.resolve":
			resolve = s
		}
	}
	if attempt == nil || resolve == nil {
		t.Fatalf("spans %v, want an attempt and a resolve", sr.Ended())
	}
	if attempt.SpanKind() != trace.SpanKindConsumer || attempt.Parent().IsValid() {
		t.Errorf("attempt span: kind %v, parent %v; want a consumer span that starts a trace", attempt.SpanKind(), attempt.Parent())
	}
	if resolve.Parent().SpanID() != attempt.SpanContext().SpanID() || resolve.SpanKind() != trace.SpanKindClient {
		t.Error("the resolve span is not a client span under the attempt's")
	}
	mu.Lock()
	got := traceparent
	mu.Unlock()
	if !strings.Contains(got, resolve.SpanContext().SpanID().String()) {
		t.Errorf("resolver got traceparent %q, want the resolve span %s", got, resolve.SpanContext().SpanID())
	}
	dec.mu.Lock()
	defer dec.mu.Unlock()
	if len(dec.spans) != 1 || dec.spans[0].TraceID() != attempt.SpanContext().TraceID() {
		t.Error("the decision is not part of the attempt's trace")
	}
	for _, s := range sr.Ended() {
		for _, kv := range s.Attributes() {
			if v := kv.Value.String(); strings.Contains(v, token) || strings.Contains(v, hashOf(token)) || strings.Contains(v, "maria") {
				t.Errorf("span %s: %s = %q", s.Name(), kv.Key, v)
			}
		}
	}
}
