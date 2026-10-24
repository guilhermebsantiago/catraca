package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// benchBody is a send as platforms post it before an email goes out.
const benchBody = `{"type":"send","account_id":"acct_1","api_key_id":"key_1","ip":"203.0.113.10",` +
	`"from":"news@example.com","to":["someone@gmail.com"],"subject":"Your weekly summary",` +
	`"links":["https://example.com/summary"]}`

// BenchmarkServeDecide measures the HTTP layer's own cost for POST
// /v1/decide: reading and decoding the body, the token, admission, the
// access log, the metrics and the response, around a decider that answers
// at once. The engine's cost is BenchmarkDecide's.
func BenchmarkServeDecide(b *testing.B) {
	s := benchServer(b)
	b.ReportAllocs()
	for b.Loop() {
		benchServe(b, s)
	}
}

// BenchmarkServeDecideParallel is BenchmarkServeDecide from GOMAXPROCS
// goroutines, to catch contention in the middleware and admission.
func BenchmarkServeDecideParallel(b *testing.B) {
	s := benchServer(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchServe(b, s)
		}
	})
}

func benchServer(b *testing.B, mod ...func(*Options)) *Server {
	b.Helper()
	d := decision.Decision{
		ID: "01M50Q9TE1EPGZCTSX7N6NPC78", EventID: "01M50Q9TE1EPGZCTSX7N6NPC77",
		Time: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC), Action: decision.Allow,
		Matches: []decision.Match{}, Shadow: []decision.Match{}, Errors: []decision.RuleError{},
		RulesetVersion: "3f2967e0", LatencyMicros: 4,
	}
	opts := Options{
		Decider: deciderFunc(func(context.Context, event.Event) (decision.Decision, error) { return d, nil }),
		Rules:   noRules{},
		Audit:   fakeAudit{},
		Tokens:  []Token{{Name: "platform", Value: testToken}},
		// The access log is written, as in production, to nowhere.
		Logger:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Registerer: prometheus.NewRegistry(),
	}
	for _, m := range mod {
		m(&opts)
	}
	s, err := New(opts)
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func benchServe(b *testing.B, s http.Handler) {
	req := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(benchBody))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		b.Errorf("status %d: %s", rec.Code, rec.Body)
	}
}
