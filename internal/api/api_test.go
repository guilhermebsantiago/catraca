package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

const testToken = "api-test-token-0123456789"

type deciderFunc func(ctx context.Context, ev event.Event) (decision.Decision, error)

func (f deciderFunc) Decide(ctx context.Context, ev event.Event) (decision.Decision, error) {
	return f(ctx, ev)
}

type noRules struct{}

func (noRules) Current() *rules.Ruleset { return nil }

// fakeAudit fails every call, so tests see how errors are answered.
type fakeAudit struct{ err error }

func (f fakeAudit) Get(context.Context, string) (audit.Entry, error) { return audit.Entry{}, f.err }
func (f fakeAudit) Label(context.Context, string, audit.Label) error { return f.err }
func (f fakeAudit) RuleStats(context.Context, time.Time) ([]precision.RuleStats, error) {
	return nil, f.err
}
func (f fakeAudit) ReviewQueue(context.Context, string, decision.Mode, int) ([]audit.ReviewItem, error) {
	return nil, f.err
}
func (f fakeAudit) Flush(context.Context) error { return f.err }

func newTestServer(t *testing.T, d Decider, log *slog.Logger, mod ...func(*Options)) *Server {
	t.Helper()
	opts := Options{
		Decider: d,
		Rules:   noRules{},
		Audit:   fakeAudit{err: errors.New("database is down")},
		Tokens:  []Token{{Name: "a", Value: "other-token-0123456789"}, {Name: "b", Value: testToken}},
		Logger:  log,
	}
	for _, m := range mod {
		m(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func serve(s http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestNewValidatesOptions(t *testing.T) {
	d := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) { return decision.Decision{}, nil })
	base := Options{Decider: d, Rules: noRules{}, Audit: fakeAudit{}, Tokens: []Token{{Name: "a", Value: "x"}}}
	tests := map[string]func(*Options){
		"decider": func(o *Options) { o.Decider = nil },
		"rules":   func(o *Options) { o.Rules = nil },
		"audit":   func(o *Options) { o.Audit = nil },
		"tokens":  func(o *Options) { o.Tokens = nil },
		"empty":   func(o *Options) { o.Tokens = []Token{{Name: "a"}} },
	}
	for name, mod := range tests {
		opts := base
		mod(&opts)
		if _, err := New(opts); err == nil {
			t.Errorf("%s: New accepted invalid options", name)
		}
	}
	if _, err := New(base); err != nil {
		t.Errorf("valid options: %v", err)
	}
}

func TestPanicIsRecovered(t *testing.T) {
	var logs bytes.Buffer
	s := newTestServer(t, deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		panic("boom")
	}), slog.New(slog.NewJSONHandler(&logs, nil)))
	rec := serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"code":"internal"`) {
		t.Errorf("panic answered %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "panic serving request") || !strings.Contains(logs.String(), "boom") {
		t.Errorf("panic not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"route":"POST /v1/decide"`) {
		t.Errorf("no access log after a panic: %s", logs.String())
	}
}

func TestAbortHandlerPanicPropagates(t *testing.T) {
	s := newTestServer(t, deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		panic(http.ErrAbortHandler)
	}), nil)
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	t.Error("the panic did not propagate")
}

func TestDecideErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("%w: %w", engine.ErrInvalidEvent, errors.New("event: type is required")), 400, "invalid_event"},
		{engine.ErrNoRuleset, 503, "no_ruleset"},
		{errors.New("engine: mark key k leaked: store down"), 503, "unavailable"},
	}
	for _, tt := range tests {
		s := newTestServer(t, deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
			return decision.Decision{}, tt.err
		}), nil)
		rec := serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
		if rec.Code != tt.status || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
			t.Errorf("%v: %d %s", tt.err, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "store down") {
			t.Errorf("an internal error reached the caller: %s", rec.Body)
		}
	}
	s := newTestServer(t, deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		return decision.Decision{}, tests[0].err
	}), nil)
	if body := serve(s, "POST", "/v1/decide", `{}`).Body.String(); !strings.Contains(body, `"message":"event: type is required"`) {
		t.Errorf("invalid event message: %s", body)
	}
}

func TestAuditErrorsAreHidden(t *testing.T) {
	s := newTestServer(t, nil, nil, func(o *Options) { o.Decider = deciderFunc(nil) })
	for _, path := range []string{"/v1/decisions/x", "/v1/rules/r/review"} {
		rec := serve(s, "GET", path, "")
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "database is down") {
			t.Errorf("GET %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := serve(s, "GET", "/v1/stats/rules", ""); rec.Code != 503 {
		t.Errorf("stats without a ruleset: %d %s", rec.Code, rec.Body)
	}
}

func TestUnconfiguredRoutes(t *testing.T) {
	s := newTestServer(t, deciderFunc(nil), nil, func(o *Options) {
		o.Checks = []Check{{Name: "store", Check: func(context.Context) error { return errors.New("unreachable") }}}
	})
	for _, path := range []string{"/v1/feedback", "/v1/feedback/ses", "/v1/feedback/usesend", "/v1/secret-scanning/github", "/v1/rules/reload"} {
		rec := serve(s, "POST", path, "{}")
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"code":"not_configured"`) {
			t.Errorf("POST %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := serve(s, "GET", "/metrics", ""); rec.Code != 404 {
		t.Errorf("metrics without a gatherer: %d", rec.Code)
	}
	rec := serve(s, "GET", "/readyz", "")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"store":"unreachable"`) {
		t.Errorf("readyz: %d %s", rec.Code, rec.Body)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                       "1",
		500 * time.Millisecond:  "1",
		time.Second:             "1",
		1500 * time.Millisecond: "2",
		time.Minute:             "60",
	} {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%v) = %s, want %s", d, got, want)
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"720h":                 now.Add(-720 * time.Hour),
		"90m":                  now.Add(-90 * time.Minute),
		"30d":                  now.AddDate(0, 0, -30),
		"2026-10-01T00:00:00Z": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		"2026-10-01":           time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	} {
		got, err := ParseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "soon", "0s", "-1h", "xd", "-3d"} {
		if _, err := ParseSince(in, now); err == nil {
			t.Errorf("ParseSince(%q) succeeded", in)
		}
	}
}

func TestRuleInfos(t *testing.T) {
	rs, err := rules.Parse([]byte(`version: 1
rules:
  - id: a
    when: event.type == "send"
    action: block
    mode: enforce
    on_error: open
    reason: r
    override: {by: me, reason: because, at: 2026-10-01}
  - id: b
    when: event.type == "send"
    action: flag
    reason: r
`))
	if err != nil {
		t.Fatal(err)
	}
	got := RuleInfos(rs)
	want := []precision.RuleInfo{{ID: "a", Mode: decision.Enforce, HasOverride: true}, {ID: "b", Mode: decision.Shadow}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("RuleInfos = %+v", got)
	}
}
