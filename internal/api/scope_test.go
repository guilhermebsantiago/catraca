package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// scopedRoutes are the routes that take a token, with the scope each needs
// and a request the route accepts.
var scopedRoutes = []struct {
	pattern, path, body string
	scope               Scope
}{
	{"POST /v1/decide", "/v1/decide", `{"type":"send","account_id":"a"}`, ScopeDecide},
	{"POST /v1/events", "/v1/events", `{"type":"send","account_id":"a"}`, ScopeDecide},
	{"GET /v1/decisions", "/v1/decisions?account_id=a", "", ScopeRead},
	{"GET /v1/decisions/{id}", "/v1/decisions/d1", "", ScopeRead},
	{"POST /v1/decisions/{id}/labels", "/v1/decisions/d1/labels", `{"verdict":"true_positive","by":"ana"}`, ScopeLabel},
	{"GET /v1/rules", "/v1/rules", "", ScopeRead},
	{"POST /v1/rules/reload", "/v1/rules/reload", "", ScopeAdmin},
	{"GET /v1/rules/{id}/review", "/v1/rules/r1/review", "", ScopeRead},
	{"GET /v1/stats/rules", "/v1/stats/rules", "", ScopeRead},
	{"GET /v1/accounts/{id}/state", "/v1/accounts/a/state", "", ScopeRead},
	{"PUT /v1/accounts/{id}/state", "/v1/accounts/a/state", `{"state":"review"}`, ScopeAdmin},
	{"DELETE /v1/accounts/{id}/state", "/v1/accounts/a/state", "", ScopeAdmin},
}

// scopedTokens are one client per scope, one with every scope, and a token
// each of the decide and full clients is rotating out.
var scopedTokens = []Token{
	{Name: "send-path", Value: "tok-decide-0123456789", Scopes: []Scope{ScopeDecide}},
	{Name: "send-path", Value: "tok-decide-old-0123456789", Scopes: []Scope{ScopeDecide}, Previous: true},
	{Name: "reader", Value: "tok-read-0123456789", Scopes: []Scope{ScopeRead}},
	{Name: "labeler", Value: "tok-label-0123456789", Scopes: []Scope{ScopeLabel}},
	{Name: "admin", Value: "tok-admin-0123456789", Scopes: []Scope{ScopeAdmin}},
	{Name: "ops", Value: "tok-ops-0123456789", Scopes: []Scope{ScopeRead, ScopeLabel, ScopeAdmin}},
	{Name: "full", Value: "tok-full-0123456789"},
	{Name: "full", Value: "tok-full-old-0123456789", Previous: true},
}

func newScopedServer(t *testing.T, logs *bytes.Buffer, a AuditLog) *Server {
	t.Helper()
	d := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		return decision.Decision{ID: "d1", Action: decision.Allow}, nil
	})
	return newTestServer(t, d, slog.New(slog.NewJSONHandler(logs, nil)), func(o *Options) {
		o.Tokens = scopedTokens
		if a != nil {
			o.Audit = a
		}
	})
}

func send(s http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// lastLog returns the last access log line.
func lastLog(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("access log %q: %v", lines[len(lines)-1], err)
	}
	return m
}

func TestRouteScopes(t *testing.T) {
	var logs bytes.Buffer
	s := newScopedServer(t, &logs, nil)

	// Every route that takes a token is in the table, with its scope, so a
	// new route cannot be added without deciding its scope here too.
	want := map[string]Scope{}
	for _, rt := range scopedRoutes {
		want[rt.pattern] = rt.scope
	}
	if !maps.Equal(s.routeScopes, want) {
		t.Fatalf("the server's route scopes are %v, the test's %v", s.routeScopes, want)
	}

	for _, rt := range scopedRoutes {
		method, _, _ := strings.Cut(rt.pattern, " ")
		t.Run(rt.pattern, func(t *testing.T) {
			for name, header := range map[string]string{"no token": "", "wrong token": "tok-wrong-0123456789"} {
				rec := send(s, method, rt.path, rt.body, header)
				if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"unauthorized"`) {
					t.Errorf("%s: %d %s, want 401 unauthorized", name, rec.Code, rec.Body)
				}
				if log := lastLog(t, &logs); log["scope_check"] != nil || log["client"] != nil {
					t.Errorf("%s: access log %v names a client or a scope check", name, log)
				}
			}
			for _, tok := range scopedTokens {
				label := tok.Name
				if tok.Previous {
					label += " (previous)"
				}
				allowed := tok.Scopes == nil || slices.Contains(tok.Scopes, rt.scope)
				rec := send(s, method, rt.path, rt.body, tok.Value)
				log := lastLog(t, &logs)
				if log["client"] != tok.Name || log["scope"] != string(rt.scope) {
					t.Errorf("%s: access log %v, want client %s and scope %s", label, log, tok.Name, rt.scope)
				}
				if tok.Previous && log["previous_token"] != true {
					t.Errorf("%s: access log %v does not say previous_token", label, log)
				}
				if !allowed {
					if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"insufficient_scope"`) ||
						!strings.Contains(rec.Body.String(), "the "+string(rt.scope)+" scope") {
						t.Errorf("%s: %d %s, want 403 insufficient_scope naming %s", label, rec.Code, rec.Body, rt.scope)
					}
					if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="catraca", error="insufficient_scope", scope="`+string(rt.scope)+`"` {
						t.Errorf("%s: WWW-Authenticate %q", label, got)
					}
					if log["scope_check"] != "denied" || log["status"] != float64(http.StatusForbidden) {
						t.Errorf("%s: access log %v, want scope_check denied", label, log)
					}
					continue
				}
				if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
					t.Errorf("%s: %d %s, want the route to answer", label, rec.Code, rec.Body)
				}
				if log["scope_check"] != "allowed" {
					t.Errorf("%s: access log %v, want scope_check allowed", label, log)
				}
			}
		})
	}
}

// TestUnscopedRoutesTakeNoToken checks that the routes without a scope
// answer without a token: feedback and secret scanning authenticate by
// signature, health and metrics by where they listen.
func TestUnscopedRoutesTakeNoToken(t *testing.T) {
	var logs bytes.Buffer
	s := newScopedServer(t, &logs, nil)
	for _, rt := range []struct{ method, path string }{
		{"POST", "/v1/feedback"},
		{"POST", "/v1/feedback/ses"},
		{"POST", "/v1/feedback/usesend"},
		{"POST", "/v1/secret-scanning/github"},
		{"GET", "/healthz"},
		{"GET", "/readyz"},
	} {
		rec := send(s, rt.method, rt.path, "", "")
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s %s without a token: %d %s", rt.method, rt.path, rec.Code, rec.Body)
		}
	}
}

func TestNewRejectsBadScopes(t *testing.T) {
	d := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) { return decision.Decision{}, nil })
	for name, scopes := range map[string][]Scope{"empty": {}, "unknown": {ScopeRead, "write"}} {
		_, err := New(Options{Decider: d, Rules: noRules{}, Audit: fakeAudit{}, Tokens: []Token{{Name: "a", Value: "x", Scopes: scopes}}})
		if err == nil {
			t.Errorf("%s: New accepted scopes %q", name, scopes)
		}
	}
}

// TestScopesMatchConfig keeps the scopes the configuration accepts and the
// scopes the server knows the same.
func TestScopesMatchConfig(t *testing.T) {
	var names []string
	for _, sc := range Scopes {
		names = append(names, string(sc))
	}
	if !slices.Equal(names, config.TokenScopes) {
		t.Errorf("api.Scopes = %v, config.TokenScopes = %v", names, config.TokenScopes)
	}
}

// TestDocsListRouteScopes keeps the route table of docs/api.md in step with
// the server: each route that takes a token has a row naming its scope.
func TestDocsListRouteScopes(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "api.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for line := range strings.SplitSeq(string(doc), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			continue
		}
		route, scope := strings.Trim(strings.TrimSpace(cells[1]), "`"), strings.Trim(strings.TrimSpace(cells[2]), "`")
		rows[route] = scope
	}
	for _, rt := range scopedRoutes {
		if rows[rt.pattern] != string(rt.scope) {
			t.Errorf("docs/api.md: no row | `%s` | `%s` | in the route scope table", rt.pattern, rt.scope)
		}
	}
}

// labelAudit records the label it is given.
type labelAudit struct {
	fakeAudit
	got []audit.Label
}

func (a *labelAudit) Label(_ context.Context, _ string, l audit.Label) error {
	a.got = append(a.got, l)
	return nil
}

func (a *labelAudit) Get(context.Context, string) (audit.Entry, error) {
	return audit.Entry{Labels: a.got}, nil
}

// TestLabelRecordsTheToken checks that a label keeps the name of the token
// that gave it, whatever the body says.
func TestLabelRecordsTheToken(t *testing.T) {
	var logs bytes.Buffer
	a := &labelAudit{}
	s := newScopedServer(t, &logs, a)
	rec := send(s, "POST", "/v1/decisions/d1/labels", `{"verdict":"false_positive","by":"appeals","client":"someone-else"}`, "tok-label-0123456789")
	if rec.Code != http.StatusCreated {
		t.Fatalf("label: %d %s", rec.Code, rec.Body)
	}
	if len(a.got) != 1 || a.got[0].Client != "labeler" || a.got[0].By != "appeals" {
		t.Errorf("labeled %+v, want by appeals with client labeler", a.got)
	}
	if !strings.Contains(rec.Body.String(), `"client":"labeler"`) {
		t.Errorf("the response does not show the label's client: %s", rec.Body)
	}
}
