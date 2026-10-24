package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/app"
	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
	"github.com/guilhermebsantiago/catraca/signature"
)

const (
	token  = "test-token-0123456789abcdef0123456789"
	secret = "test-secret-0123456789abcdef012345678"
	// leakedToken is the API key the fake resolver knows.
	leakedToken = "acme_live_0123456789leaked"
)

// testRules has an enforced rule for each action the tests need and one
// shadow rule for the review queue.
const testRules = `version: 1
defaults: {mode: shadow, on_error: open}
rules:
  - id: leaked-key-send
    when: event.type == "send" && event.api_key_id != "" && key.leaked
    action: block
    mode: enforce
    on_error: open
    reason: The API key was found in public
  - id: leaked-key-reported
    when: event.type == "key_leak"
    action: block
    mode: enforce
    on_error: open
    effects: [revoke_key]
    reason: The API key was reported leaked
  - id: blocked-sender
    when: event.type == "send" && event.from_domain == "spam.example"
    action: block
    mode: enforce
    on_error: open
    reason: Known spam domain
  - id: burst
    when: event.type == "send" && account.sends_1m > 3
    action: throttle
    retry_after: 30s
    mode: enforce
    on_error: open
    reason: Sending too fast
  - id: complaints
    when: event.type == "send" && account.complaints_24h >= 2
    action: hold
    mode: enforce
    on_error: open
    reason: Too many complaints
  - id: wide-send
    when: event.type == "send" && event.recipients > 5
    action: flag
    reason: Many recipients
`

// harness is a running Catraca with fake GitHub, resolver and hook
// endpoints around it.
type harness struct {
	t         *testing.T
	dir       string
	rulesPath string
	dbPath    string
	app       *app.App
	srv       *httptest.Server
	hook      *hookServer
	github    *ecdsa.PrivateKey
	logs      *syncBuffer
}

type options struct {
	rules string
	// maxBodyBytes is server.max_body_bytes; zero means 4096, small enough
	// to test the limit.
	maxBodyBytes int
	// redisURL, when set, keeps counters in Redis instead of memory.
	redisURL string
	// drainDelay is server.drain_delay; empty means 0s.
	drainDelay string
	// auditDSN replaces the SQLite audit database in the test's directory.
	auditDSN string
	// admin sets server.admin_addr, so health and metrics leave the API's
	// handler.
	admin bool
	// resolverURL replaces the fake resolver of secret scanning.
	resolverURL string
	// extra is appended to the configuration: sections of its own.
	extra string
}

func newHarness(t *testing.T, opts options) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), logs: &syncBuffer{}}
	h.rulesPath = filepath.Join(h.dir, "rules.yaml")
	h.dbPath = filepath.Join(h.dir, "audit.db")
	if opts.rules == "" {
		opts.rules = testRules
	}
	if opts.maxBodyBytes == 0 {
		opts.maxBodyBytes = 4096
	}
	if opts.drainDelay == "" {
		opts.drainDelay = "0s"
	}
	if opts.auditDSN == "" {
		opts.auditDSN = "sqlite:" + filepath.ToSlash(h.dbPath)
	}
	h.writeRules(opts.rules)

	h.hook = newHookServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h.github = key
	keys := githubKeysServer(t, &key.PublicKey)
	if opts.resolverURL == "" {
		opts.resolverURL = resolverServer(t).URL
	}

	yaml := fmt.Sprintf(`
server:
  max_body_bytes: %d
  shutdown_timeout: 10s
  drain_delay: %s
auth:
  tokens:
    - name: test
      token: %s
rules:
  path: '%s'
audit:
  dsn: '%s'
# Even the memory store can miss the default 10ms on a loaded machine, and a
# degraded decision skips the rules that read account signals.
engine:
  deadline: 2s
hooks:
  - name: revoke_key
    url: %s
    secret: %s
feedback:
  generic:
    secret: %s
  usesend:
    secret: %s
secret_scanning:
  github:
    enabled: true
    keys_url: %s
    resolver:
      url: %s
      secret: %s
logging:
  level: debug
`, opts.maxBodyBytes, opts.drainDelay, token, filepath.ToSlash(h.rulesPath), opts.auditDSN, h.hook.URL, secret, secret, secret, keys.URL, opts.resolverURL, secret)
	if opts.redisURL != "" {
		yaml += fmt.Sprintf("store:\n  backend: redis\n  redis:\n    url: '%s'\n", opts.redisURL)
	}
	if opts.admin {
		// Tests pass their own listener; the address only turns it on.
		yaml = strings.Replace(yaml, "server:\n", "server:\n  admin_addr: 127.0.0.1:0\n", 1)
	}
	yaml += opts.extra
	cfg, err := config.Parse([]byte(yaml), "", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	log := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.app, err = app.New(context.Background(), cfg, app.Options{Logger: log, Version: "test"})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	h.srv = httptest.NewServer(h.app.Handler())
	t.Cleanup(func() {
		h.srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := h.app.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return h
}

func (h *harness) writeRules(content string) {
	h.t.Helper()
	if err := os.WriteFile(h.rulesPath, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// response is a decoded HTTP response.
type response struct {
	status int
	header http.Header
	body   []byte
	// close is set when the server closed the connection after the response
	// (net/http removes the Connection: close header).
	close bool
}

func (r response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

// errorCode returns the code of a {"error": {"code": ...}} body.
func (r response) errorCode(t *testing.T) string {
	t.Helper()
	code, _ := r.apiError(t)
	return code
}

// apiError returns the code and message of a {"error": {...}} body.
func (r response) apiError(t *testing.T) (code, message string) {
	t.Helper()
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	r.json(t, &e)
	if e.Error.Code == "" || e.Error.Message == "" {
		t.Fatalf("not an API error: %s", r.body)
	}
	return e.Error.Code, e.Error.Message
}

// do sends a request. body is sent as is when it is a string or []byte and
// encoded as JSON otherwise. auth is the bearer token, "" for none.
func (h *harness) do(method, path, auth string, body any, headers ...string) response {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: data, close: resp.Close}
}

// decide posts an event to /v1/decide and returns the decision.
func (h *harness) decide(ev map[string]any) (decision.Decision, response) {
	h.t.Helper()
	r := h.do("POST", "/v1/decide", token, ev)
	if r.status != http.StatusOK {
		h.t.Fatalf("decide: status %d: %s", r.status, r.body)
	}
	var out api.DecisionResponse
	r.json(h.t, &out)
	return out.Decision, r
}

func send(account, from string, extra ...any) map[string]any {
	ev := map[string]any{"type": "send", "account_id": account, "from": from, "to": []string{"someone@mail.example"}}
	for i := 0; i+1 < len(extra); i += 2 {
		ev[extra[i].(string)] = extra[i+1]
	}
	return ev
}

func TestDecideActions(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})

	d, _ := h.decide(send("acct_good", "hello@shop.example"))
	if d.Action != decision.Allow || d.ID == "" || d.RulesetVersion != h.app.Ruleset().Version() {
		t.Errorf("good send: %+v", d)
	}

	d, _ = h.decide(send("acct_spam", "win@spam.example"))
	if d.Action != decision.Block || len(d.Matches) != 1 || d.Matches[0].RuleID != "blocked-sender" {
		t.Errorf("spam send: %+v", d)
	}

	var r response
	for range 4 {
		d, r = h.decide(send("acct_fast", "hi@fast.example"))
	}
	if d.Action != decision.Throttle || d.RetryAfter != 30*time.Second {
		t.Errorf("fourth send in a minute: %+v", d)
	}
	if got := r.header.Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q, want 30", got)
	}
	if _, r = h.decide(send("acct_good", "hello@shop.example")); r.header.Get("Retry-After") != "" {
		t.Error("Retry-After set on an allowed send")
	}

	r = h.do("POST", "/v1/events", token, map[string]any{"type": "account", "account_id": "acct_new", "ip": "203.0.113.9", "account": map[string]any{"action": "signup"}})
	if r.status != http.StatusAccepted {
		t.Fatalf("POST /v1/events: %d %s", r.status, r.body)
	}
	var ev api.DecisionResponse
	r.json(t, &ev)
	if ev.Decision.Action != decision.Allow {
		t.Errorf("account event: %+v", ev.Decision)
	}

	r = h.do("GET", "/v1/decisions/"+ev.Decision.ID, token, nil)
	if r.status != http.StatusOK {
		t.Fatalf("GET decision: %d %s", r.status, r.body)
	}
	var entry audit.Entry
	r.json(t, &entry)
	if entry.Decision.ID != ev.Decision.ID || entry.Event.AccountAction != "signup" || entry.Labels == nil {
		t.Errorf("entry = %+v", entry)
	}
	if r := h.do("GET", "/v1/decisions/nope", token, nil); r.status != http.StatusNotFound || r.errorCode(t) != "not_found" {
		t.Errorf("unknown decision: %d %s", r.status, r.body)
	}
}

func TestAuth(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	ev := send("acct", "a@b.example")

	for name, header := range map[string]string{
		"missing":      "",
		"wrong token":  "Bearer not-the-token-0123456789abcdef",
		"basic scheme": "Basic " + base64.StdEncoding.EncodeToString([]byte("u:"+token)),
		"no token":     "Bearer ",
	} {
		r := h.do("POST", "/v1/decide", "", ev, "Authorization", header)
		if r.status != http.StatusUnauthorized || r.errorCode(t) != "unauthorized" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate header", name)
		}
	}
	for _, path := range []string{"/v1/rules", "/v1/decisions/x", "/v1/stats/rules", "/v1/rules/burst/review"} {
		if r := h.do("GET", path, "", nil); r.status != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: %d", path, r.status)
		}
	}
	if r := h.do("POST", "/v1/decide", "", ev, "Authorization", "bearer "+token); r.status != http.StatusOK {
		t.Errorf("lowercase scheme: %d %s", r.status, r.body)
	}

	// Feedback and secret scanning authenticate by signature, not by token:
	// the signature check answers, with or without a bearer token.
	for _, auth := range []string{"", token} {
		r := h.do("POST", "/v1/feedback", auth, `{"account_id":"a","feedback":{"kind":"complaint"}}`)
		if r.status != http.StatusUnauthorized || !strings.Contains(string(r.body), "invalid signature") {
			t.Errorf("unsigned feedback (token %q): %d %s", auth, r.status, r.body)
		}
		r = h.do("POST", "/v1/secret-scanning/github", auth, `[]`)
		if r.status != http.StatusUnauthorized || !strings.Contains(string(r.body), "missing signature") {
			t.Errorf("unsigned batch (token %q): %d %s", auth, r.status, r.body)
		}
	}
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		if r := h.do("GET", path, "", nil); r.status != http.StatusOK {
			t.Errorf("GET %s: %d", path, r.status)
		}
	}
}

func TestInvalidEvents(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	tests := []struct {
		name, body string
		status     int
		code, msg  string
	}{
		{"no type", `{"account_id":"a"}`, 400, "invalid_event", "event: type is required"},
		{"unknown type", `{"type":"email","account_id":"a"}`, 400, "invalid_event", "unknown type email"},
		{"no account", `{"type":"send"}`, 400, "invalid_event", "account_id is required"},
		{"feedback without details", `{"type":"feedback","account_id":"a"}`, 400, "invalid_event", "feedback object"},
		{"NUL in an id", `{"type":"send","account_id":"acct\u0000"}`, 400, "invalid_event", "event: account_id contains the control character U+0000"},
		{"escape in a key id", `{"type":"send","account_id":"a","api_key_id":"\u001b[2J"}`, 400, "invalid_event", "api_key_id contains the control character U+001B"},
		{"NUL in the subject", `{"type":"send","account_id":"a","subject":"hi\u0000"}`, 400, "invalid_event", "subject contains NUL"},
		{"dated 1970", `{"type":"send","account_id":"a","time":"1970-01-01T00:00:00Z"}`, 400, "invalid_event", "event: time 1970-01-01T00:00:00Z is more than 168h0m0s in the past"},
		{"empty body", ``, 400, "invalid_json", "the body is empty"},
		{"syntax", `{"type":`, 400, "invalid_json", "truncated"},
		{"bad syntax", `{"type" "send"}`, 400, "invalid_json", "invalid JSON at byte"},
		{"misspelled field", `{"type":"send","acount_id":"a"}`, 400, "invalid_json", `unknown field "acount_id"`},
		{"wrong type", `{"type":"send","account_id":"a","to":"x@y.example"}`, 400, "invalid_json", "to: want a list, got a JSON string"},
		{"bad time", `{"type":"send","account_id":"a","time":"yesterday"}`, 400, "invalid_json", "invalid time"},
		{"two values", `{"type":"send","account_id":"a"} {}`, 400, "invalid_json", "a single JSON value"},
		{"too large", `{"type":"send","account_id":"a","subject":"` + strings.Repeat("x", 5000) + `"}`, 413, "body_too_large", "larger than 4096 bytes"},
	}
	for _, tt := range tests {
		r := h.do("POST", "/v1/decide", token, tt.body)
		if r.status != tt.status {
			t.Errorf("%s: status %d, want %d: %s", tt.name, r.status, tt.status, r.body)
			continue
		}
		if code, msg := r.apiError(t); code != tt.code || !strings.Contains(msg, tt.msg) {
			t.Errorf("%s: %s, want code %s and %q", tt.name, r.body, tt.code, tt.msg)
		}
	}
}

func TestLabelsAndStats(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	var ids []string
	for range 3 {
		d, _ := h.decide(send("acct_spam", "win@spam.example"))
		ids = append(ids, d.ID)
	}
	label := func(id string, body any) response {
		return h.do("POST", "/v1/decisions/"+id+"/labels", token, body)
	}
	for i, id := range ids {
		verdict := audit.TruePositive
		if i == 2 {
			verdict = audit.FalsePositive
		}
		r := label(id, audit.Label{Verdict: verdict, By: "reviewer@platform", Reason: "checked"})
		if r.status != http.StatusCreated {
			t.Fatalf("label: %d %s", r.status, r.body)
		}
		var entry audit.Entry
		r.json(t, &entry)
		if len(entry.Labels) != 1 || entry.Labels[0].Verdict != verdict || entry.Labels[0].By != "reviewer@platform" {
			t.Errorf("labels = %+v", entry.Labels)
		}
	}

	if r := label("missing", audit.Label{Verdict: audit.TruePositive, By: "x"}); r.status != 404 || r.errorCode(t) != "not_found" {
		t.Errorf("unknown decision: %d %s", r.status, r.body)
	}
	if r := label(ids[0], map[string]any{"verdict": "maybe", "by": "x"}); r.status != 400 || r.errorCode(t) != "invalid_label" {
		t.Errorf("bad verdict: %d %s", r.status, r.body)
	}
	if r := label(ids[0], map[string]any{"verdict": "true_positive"}); r.status != 400 || r.errorCode(t) != "invalid_label" {
		t.Errorf("no by: %d %s", r.status, r.body)
	}
	if r := label(ids[0], audit.Label{RuleID: "burst", Verdict: audit.TruePositive, By: "x"}); r.status != 422 || r.errorCode(t) != "rule_not_matched" {
		t.Errorf("rule that did not match: %d %s", r.status, r.body)
	}

	r := h.do("GET", "/v1/stats/rules?since=1h", token, nil)
	if r.status != http.StatusOK {
		t.Fatalf("stats: %d %s", r.status, r.body)
	}
	var stats api.StatsResponse
	r.json(t, &stats)
	if stats.RulesetVersion != h.app.Ruleset().Version() || stats.Gate.MinLabeled != 30 || time.Since(stats.Since) < 59*time.Minute {
		t.Errorf("stats header: %+v", stats)
	}
	var found bool
	for _, res := range stats.Rules {
		if res.RuleID != "blocked-sender" {
			continue
		}
		found = true
		if res.Matches != 3 || res.Labeled != 3 || res.TruePositives != 2 || res.FalsePositives != 1 || res.Mode != decision.Enforce {
			t.Errorf("blocked-sender stats = %+v", res)
		}
		if res.Status != "insufficient_labels" {
			t.Errorf("status = %s, want insufficient_labels with 3 of 30 labels", res.Status)
		}
	}
	if !found || len(stats.Rules) != len(h.app.Ruleset().Rules()) {
		t.Errorf("rules in stats: %+v", stats.Rules)
	}
	if stats.Promote == nil || stats.Retire == nil {
		t.Errorf("promote and retire must be lists: %s", r.body)
	}

	for _, since := range []string{"30d", "2026-01-01T00:00:00Z", "2026-01-01"} {
		if r := h.do("GET", "/v1/stats/rules?since="+since, token, nil); r.status != http.StatusOK {
			t.Errorf("since=%s: %d %s", since, r.status, r.body)
		}
	}
	for _, since := range []string{"soon", "-1h", "0s"} {
		if r := h.do("GET", "/v1/stats/rules?since="+since, token, nil); r.status != 400 || r.errorCode(t) != "invalid_parameter" {
			t.Errorf("since=%s: %d %s", since, r.status, r.body)
		}
	}
}

func TestReviewQueue(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	to := []string{"a@1.example", "b@2.example", "c@3.example", "d@4.example", "e@5.example", "f@6.example"}
	d, _ := h.decide(send("acct_wide", "news@wide.example", "to", to))
	if d.Action != decision.Allow || len(d.Shadow) != 1 || d.Shadow[0].RuleID != "wide-send" {
		t.Fatalf("decision = %+v", d)
	}

	review := func(query string) api.ReviewResponse {
		t.Helper()
		r := h.do("GET", "/v1/rules/wide-send/review"+query, token, nil)
		if r.status != http.StatusOK {
			t.Fatalf("review: %d %s", r.status, r.body)
		}
		var out api.ReviewResponse
		r.json(t, &out)
		return out
	}
	q := review("?mode=shadow&limit=10")
	if q.RuleID != "wide-send" || q.Mode != decision.Shadow || len(q.Items) != 1 {
		t.Fatalf("queue = %+v", q)
	}
	if it := q.Items[0]; it.DecisionID != d.ID || it.Reason != "Many recipients" || it.Event.Recipients != 6 || it.Event.FromDomain != "wide.example" {
		t.Errorf("item = %+v", it)
	}
	if q := review("?mode=enforce"); len(q.Items) != 0 {
		t.Errorf("enforce queue = %+v", q.Items)
	}

	r := h.do("POST", "/v1/decisions/"+d.ID+"/labels", token, audit.Label{RuleID: "wide-send", Verdict: audit.FalsePositive, By: "reviewer"})
	if r.status != http.StatusCreated {
		t.Fatalf("label: %d %s", r.status, r.body)
	}
	if q := review(""); len(q.Items) != 0 {
		t.Errorf("a labeled match is still queued: %+v", q.Items)
	}

	for _, query := range []string{"?mode=sometimes", "?limit=0", "?limit=5000", "?limit=x"} {
		if r := h.do("GET", "/v1/rules/wide-send/review"+query, token, nil); r.status != 400 || r.errorCode(t) != "invalid_parameter" {
			t.Errorf("%s: %d %s", query, r.status, r.body)
		}
	}
}

func TestReload(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	rulesVersion := func() string {
		t.Helper()
		r := h.do("GET", "/v1/rules", token, nil)
		if r.status != http.StatusOK {
			t.Fatalf("GET /v1/rules: %d %s", r.status, r.body)
		}
		var rs struct {
			Version string            `json:"version"`
			Rules   []json.RawMessage `json:"rules"`
		}
		r.json(t, &rs)
		if len(rs.Rules) == 0 {
			t.Fatalf("no rules in %s", r.body)
		}
		return rs.Version
	}
	v1 := rulesVersion()

	h.writeRules(testRules + "  - id: Broken Rule\n    when: event.type ==\n")
	r := h.do("POST", "/v1/rules/reload", token, nil)
	if r.status != http.StatusUnprocessableEntity || r.errorCode(t) != "invalid_ruleset" {
		t.Fatalf("broken reload: %d %s", r.status, r.body)
	}
	var e struct {
		Error struct {
			Message string   `json:"message"`
			Details []string `json:"details"`
		} `json:"error"`
	}
	r.json(t, &e)
	if !strings.Contains(e.Error.Message, "still serving version "+v1) || len(e.Error.Details) < 2 {
		t.Errorf("error = %+v", e.Error)
	}
	if got := rulesVersion(); got != v1 {
		t.Fatalf("a broken file replaced the ruleset: %s -> %s", v1, got)
	}
	if d, _ := h.decide(send("acct", "win@spam.example")); d.Action != decision.Block || d.RulesetVersion != v1 {
		t.Errorf("decision after a failed reload: %+v", d)
	}

	h.writeRules(strings.Replace(testRules, `event.from_domain == "spam.example"`, `event.from_domain == "junk.example"`, 1))
	r = h.do("POST", "/v1/rules/reload", token, nil)
	if r.status != http.StatusOK {
		t.Fatalf("reload: %d %s", r.status, r.body)
	}
	var rel api.ReloadResponse
	r.json(t, &rel)
	if rel.PreviousVersion != v1 || rel.Version == v1 || !rel.Changed || rel.Rules != 6 || rel.Warnings == nil {
		t.Errorf("reload = %+v", rel)
	}
	if got := rulesVersion(); got != rel.Version {
		t.Errorf("version after reload = %s, want %s", got, rel.Version)
	}
	if d, _ := h.decide(send("acct", "win@spam.example")); d.Action != decision.Allow || d.RulesetVersion != rel.Version {
		t.Errorf("decision after reload: %+v", d)
	}
	metrics := h.do("GET", "/metrics", "", nil)
	for _, want := range []string{`catraca_ruleset_loads_total{result="error"} 1`, `catraca_ruleset_loads_total{result="ok"} 2`, `catraca_ruleset_info{version="` + rel.Version + `"} 1`} {
		if !strings.Contains(string(metrics.body), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestStartWithoutRuleset(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{rules: "version: 1\nrules: [oops\n"})
	if h.app.Ruleset() != nil {
		t.Fatal("a broken ruleset loaded")
	}
	r := h.do("GET", "/readyz", "", nil)
	if r.status != http.StatusServiceUnavailable || !strings.Contains(string(r.body), `"rules":"no ruleset loaded"`) {
		t.Errorf("readyz: %d %s", r.status, r.body)
	}
	if r := h.do("POST", "/v1/decide", token, send("a", "x@y.example")); r.status != 503 || r.errorCode(t) != "no_ruleset" {
		t.Errorf("decide: %d %s", r.status, r.body)
	}
	if r := h.do("GET", "/v1/rules", token, nil); r.status != 503 || r.errorCode(t) != "no_ruleset" {
		t.Errorf("rules: %d %s", r.status, r.body)
	}
	if r := h.do("POST", "/v1/rules/reload", token, nil); r.status != 422 || !strings.Contains(string(r.body), "no ruleset is loaded") {
		t.Errorf("broken reload: %d %s", r.status, r.body)
	}

	h.writeRules(testRules)
	if r := h.do("POST", "/v1/rules/reload", token, nil); r.status != http.StatusOK {
		t.Fatalf("reload: %d %s", r.status, r.body)
	}
	r = h.do("GET", "/readyz", "", nil)
	if r.status != http.StatusOK || !strings.Contains(string(r.body), `"status":"ready"`) {
		t.Errorf("readyz after reload: %d %s", r.status, r.body)
	}
	if d, _ := h.decide(send("a", "x@y.example")); d.Action != decision.Allow {
		t.Errorf("decide after reload: %+v", d)
	}
}

func TestReadiness(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	r := h.do("GET", "/readyz", "", nil)
	var ready api.ReadyResponse
	r.json(t, &ready)
	want := map[string]string{"rules": "ok", "shutdown": "ok"}
	if r.status != http.StatusOK || ready.Status != "ready" || fmt.Sprint(ready.Checks) != fmt.Sprint(want) || ready.Dependencies != nil {
		t.Errorf("readyz: %d %s", r.status, r.body)
	}
	if r := h.do("GET", "/healthz", "", nil); r.status != http.StatusOK || !strings.Contains(string(r.body), `"ok"`) {
		t.Errorf("healthz: %d %s", r.status, r.body)
	}

	// The memory store is not a dependency; the audit database is.
	eventually(t, 5*time.Second, func() bool {
		r = h.do("GET", "/readyz?verbose", "", nil)
		ready = api.ReadyResponse{}
		r.json(t, &ready)
		return ready.Dependencies["audit"].Status == "ok"
	})
	if _, ok := ready.Dependencies["store"]; ok || r.status != http.StatusOK || ready.Dependencies["audit"].CheckedAt.IsZero() {
		t.Errorf("readyz?verbose: %d %s", r.status, r.body)
	}
	m := string(h.do("GET", "/metrics", "", nil).body)
	if !strings.Contains(m, `catraca_dependency_up{dependency="audit"} 1`) {
		t.Errorf("metrics lack catraca_dependency_up for the audit database")
	}
}

// TestReadinessIgnoresDependencies runs the server on a Redis that does not
// answer: decisions are degraded, and the server stays ready.
func TestReadinessIgnoresDependencies(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // nothing listens there now
	h := newHarness(t, options{redisURL: "redis://" + ln.Addr().String() + "/0"})

	d, _ := h.decide(send("acct", "a@shop.example"))
	if !d.Degraded || d.Action != decision.Allow {
		t.Errorf("decision with Redis down: %+v", d)
	}
	r := h.do("GET", "/readyz", "", nil)
	if r.status != http.StatusOK {
		t.Errorf("readyz with Redis down: %d %s", r.status, r.body)
	}
	var ready api.ReadyResponse
	eventually(t, 10*time.Second, func() bool {
		r = h.do("GET", "/readyz?verbose", "", nil)
		ready = api.ReadyResponse{}
		r.json(t, &ready)
		return ready.Dependencies["store"].Status == "unavailable" && ready.Dependencies["audit"].Status == "ok"
	})
	if r.status != http.StatusOK || ready.Status != "ready" {
		t.Errorf("readyz?verbose with Redis down: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), ln.Addr().String()) {
		t.Errorf("readyz shows the Redis address: %s", r.body)
	}
	if m := string(h.do("GET", "/metrics", "", nil).body); !strings.Contains(m, `catraca_dependency_up{dependency="store"} 0`) {
		t.Error("metrics do not show the store down")
	}
	if !strings.Contains(h.logs.String(), "a dependency is unavailable") {
		t.Error("no log of the store going down")
	}
}

// TestServesWhileTheAuditDatabaseIsUnreachable starts the server with a
// Postgres audit database that refuses connections: it starts, is ready,
// decides, answers 503 where the audit log is needed, and says so in its
// dependencies, metrics and logs.
func TestServesWhileTheAuditDatabaseIsUnreachable(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // nothing listens there now
	h := newHarness(t, options{auditDSN: "postgres://catraca:pw@" + ln.Addr().String() + "/catraca?sslmode=disable"})

	if r := h.do("GET", "/readyz", "", nil); r.status != http.StatusOK {
		t.Errorf("readyz: %d %s", r.status, r.body)
	}
	d, _ := h.decide(send("acct", "win@spam.example"))
	if d.Action != decision.Block {
		t.Errorf("decision without the audit log: %+v", d)
	}
	if r := h.do("GET", "/v1/decisions/"+d.ID, token, nil); r.status != http.StatusServiceUnavailable || r.errorCode(t) != "audit_unavailable" {
		t.Errorf("GET decision: %d %s", r.status, r.body)
	}
	if r := h.do("GET", "/v1/stats/rules", token, nil); r.status != http.StatusServiceUnavailable || r.errorCode(t) != "audit_unavailable" {
		t.Errorf("GET stats: %d %s", r.status, r.body)
	}
	var ready api.ReadyResponse
	eventually(t, 10*time.Second, func() bool {
		r := h.do("GET", "/readyz?verbose", "", nil)
		ready = api.ReadyResponse{}
		r.json(t, &ready)
		return ready.Dependencies["audit"].Status == "not_open"
	})
	if ready.Status != "ready" {
		t.Errorf("readyz?verbose: %+v", ready)
	}
	if m := string(h.do("GET", "/metrics", "", nil).body); !strings.Contains(m, `catraca_dependency_up{dependency="audit"} 0`) {
		t.Error("metrics do not show the audit database down")
	}
	eventually(t, 10*time.Second, func() bool {
		return strings.Contains(h.logs.String(), "the audit database is unreachable; deciding without the audit log")
	})
}

// signedFeedback posts a generic feedback event signed with secret.
func (h *harness) signedFeedback(body string, key string) response {
	h.t.Helper()
	return h.do("POST", "/v1/feedback", "", body, signature.Header, signature.Sign(key, time.Now(), []byte(body)))
}

// useSend posts a useSend webhook about one email of team, signed as useSend
// signs them. Each webhook call has its own id, as in useSend, unless the
// same one is sent again: the id is made from kind and createdAt.
func (h *harness) useSend(kind string, createdAt time.Time, team int) response {
	h.t.Helper()
	body := fmt.Sprintf(`{"id":"call_%s_%d","type":%q,"createdAt":%q,"teamId":%d,"data":{"id":"email_1","from":"news@us.example","to":["someone@mail.example"]}}`,
		kind, createdAt.UnixNano(), kind, createdAt.UTC().Format(time.RFC3339), team)
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + body))
	return h.do("POST", "/v1/feedback/usesend", "", body,
		"X-UseSend-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)), "X-UseSend-Timestamp", ts)
}

// TestEventTimeBoundsOnEveryRoute sends events dated a month ahead and in
// 1970 through every route that takes an event time. A time ahead counts
// when it arrives, so it cannot empty the counters rules read; a time older
// than every counter is refused, so it cannot make an account look old.
// Secret scanning stamps events with the time it receives them.
func TestEventTimeBoundsOnEveryRoute(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	ahead := time.Now().Add(30 * 24 * time.Hour)
	epoch := time.Unix(0, 0)

	// POST /v1/decide: the send dated ahead is the first of four in a minute.
	first, _ := h.decide(send("acct_skew", "hi@skew.example", "time", ahead))
	var d decision.Decision
	for range 3 {
		d, _ = h.decide(send("acct_skew", "hi@skew.example"))
	}
	if d.Action != decision.Throttle {
		t.Errorf("fourth send in a minute, the first dated a month ahead: %+v", d)
	}
	r := h.do("GET", "/v1/decisions/"+first.ID, token, nil)
	if r.status != http.StatusOK {
		t.Fatalf("GET decision: %d %s", r.status, r.body)
	}
	var entry audit.Entry
	r.json(t, &entry)
	if off := time.Since(entry.Event.Time); off < -time.Minute || off > time.Minute {
		t.Errorf("stored event time %s, want the time it arrived", entry.Event.Time)
	}

	// POST /v1/events.
	r = h.do("POST", "/v1/events", token, map[string]any{"type": "account", "account_id": "acct_old", "time": epoch, "account": map[string]any{"action": "signup"}})
	if code, msg := r.apiError(t); r.status != http.StatusBadRequest || code != "invalid_event" || !strings.Contains(msg, "in the past") {
		t.Errorf("account event dated 1970: %d %s", r.status, r.body)
	}

	// POST /v1/feedback: complaints dated ahead and now both count.
	for _, at := range []time.Time{ahead, time.Now()} {
		body := fmt.Sprintf(`{"account_id":"acct_gen","time":%q,"feedback":{"kind":"complaint"}}`, at.UTC().Format(time.RFC3339))
		if r := h.signedFeedback(body, secret); r.status != http.StatusAccepted {
			t.Fatalf("generic complaint at %s: %d %s", at, r.status, r.body)
		}
	}
	if d, _ := h.decide(send("acct_gen", "news@gen.example")); d.Action != decision.Hold {
		t.Errorf("send after two complaints, one dated a month ahead: %+v", d)
	}
	r = h.signedFeedback(`{"account_id":"acct_gen","time":"1970-01-01T00:00:00Z","feedback":{"kind":"complaint"}}`, secret)
	if r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "in the past") {
		t.Errorf("generic complaint dated 1970: %d %s", r.status, r.body)
	}

	// POST /v1/feedback/usesend: the same, for the account that is team 4242.
	for _, at := range []time.Time{ahead, time.Now()} {
		if r := h.useSend("email.complained", at, 4242); r.status != http.StatusOK {
			t.Fatalf("useSend complaint at %s: %d %s", at, r.status, r.body)
		}
	}
	if d, _ := h.decide(send("4242", "news@us.example")); d.Action != decision.Hold {
		t.Errorf("send after two useSend complaints, one dated a month ahead: %+v", d)
	}
	// Refused, and acknowledged so that useSend does not retry it.
	if r := h.useSend("email.complained", epoch, 4242); r.status != http.StatusOK {
		t.Errorf("useSend complaint dated 1970: %d %s", r.status, r.body)
	}

	m := string(h.do("GET", "/metrics", "", nil).body)
	for _, want := range []string{
		`catraca_event_times_out_of_bounds_total{bound="future"} 3`,
		`catraca_event_times_out_of_bounds_total{bound="past"} 3`,
		`catraca_feedback_outcomes_total{outcome="malformed",provider="generic"} 1`,
		`catraca_feedback_outcomes_total{outcome="malformed",provider="usesend"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestEventLimits(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{maxBodyBytes: 1 << 20})
	to := func(n int) []string {
		addrs := make([]string, n)
		for i := range addrs {
			addrs[i] = fmt.Sprintf("u%d@d%d.example", i, i)
		}
		return addrs
	}
	h.decide(send("acct_wide", "news@wide.example", "to", to(event.MaxRecipients)))
	tests := []struct {
		name string
		ev   map[string]any
		msg  string
	}{
		{"too many recipients", send("acct_wide", "news@wide.example", "to", to(event.MaxRecipients+1)), "event: to has 1001 addresses; at most 1000 are accepted"},
		{"too many links", send("acct_wide", "news@wide.example", "links", to(event.MaxLinks+1)), "event: links has 1001 links"},
		{"account id too long", send(strings.Repeat("a", event.MaxIDBytes+1), "news@wide.example"), "event: account_id is 257 bytes; at most 256 are accepted"},
		{"subject too long", send("acct_wide", "news@wide.example", "subject", strings.Repeat("s", event.MaxTextBytes+1)), "event: subject is 8193 bytes"},
	}
	for _, tt := range tests {
		r := h.do("POST", "/v1/decide", token, tt.ev)
		if r.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tt.name, r.status)
			continue
		}
		if code, msg := r.apiError(t); code != "invalid_event" || !strings.HasPrefix(msg, tt.msg) {
			t.Errorf("%s: %s %q, want invalid_event %q", tt.name, code, msg, tt.msg)
		}
	}
}

func TestGenericFeedbackChangesLaterDecisions(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	if d, _ := h.decide(send("acct_fb", "news@fb.example")); d.Action != decision.Allow {
		t.Fatalf("first send: %+v", d)
	}
	complaint := `{"account_id":"acct_fb","from":"news@fb.example","feedback":{"kind":"complaint","recipient":"angry@mail.example"}}`
	if r := h.signedFeedback(complaint, "wrong-secret-0123456789abcdef"); r.status != http.StatusUnauthorized {
		t.Errorf("wrongly signed feedback: %d %s", r.status, r.body)
	}
	for range 2 {
		r := h.signedFeedback(complaint, secret)
		if r.status != http.StatusAccepted {
			t.Fatalf("feedback: %d %s", r.status, r.body)
		}
		var out api.DecisionResponse
		r.json(t, &out)
		if out.Decision.ID == "" {
			t.Errorf("feedback answer has no decision: %s", r.body)
		}
	}
	d, _ := h.decide(send("acct_fb", "news@fb.example"))
	if d.Action != decision.Hold || len(d.Matches) != 1 || d.Matches[0].RuleID != "complaints" {
		t.Errorf("send after two complaints: %+v", d)
	}
	if d, _ := h.decide(send("acct_other", "news@other.example")); d.Action != decision.Allow {
		t.Errorf("another account: %+v", d)
	}
	if r := h.do("POST", "/v1/feedback/ses", "", `{}`); r.status != 404 || r.errorCode(t) != "not_configured" {
		t.Errorf("unconfigured SES: %d %s", r.status, r.body)
	}
}

// TestFeedbackIsRetriedWhenTheStoreFails checks that feedback the store
// could not count is answered 503, so the provider sends it again, while a
// send is still decided, and that the feedback counts once it is.
func TestFeedbackIsRetriedWhenTheStoreFails(t *testing.T) {
	t.Parallel()
	mr := storetest.Miniredis(t)
	h := newHarness(t, options{redisURL: "redis://" + mr.Addr() + "/0?read_timeout=1m"})
	mr.SetError("LOADING Redis is loading the dataset in memory")

	d, r := h.decide(send("acct_down", "news@down.example"))
	if !d.Degraded || !d.Uncounted || r.status != http.StatusOK {
		t.Errorf("send with the store failing: %d %+v, want 200 and a degraded, uncounted decision", r.status, d)
	}
	complaint := `{"id":"fb-1","account_id":"acct_down","feedback":{"kind":"complaint"}}`
	r = h.signedFeedback(complaint, secret)
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "10" {
		t.Errorf("generic complaint with the store failing: %d %s, Retry-After %q", r.status, r.body, r.header.Get("Retry-After"))
	}
	at := time.Now()
	if r := h.useSend("email.complained", at, 4343); r.status != http.StatusServiceUnavailable {
		t.Errorf("useSend complaint with the store failing: %d %s", r.status, r.body)
	}

	mr.SetError("")
	for i := range 2 {
		r = h.signedFeedback(complaint, secret)
		var out api.DecisionResponse
		r.json(t, &out)
		if r.status != http.StatusAccepted || out.Decision.Duplicate != (i > 0) {
			t.Errorf("complaint sent again, %d: %d %s", i+1, r.status, r.body)
		}
		if r := h.useSend("email.complained", at, 4343); r.status != http.StatusOK {
			t.Errorf("useSend complaint sent again, %d: %d %s", i+1, r.status, r.body)
		}
	}
	m := string(h.do("GET", "/metrics", "", nil).body)
	for _, want := range []string{
		`catraca_feedback_outcomes_total{outcome="uncounted",provider="generic"} 1`,
		`catraca_feedback_outcomes_total{outcome="uncounted",provider="usesend"} 1`,
		`catraca_duplicate_events_total{type="feedback"} 2`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// TestRetriesCountOnce sends events again with the ids they were first sent
// with, as platforms and providers retry, through the decide, events,
// generic feedback and useSend routes, on each store: each event counts
// once, and the answer to a retry says it was a duplicate.
func TestRetriesCountOnce(t *testing.T) {
	t.Parallel()
	stores := map[string]string{
		"memory":    "",
		"miniredis": "redis://" + storetest.Miniredis(t).Addr() + "/0?read_timeout=1m",
	}
	if url := os.Getenv(storetest.RedisURLEnv); url != "" {
		stores["redis-server"] = url
	}
	for name, url := range stores {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, options{redisURL: url})
			// A real Redis keeps the counters of earlier runs: the
			// accounts are new each time.
			run := time.Now().UnixNano()
			acct := fmt.Sprintf("acct_retry_%d", run)

			// burst throttles the fourth send in a minute; one send sent
			// four times is one send.
			for i := range 4 {
				d, _ := h.decide(send(acct, "hi@retry.example", "id", "msg-1"))
				if d.Action != decision.Allow || d.Duplicate != (i > 0) || d.EventID != "msg-1" {
					t.Errorf("send %d of msg-1: %+v", i+1, d)
				}
			}
			for _, id := range []string{"msg-2", "msg-3"} {
				if d, _ := h.decide(send(acct, "hi@retry.example", "id", id)); d.Action != decision.Allow || d.Duplicate {
					t.Errorf("%s: %+v, want the third and fourth sends allowed", id, d)
				}
			}
			if d, _ := h.decide(send(acct, "hi@retry.example", "id", "msg-4")); d.Action != decision.Throttle {
				t.Errorf("fifth send: %+v, want throttled", d)
			}

			// complaints holds an account with two; one complaint sent
			// twice is one.
			complaint := map[string]any{"id": "fb-1", "type": "feedback", "account_id": acct + "_fb", "feedback": map[string]any{"kind": "complaint"}}
			for i := range 2 {
				r := h.do("POST", "/v1/events", token, complaint)
				var out api.DecisionResponse
				r.json(t, &out)
				if r.status != http.StatusAccepted || out.Decision.Duplicate != (i > 0) {
					t.Errorf("complaint %d of fb-1: %d %s", i+1, r.status, r.body)
				}
			}
			if d, _ := h.decide(send(acct+"_fb", "hi@retry.example")); d.Action != decision.Allow {
				t.Errorf("send after one complaint sent twice: %+v", d)
			}

			// The same through the generic feedback endpoint.
			generic := fmt.Sprintf(`{"id":"fb-1","account_id":%q,"feedback":{"kind":"complaint"}}`, acct+"_gen")
			for i := range 2 {
				r := h.signedFeedback(generic, secret)
				var out api.DecisionResponse
				r.json(t, &out)
				if r.status != http.StatusAccepted || out.Decision.Duplicate != (i > 0) {
					t.Errorf("generic complaint %d of fb-1: %d %s", i+1, r.status, r.body)
				}
			}
			if d, _ := h.decide(send(acct+"_gen", "hi@retry.example")); d.Action != decision.Allow {
				t.Errorf("send after one generic complaint sent twice: %+v", d)
			}

			// And for useSend, which sends a webhook call again with its
			// id.
			team := int(run % 1_000_000_000)
			at := time.Now()
			for range 2 {
				if r := h.useSend("email.complained", at, team); r.status != http.StatusOK {
					t.Fatalf("useSend complaint: %d %s", r.status, r.body)
				}
			}
			if d, _ := h.decide(send(strconv.Itoa(team), "news@us.example")); d.Action != decision.Allow {
				t.Errorf("send after one useSend complaint sent twice: %+v", d)
			}
			if r := h.useSend("email.complained", at.Add(time.Second), team); r.status != http.StatusOK {
				t.Fatalf("useSend complaint: %d %s", r.status, r.body)
			}
			if d, _ := h.decide(send(strconv.Itoa(team), "news@us.example")); d.Action != decision.Hold {
				t.Errorf("send after two useSend complaints: %+v", d)
			}

			m := string(h.do("GET", "/metrics", "", nil).body)
			for _, want := range []string{
				`catraca_duplicate_events_total{type="send"} 3`,
				`catraca_duplicate_events_total{type="feedback"} 3`,
			} {
				if !strings.Contains(m, want) {
					t.Errorf("metrics lack %s", want)
				}
			}
		})
	}
}

func TestGitHubSecretScanningBlocksLeakedKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	if d, _ := h.decide(send("acct_leak", "app@leak.example", "api_key_id", "key_leaked")); d.Action != decision.Allow {
		t.Fatalf("send before the leak: %+v", d)
	}

	batch := []byte(`[{"token":"` + leakedToken + `","type":"acme_api_key","url":"https://github.com/octo/repo/blob/main/.env","source":"content"},` +
		`{"token":"acme_live_somebody_else","type":"acme_api_key","url":"https://github.com/octo/repo","source":"commit"}]`)
	digest := sha256.Sum256(batch)
	sig, err := ecdsa.SignASN1(rand.Reader, h.github, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/secret-scanning/github", "", batch,
		"Github-Public-Key-Identifier", "test-key",
		"Github-Public-Key-Signature", base64.StdEncoding.EncodeToString(sig))
	if r.status != http.StatusAccepted {
		t.Fatalf("batch: %d %s", r.status, r.body)
	}
	bad := h.do("POST", "/v1/secret-scanning/github", "", batch,
		"Github-Public-Key-Identifier", "test-key",
		"Github-Public-Key-Signature", base64.StdEncoding.EncodeToString(sig[:len(sig)-2]))
	if bad.status != http.StatusUnauthorized {
		t.Errorf("forged batch: %d %s", bad.status, bad.body)
	}

	// Each attempt sends from its own account, so a leak that takes a while
	// to land does not also trip the burst rule of a busy account.
	var (
		d        decision.Decision
		attempts int
	)
	eventually(t, 10*time.Second, func() bool {
		attempts++
		d, _ = h.decide(send(fmt.Sprintf("acct_leak_%d", attempts), "app@leak.example", "api_key_id", "key_leaked"))
		return d.Action == decision.Block
	})
	if len(d.Matches) != 1 || d.Matches[0].RuleID != "leaked-key-send" {
		t.Errorf("send after the leak: %+v", d)
	}
	if d, _ := h.decide(send("acct_other", "app@other.example", "api_key_id", "key_other")); d.Action != decision.Allow {
		t.Errorf("another key: %+v", d)
	}

	// The key_leak decision called the revoke_key hook, signed.
	var got hookCall
	eventually(t, 10*time.Second, func() bool {
		calls := h.hook.calls()
		if len(calls) > 0 {
			got = calls[0]
		}
		return len(calls) > 0
	})
	if err := signature.Verify(secret, got.signature, got.body, 0); err != nil {
		t.Errorf("hook signature: %v", err)
	}
	var payload struct {
		Effect   string   `json:"effect"`
		APIKeyID string   `json:"api_key_id"`
		RuleIDs  []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Effect != "revoke_key" || payload.APIKeyID != "key_leaked" || len(payload.RuleIDs) != 1 || payload.RuleIDs[0] != "leaked-key-reported" {
		t.Errorf("hook payload = %s", got.body)
	}

	eventually(t, 5*time.Second, func() bool {
		m := string(h.do("GET", "/metrics", "", nil).body)
		return strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="leaked"} 1`) &&
			strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="not_found"} 1`) &&
			strings.Contains(m, "catraca_hooks_delivered_total 1")
	})
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	h.decide(send("acct", "a@shop.example"))
	h.decide(send("acct", "a@spam.example"))
	h.signedFeedback(`{"account_id":"acct","feedback":{"kind":"delivery"}}`, secret)
	h.do("POST", "/v1/decide", token, `{}`)

	// The hooks count their backlog when they start, in the background.
	eventually(t, 5*time.Second, func() bool {
		m := string(h.do("GET", "/metrics", "", nil).body)
		return strings.Contains(m, "catraca_audit_recorded_total 3") && strings.Contains(m, `catraca_hooks_pending{hook="revoke_key"} 0`)
	})
	m := string(h.do("GET", "/metrics", "", nil).body)
	for _, want := range []string{
		`catraca_decisions_total{action="allow"} 2`,
		`catraca_decisions_total{action="block"} 1`,
		`catraca_rule_matches_total{mode="enforce",rule="blocked-sender"} 1`,
		`catraca_decision_duration_seconds_count 3`,
		`catraca_http_request_duration_seconds_count{route="POST /v1/decide",status="200"} 2`,
		`catraca_http_request_duration_seconds_count{route="POST /v1/decide",status="400"} 1`,
		`catraca_http_request_duration_seconds_count{route="POST /v1/feedback",status="202"} 1`,
		`catraca_feedback_outcomes_total{outcome="decided",provider="generic"} 1`,
		`catraca_feedback_outcomes_total{outcome="invalid_signature",provider="generic"} 0`,
		`catraca_secret_scanning_outcomes_total{outcome="leaked"} 0`,
		`catraca_audit_recorded_total 3`,
		`catraca_audit_dropped_total 0`,
		`catraca_audit_rejected_total 0`,
		`catraca_audit_queued 0`,
		`catraca_audit_retention_deleted_total{table="decisions"} 0`,
		`catraca_audit_retention_deleted_total{table="outbox"} 0`,
		`catraca_audit_retention_errors_total 0`,
		`go_sql_max_open_connections{db_name="audit"} 10`,
		`catraca_hooks_delivered_total 0`,
		`catraca_hooks_dead_total 0`,
		`catraca_hooks_expired_total 0`,
		`catraca_hooks_enqueue_deferred_total 0`,
		`catraca_hooks_pending_due{hook="revoke_key"} 0`,
		`catraca_hooks_oldest_pending_age_seconds{hook="revoke_key"} 0`,
		`catraca_ruleset_rules{mode="enforce"} 5`,
		`catraca_ruleset_rules{mode="shadow"} 1`,
		`catraca_build_info{goversion=`,
		`catraca_records_dropped_total 0`,
		`go_goroutines `,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestRoutingAndRequestIDs(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	r := h.do("GET", "/v1/decide", token, nil)
	if r.status != http.StatusMethodNotAllowed || r.header.Get("Allow") != "POST" || r.errorCode(t) != "method_not_allowed" {
		t.Errorf("GET /v1/decide: %d %v %s", r.status, r.header, r.body)
	}
	r = h.do("DELETE", "/v1/rules", token, nil)
	if r.status != http.StatusMethodNotAllowed || r.header.Get("Allow") != "GET" {
		t.Errorf("DELETE /v1/rules: %d %v", r.status, r.header)
	}
	if r := h.do("GET", "/v2/decide", token, nil); r.status != 404 || r.errorCode(t) != "not_found" {
		t.Errorf("unknown route: %d %s", r.status, r.body)
	}

	r = h.do("GET", "/healthz", "", nil, api.RequestIDHeader, "trace-abc.123")
	if got := r.header.Get(api.RequestIDHeader); got != "trace-abc.123" {
		t.Errorf("request id = %q, want the client's", got)
	}
	r = h.do("GET", "/healthz", "", nil, api.RequestIDHeader, "bad id\twith spaces")
	if got := r.header.Get(api.RequestIDHeader); len(got) != 32 {
		t.Errorf("request id = %q, want a generated one", got)
	}
	d, r := h.decide(send("acct_log", "a@shop.example"))
	id := r.header.Get(api.RequestIDHeader)

	// The access log names the route, the client and the decision.
	var line map[string]any
	for _, l := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(l, `"request_id":"`+id+`"`) {
			if err := json.Unmarshal([]byte(l), &line); err != nil {
				t.Fatal(err)
			}
		}
	}
	if line["route"] != "POST /v1/decide" || line["client"] != "test" || line["decision_id"] != d.ID || line["status"] != float64(200) {
		t.Errorf("access log line = %v", line)
	}
	if strings.Contains(h.logs.String(), token) || strings.Contains(h.logs.String(), secret) {
		t.Error("a secret reached the logs")
	}
}

func TestServeShutsDownInOrder(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.app.Serve(ctx, ln, nil) }()

	h.srv.URL = "http://" + ln.Addr().String()
	var ids []string
	for range 20 {
		d, _ := h.decide(send("acct_shutdown", "a@shop.example"))
		ids = append(ids, d.ID)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return")
	}

	// Every decision made before the shutdown is in the audit log.
	db, err := audit.Open(context.Background(), "sqlite:"+h.dbPath, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	for _, id := range ids {
		if _, err := db.Get(context.Background(), id); err != nil {
			t.Errorf("decision %s: %v", id, err)
		}
	}
	if !strings.Contains(h.logs.String(), `"msg":"stopped"`) {
		t.Error("no stopped log line")
	}
}

// serveOn runs h's app on a new local listener, points h's requests at it,
// and returns the function that stops it and the channel Serve's result
// arrives on.
func (h *harness) serveOn() (stop context.CancelFunc, done <-chan error) {
	h.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- h.app.Serve(ctx, ln, nil) }()
	h.srv.URL = "http://" + ln.Addr().String()
	h.t.Cleanup(cancel)
	return cancel, errc
}

// waitServe waits for Serve's result.
func waitServe(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestServeDrains checks the drain on shutdown: once the context ends, the
// server reports not ready, still decides, closes connections after each
// response, and stops only when the drain is over. The test, not the clock,
// ends the drain, so a slow machine cannot end it before the checks run.
func TestServeDrains(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{drainDelay: "1h"})
	release := make(chan struct{})
	app.HoldDrain(h.app, release)
	stop, done := h.serveOn()
	if r := h.do("GET", "/readyz", "", nil); r.status != http.StatusOK {
		t.Fatalf("readyz before the shutdown: %d %s", r.status, r.body)
	}

	stop()
	var r response
	eventually(t, 10*time.Second, func() bool {
		r = h.do("GET", "/readyz", "", nil)
		return r.status == http.StatusServiceUnavailable
	})
	if !strings.Contains(string(r.body), `"shutdown":"draining"`) || !strings.Contains(string(r.body), `"rules":"ok"`) {
		t.Errorf("readyz while draining: %s", r.body)
	}
	d, r := h.decide(send("acct_drain", "a@shop.example"))
	if d.ID == "" || !r.close {
		t.Errorf("decide while draining: %+v, connection closed: %t", d, r.close)
	}
	select {
	case err := <-done:
		t.Fatalf("Serve returned %v before the drain ended", err)
	case <-time.After(50 * time.Millisecond):
	}
	if !strings.Contains(h.logs.String(), `"msg":"draining: reporting not ready`) {
		t.Errorf("no log line for the drain:\n%s", h.logs)
	}

	close(release)
	waitServe(t, done)
	if !strings.Contains(h.logs.String(), `"msg":"stopped"`) {
		t.Error("no stopped log line")
	}
}

// TestAdminListener checks server.admin_addr: health and metrics move to the
// admin listener, take no token there, and leave the API listener, which
// keeps every other route.
func TestAdminListener(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{admin: true})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.app.Serve(ctx, ln, admin) }()

	apiURL, adminURL := "http://"+ln.Addr().String(), "http://"+admin.Addr().String()
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		h.srv.URL = adminURL
		if r := h.do("GET", path, "", nil); r.status != http.StatusOK {
			t.Errorf("admin GET %s: %d %s", path, r.status, r.body)
		}
		h.srv.URL = apiURL
		if r := h.do("GET", path, "", nil); r.status != http.StatusNotFound {
			t.Errorf("API GET %s: %d, want 404", path, r.status)
		}
	}
	h.srv.URL = adminURL
	if r := h.do("POST", "/v1/decide", token, send("acct", "a@shop.example")); r.status != http.StatusNotFound {
		t.Errorf("admin POST /v1/decide: %d, want 404", r.status)
	}
	h.srv.URL = apiURL
	h.decide(send("acct", "a@shop.example"))
	if !strings.Contains(h.logs.String(), `"admin_addr":"`+admin.Addr().String()+`"`) {
		t.Error("the listening log line lacks the admin address")
	}

	cancel()
	waitServe(t, done)
	if _, err := net.Dial("tcp", admin.Addr().String()); err == nil {
		t.Error("the admin listener is still open after Serve returned")
	}

	// Serve refuses a listener the configuration does not expect, and the
	// lack of one it does.
	other := newHarness(t, options{})
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	admin2, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := other.app.Serve(context.Background(), ln2, admin2); err == nil {
		t.Error("Serve accepted an admin listener without server.admin_addr")
	}
}

// TestServeDrainDelay checks that the drain lasts at least
// server.drain_delay on the clock.
func TestServeDrainDelay(t *testing.T) {
	t.Parallel()
	const delay = 200 * time.Millisecond
	h := newHarness(t, options{drainDelay: delay.String()})
	stop, done := h.serveOn()
	h.do("GET", "/healthz", "", nil)
	stop()
	start := time.Now()
	waitServe(t, done)
	if took := time.Since(start); took < delay {
		t.Errorf("Serve stopped %v after its context ended, before the %v drain delay", took, delay)
	}
}

func eventually(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met after %v", timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// githubKeysServer is a fake of GitHub's secret scanning public keys
// endpoint, serving pub as "test-key".
func githubKeysServer(t *testing.T, pub *ecdsa.PublicKey) *httptest.Server {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"public_keys": []map[string]any{{
		"key_identifier": "test-key",
		"key":            string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		"is_current":     true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// resolverServer is a fake platform resolver that knows one key.
func resolverServer(t *testing.T) *httptest.Server {
	t.Helper()
	want := sha256.Sum256([]byte(leakedToken))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := signature.Verify(secret, r.Header.Get(signature.Header), body, 0); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var req struct {
			TokenSHA256 string `json:"token_sha256"`
			Token       string `json:"token"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Token != "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.TokenSHA256 != hex.EncodeToString(want[:]) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"api_key_id":"key_leaked","account_id":"acct_leak"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type hookCall struct {
	signature string
	body      []byte
}

// hookServer records the effect webhooks it receives.
type hookServer struct {
	*httptest.Server
	mu  sync.Mutex
	got []hookCall
}

func newHookServer(t *testing.T) *hookServer {
	t.Helper()
	h := &hookServer{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got = append(h.got, hookCall{signature: r.Header.Get(signature.Header), body: body})
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookServer) calls() []hookCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hookCall(nil), h.got...)
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
