package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

const (
	defaultRules    = "../../rules/default.yaml"
	defaultFixtures = "../../rules/default.test.yaml"
	testToken       = "cli-test-token-0123456789abcdef"
)

// result is the outcome of one in-process run.
type result struct {
	code           int
	stdout, stderr string
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
}

func runCLI(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, lookup(env))
	return result{code, out.String(), errb.String()}
}

func lookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func expect(t *testing.T, r result, code int, contains ...string) {
	t.Helper()
	if r.code != code {
		t.Errorf("exit code %d, want %d\n%s", r.code, code, r)
		return
	}
	for _, s := range contains {
		if !strings.Contains(r.stdout+r.stderr, s) {
			t.Errorf("output lacks %q\n%s", s, r)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUsageAndVersion(t *testing.T) {
	expect(t, runCLI(t, nil), exitUsage, "Usage:", "Exit codes:")
	expect(t, runCLI(t, nil, "help"), exitOK, "rules gate")
	expect(t, runCLI(t, nil, "deploy"), exitUsage, `unknown command "deploy"`)
	expect(t, runCLI(t, nil, "rules"), exitUsage, "Usage: catraca rules <check|test|gate>")
	expect(t, runCLI(t, nil, "rules", "lint"), exitUsage, `unknown command "lint"`)
	expect(t, runCLI(t, nil, "config", "-h"), exitOK, "catraca config <check>")
	expect(t, runCLI(t, nil, "rules", "check", "-h"), exitOK, "--strict", "Flags:")
	expect(t, runCLI(t, nil, "rules", "check", "--nope", defaultRules), exitUsage, "flag provided but not defined")
	expect(t, runCLI(t, nil, "rules", "check"), exitUsage, "Usage: catraca rules check")

	r := runCLI(t, nil, "version")
	expect(t, r, exitOK, "catraca dev", "go1.")
}

const brokenRules = `version: 1
rules:
  - id: Not-Kebab
    when: event.type ==
    action: explode
    reason: x
`

// warnRules loads but has a lint warning: an enforced rule that inherits
// on_error.
const warnRules = `version: 1
rules:
  - id: inherits
    when: event.type == "send"
    action: flag
    mode: enforce
    reason: r
`

func TestRulesCheck(t *testing.T) {
	dir := t.TempDir()
	expect(t, runCLI(t, nil, "rules", "check", defaultRules), exitOK, "ok ", "9 rules (1 enforced, 8 shadow)")

	broken := writeFile(t, dir, "broken.yaml", brokenRules)
	r := runCLI(t, nil, "rules", "check", broken)
	expect(t, r, exitFailed, broken+":3:", "error(s)")
	if r.stdout != "" {
		t.Errorf("errors went to stdout: %s", r.stdout)
	}

	warn := writeFile(t, dir, "warn.yaml", warnRules)
	expect(t, runCLI(t, nil, "rules", "check", warn), exitOK, warn+":3: warning: rule inherits: enforced rule inherits on_error", "1 warning(s)")
	expect(t, runCLI(t, nil, "rules", "check", warn, "--strict"), exitFailed, "FAIL", "(--strict)")
	expect(t, runCLI(t, nil, "rules", "check", "--strict", warn), exitFailed, "(--strict)")

	expect(t, runCLI(t, nil, "rules", "check", filepath.Join(dir, "missing.yaml")), exitError, "missing.yaml")
}

func TestRulesTest(t *testing.T) {
	dir := t.TempDir()
	expect(t, runCLI(t, nil, "rules", "test", defaultRules, defaultFixtures), exitOK, "0 failed")

	rules := writeFile(t, dir, "rules.yaml", warnRules)
	pass := writeFile(t, dir, "pass.test.yaml", `cases:
  - name: a send is flagged
    signals: {event: {type: send}}
    expect: {action: flag, matches: [inherits]}
`)
	fail := writeFile(t, dir, "fail.test.yaml", `cases:
  - name: a send is allowed
    signals: {event: {type: send}}
    expect: {action: allow}
`)
	expect(t, runCLI(t, nil, "rules", "test", rules, pass), exitOK, "ok    a send is flagged", "1 cases, 0 failed")
	r := runCLI(t, nil, "rules", "test", rules, pass, fail)
	expect(t, r, exitFailed, "== "+pass, "== "+fail, "FAIL  a send is allowed", "action: want allow")

	badFixture := writeFile(t, dir, "bad.test.yaml", "cases:\n  - name: x\n    nope: 1\n")
	expect(t, runCLI(t, nil, "rules", "test", rules, badFixture), exitFailed, "unknown field")
	expect(t, runCLI(t, nil, "rules", "test", rules), exitUsage, "Usage: catraca rules test")
	expect(t, runCLI(t, nil, "rules", "test", rules, filepath.Join(dir, "none.yaml")), exitError)
}

// auditDB creates a SQLite audit database with n decisions that rule
// matched in mode, labeled true positive.
func auditDB(t *testing.T, rule string, mode decision.Mode, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	db, err := audit.Open(ctx, "sqlite:"+path, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	for i := range n {
		id := fmt.Sprintf("dec_%03d", i)
		ev := event.Event{ID: "ev_" + id, Type: event.Send, Time: now, AccountID: "acct"}
		m := decision.Match{RuleID: rule, Reason: "r", Action: decision.Block, Mode: mode}
		d := decision.Decision{ID: id, Time: now, Action: decision.Block, Matches: []decision.Match{m}, RulesetVersion: "v"}
		if mode == decision.Shadow {
			d.Action, d.Matches, d.Shadow = decision.Allow, nil, []decision.Match{m}
		}
		db.Record(ctx, ev, d)
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := db.Label(ctx, fmt.Sprintf("dec_%03d", i), audit.Label{Verdict: audit.TruePositive, By: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

const gateRules = `version: 1
rules:
  - id: proven
    when: event.type == "send"
    action: block
    mode: enforce
    on_error: open
    reason: r
  - id: unproven
    when: event.type == "send" && event.recipients > 10
    action: hold
    mode: %s
    on_error: open
    reason: r
`

func TestRulesGate(t *testing.T) {
	dir := t.TempDir()
	db := auditDB(t, "proven", decision.Enforce, 40)

	passing := writeFile(t, dir, "pass.yaml", fmt.Sprintf(gateRules, "shadow"))
	expect(t, runCLI(t, nil, "rules", "gate", passing, "--audit", db), exitOK, "proven", "passes", "1 enforced rule(s) pass")

	failing := writeFile(t, dir, "fail.yaml", fmt.Sprintf(gateRules, "enforce"))
	r := runCLI(t, nil, "rules", "gate", failing, "--audit", "sqlite:"+db)
	expect(t, r, exitFailed, "FAIL 1 enforced rule(s) below the gate", "unproven: insufficient_labels")

	// The same database read from $CATRACA_AUDIT_DSN, with a stricter gate.
	expect(t, runCLI(t, map[string]string{"CATRACA_AUDIT_DSN": db}, "rules", "gate", passing, "--min-labeled", "50"), exitFailed, "proven: insufficient_labels")
	expect(t, runCLI(t, nil, "rules", "gate", passing, "--audit", db, "--since", "1h"), exitOK)

	expect(t, runCLI(t, nil, "rules", "gate", passing), exitUsage, "--audit is required")
	expect(t, runCLI(t, nil, "rules", "gate", passing, "--audit", db, "--since", "later"), exitUsage, "--since")
	expect(t, runCLI(t, nil, "rules", "gate", passing, "--audit", db, "--min-precision", "2"), exitUsage, "--min-precision")
	expect(t, runCLI(t, nil, "rules", "gate", passing, "--audit", filepath.Join(dir, "nope.db")), exitError, "does not exist")
	if _, err := os.Stat(filepath.Join(dir, "nope.db")); err == nil {
		t.Error("rules gate created a missing database")
	}
	expect(t, runCLI(t, nil, "rules", "gate", writeFile(t, dir, "none.yaml", "version: 1\nrules: []\n"), "--audit", db), exitOK, "no enforced rules")
}

func TestReport(t *testing.T) {
	dir := t.TempDir()
	db := auditDB(t, "unproven", decision.Shadow, 40)
	rules := writeFile(t, dir, "rules.yaml", fmt.Sprintf(gateRules, "shadow"))

	r := runCLI(t, nil, "report", "--rules", rules, "--audit", db)
	expect(t, r, exitOK, "Gate: at least 30 labeled matches", "unproven", "Promote candidates", "matches since ")

	r = runCLI(t, nil, "report", "--rules", rules, "--audit", db, "--json", "--since", "all")
	expect(t, r, exitOK)
	var out struct {
		Since   time.Time `json:"since"`
		Version string    `json:"ruleset_version"`
		Promote []struct {
			RuleID string `json:"rule_id"`
		} `json:"promote"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("report --json is not JSON: %v\n%s", err, r.stdout)
	}
	if !out.Since.IsZero() || out.Version == "" || len(out.Promote) != 1 || out.Promote[0].RuleID != "unproven" {
		t.Errorf("report = %+v", out)
	}

	expect(t, runCLI(t, nil, "report", "--audit", db), exitUsage, "--rules is required")
	expect(t, runCLI(t, nil, "report", "--rules", rules, "--audit", db, "extra"), exitUsage)
}

func TestReplay(t *testing.T) {
	dir := t.TempDir()
	rules := writeFile(t, dir, "rules.yaml", warnRules)
	events := writeFile(t, dir, "events.jsonl", `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}, "label": "abusive"}

{"event": {"type": "account", "account_id": "b", "time": "2026-10-01T10:00:01Z", "account": {"action": "signup"}}, "label": "legit"}
{"event": {"type": "send", "account_id": "b", "time": "2026-10-01T10:00:02Z"}}
`)
	expect(t, runCLI(t, nil, "replay", rules, events), exitOK, "3 events, 2 labeled", "inherits")

	r := runCLI(t, nil, "replay", "--json", rules, events)
	expect(t, r, exitOK)
	var out map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("replay --json is not JSON: %v\n%s", err, r.stdout)
	}

	bad := writeFile(t, dir, "bad.jsonl", `{"event": {"type": "send", "account_id": "a"}}`+"\n")
	expect(t, runCLI(t, nil, "replay", rules, bad), exitFailed, "line 1")
	expect(t, runCLI(t, nil, "replay", rules, filepath.Join(dir, "none.jsonl")), exitError)
	expect(t, runCLI(t, nil, "replay", rules), exitUsage)
}

// labelRequest is what the fake server saw of the last label request.
type labelRequest struct {
	path, auth string
	label      audit.Label
}

func TestLabel(t *testing.T) {
	var mu sync.Mutex
	var last labelRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req labelRequest
		req.path, req.auth = r.URL.Path, r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req.label)
		mu.Lock()
		last = req
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "missing"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"decision \"missing\" is not in the audit log"}}`))
		case strings.Contains(r.URL.Path, "broken"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"the audit log could not be read"}}`))
		default:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(audit.Entry{Labels: []audit.Label{req.label}})
		}
	}))
	defer srv.Close()

	r := runCLI(t, map[string]string{"CATRACA_TOKEN": testToken}, "label", "dec/1",
		"--verdict", "false_positive", "--by", "support@platform", "--reason", "appeal #4411", "--rule", "burst", "--server", srv.URL+"/")
	expect(t, r, exitOK, "labeled decision dec/1 false_positive for rule burst; it has 1 label(s)")
	mu.Lock()
	got := last
	mu.Unlock()
	if got.path != "/v1/decisions/dec%2F1/labels" && got.path != "/v1/decisions/dec/1/labels" {
		t.Errorf("path = %q", got.path)
	}
	if got.auth != "Bearer "+testToken {
		t.Errorf("Authorization = %q", got.auth)
	}
	want := audit.Label{RuleID: "burst", Verdict: audit.FalsePositive, By: "support@platform", Reason: "appeal #4411"}
	if got.label != want {
		t.Errorf("label = %+v, want %+v", got.label, want)
	}

	server := map[string]string{"CATRACA_SERVER": srv.URL}
	expect(t, runCLI(t, server, "label", "x", "--verdict", "true_positive", "--by", "a", "--token", testToken), exitOK, "for every rule that matched")
	expect(t, runCLI(t, server, "label", "missing", "--verdict", "true_positive", "--by", "a", "--token", testToken), exitFailed, `404 Not Found: not_found: decision "missing"`)
	expect(t, runCLI(t, server, "label", "broken", "--verdict", "true_positive", "--by", "a", "--token", testToken), exitError, "500")
	expect(t, runCLI(t, server, "label", "x", "--verdict", "true_positive", "--by", "a"), exitUsage, "CATRACA_TOKEN")
	expect(t, runCLI(t, server, "label", "x", "--verdict", "yes", "--by", "a", "--token", testToken), exitUsage, "--verdict")
	expect(t, runCLI(t, server, "label", "x", "--verdict", "true_positive", "--token", testToken), exitUsage, "--by is required")
	expect(t, runCLI(t, nil, "label", "x", "--verdict", "true_positive", "--by", "a", "--token", testToken, "--server", "ftp://x"), exitUsage, "--server")
	expect(t, runCLI(t, nil, "label", "--verdict", "true_positive", "--by", "a", "--token", testToken), exitUsage)

	srv.Close()
	expect(t, runCLI(t, server, "label", "x", "--verdict", "true_positive", "--by", "a", "--token", testToken), exitError)
}

// testConfig writes a valid configuration next to a copy of the default
// ruleset.
func testConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	rules, err := os.ReadFile(defaultRules)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "rules.yaml", string(rules))
	return writeFile(t, dir, "catraca.yaml", `server:
  listen: 127.0.0.1:0
auth:
  tokens:
    - name: platform
      token: ${TOKEN}
rules:
  path: rules.yaml
audit:
  dsn: postgres://catraca:hunter2@db.internal:5432/catraca
`+extra)
}

func TestConfigCheck(t *testing.T) {
	env := map[string]string{"TOKEN": testToken}
	path := testConfig(t, "")
	r := runCLI(t, env, "config", "check", "-config", path)
	expect(t, r, exitOK, path+" is valid", "(1 warning(s))", "effect revoke_key has no hook",
		"api tokens  platform", "9 rules: 1 enforced, 8 shadow", "postgres://catraca:xxxxx@db.internal:5432/catraca")
	for _, secret := range []string{testToken, "hunter2"} {
		if strings.Contains(r.stdout+r.stderr, secret) {
			t.Errorf("config check printed a secret:\n%s", r)
		}
	}

	expect(t, runCLI(t, map[string]string{"TOKEN": testToken, "CATRACA_CONFIG": path}, "config", "check"), exitOK, "is valid")
	expect(t, runCLI(t, nil, "config", "check", "-config", path), exitFailed, "environment variable TOKEN is not set")
	bad := testConfig(t, "loging:\n  level: debug\n")
	expect(t, runCLI(t, env, "config", "check", "-config", bad), exitFailed, ":11: loging: unknown field (did you mean logging?)", "1 problem(s)")
	noRules := testConfig(t, "")
	if err := os.Remove(filepath.Join(filepath.Dir(noRules), "rules.yaml")); err != nil {
		t.Fatal(err)
	}
	expect(t, runCLI(t, env, "config", "check", "-config", noRules), exitFailed, "rules.path: the ruleset does not load")
	expect(t, runCLI(t, env, "config", "check", "-config", filepath.Join(t.TempDir(), "none.yaml")), exitError, "none.yaml")
	expect(t, runCLI(t, env, "config", "check", "extra"), exitUsage)
}

func TestServe(t *testing.T) {
	env := map[string]string{"TOKEN": testToken}
	expect(t, runCLI(t, nil, "serve", "-config", testConfig(t, "")), exitFailed, "TOKEN is not set")
	expect(t, runCLI(t, env, "serve", "-config", filepath.Join(t.TempDir(), "none.yaml")), exitError)

	// A config whose audit database cannot be opened fails to start.
	path := testConfig(t, "")
	data, _ := os.ReadFile(path)
	unreachable := strings.Replace(string(data), "db.internal:5432", "127.0.0.1:1", 1)
	if err := os.WriteFile(path, []byte(unreachable), 0o600); err != nil {
		t.Fatal(err)
	}
	expect(t, runCLI(t, env, "serve", "-config", path), exitError, "catraca could not start")

	// With a SQLite database it starts, and stops when its context ends.
	path = testConfig(t, "")
	data, _ = os.ReadFile(path)
	sqlite := strings.Replace(string(data), "postgres://catraca:hunter2@db.internal:5432/catraca", "sqlite:audit.db", 1)
	if err := os.WriteFile(path, []byte(sqlite), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errb syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve", "-config", path}, &out, &errb, lookup(env)) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(errb.String(), "catraca is listening") {
		if time.Now().After(deadline) {
			t.Fatalf("serve did not start:\n%s", errb.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK || !strings.Contains(errb.String(), `"msg":"stopped"`) {
			t.Errorf("serve: exit %d\n%s", code, errb.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "audit.db")); err != nil {
		t.Errorf("the audit database was not created next to the config: %v", err)
	}
}

// syncBuffer is a bytes.Buffer safe for a server's concurrent log writes.
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
