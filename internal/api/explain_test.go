package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

func newExplainServer(t *testing.T, ruleset string) *Server {
	t.Helper()
	holder := rules.NewHolder(nil)
	if ruleset != "" {
		rs, err := rules.Parse([]byte(ruleset))
		if err != nil {
			t.Fatal(err)
		}
		holder.Store(rs)
	}
	e, err := engine.New(engine.Options{
		Catalog: signal.NewCatalog(store.NewMemory(), signal.Options{}),
		Rules:   holder,
	})
	if err != nil {
		t.Fatal(err)
	}
	return newTestServer(t, e, nil)
}

const explainTestRuleset = `version: 1
rules:
  - id: burst
    when: account.sends_1m > 1
    action: throttle
    retry_after: 30s
    mode: enforce
    on_error: open
    reason: burst
`

func TestExplain(t *testing.T) {
	s := newExplainServer(t, explainTestRuleset)
	const ev = `{"type":"send","id":"evt_1","account_id":"a","from":"x@example.com","to":["y@example.org"]}`
	for i, want := range []struct {
		observed, counted, duplicate bool
		sends                        any
		matched                      bool
	}{
		{sends: nil},
		{observed: true, counted: true, sends: 1.0},
		{observed: true, duplicate: true, sends: 1.0},
	} {
		path := "/v1/rules/explain"
		if want.observed {
			path += "?observe=true"
		}
		rec := serve(s, "POST", path, ev)
		if rec.Code != http.StatusOK {
			t.Fatalf("explanation %d: %d %s", i, rec.Code, rec.Body)
		}
		var got struct {
			RulesetVersion string `json:"ruleset_version"`
			Observed       bool
			Counted        bool
			Duplicate      bool
			Action         decision.Action
			Signals        struct {
				Event   map[string]any
				Account map[string]any
			}
			Rules []struct {
				ID      string
				Matched bool
				Mode    decision.Mode
				OnError decision.OnError `json:"on_error"`
				Error   string
			}
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Observed != want.observed || got.Counted != want.counted || got.Duplicate != want.duplicate {
			t.Errorf("explanation %d: %s", i, rec.Body)
		}
		if got.Signals.Event["recipients"] != 1.0 || got.Signals.Account["sends_1m"] != want.sends {
			t.Errorf("explanation %d: signals %+v", i, got.Signals)
		}
		if len(got.Rules) != 1 || got.Rules[0].ID != "burst" || got.Rules[0].Matched || got.Rules[0].Mode != decision.Enforce ||
			got.Rules[0].OnError != decision.FailOpen || got.RulesetVersion == "" || got.Action != decision.Allow {
			t.Errorf("explanation %d: %s", i, rec.Body)
		}
		if !want.observed && !strings.Contains(rec.Body.String(), `"account":null`) {
			t.Errorf("explanation %d does not show the absent account signals as null: %s", i, rec.Body)
		}
	}
}

// TestExplainObserveNeedsDecide: a read token explains, but observing counts
// the event, so it needs the decide scope too.
func TestExplainObserveNeedsDecide(t *testing.T) {
	rs, err := rules.Parse([]byte(explainTestRuleset))
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.New(engine.Options{
		Catalog: signal.NewCatalog(store.NewMemory(), signal.Options{}),
		Rules:   rules.NewHolder(rs),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, e, nil, func(o *Options) { o.Tokens = scopedTokens })
	const ev = `{"type":"send","account_id":"a"}`
	for _, tc := range []struct {
		token, path string
		status      int
	}{
		{"tok-read-0123456789", "/v1/rules/explain", http.StatusOK},
		{"tok-read-0123456789", "/v1/rules/explain?observe=true", http.StatusForbidden},
		{"tok-ops-0123456789", "/v1/rules/explain?observe=true", http.StatusForbidden},
		{"tok-full-0123456789", "/v1/rules/explain?observe=true", http.StatusOK},
		{"tok-decide-0123456789", "/v1/rules/explain", http.StatusForbidden},
	} {
		rec := send(s, "POST", tc.path, ev, tc.token)
		if rec.Code != tc.status {
			t.Errorf("%s %s: %d %s, want %d", tc.token, tc.path, rec.Code, rec.Body, tc.status)
		}
		if rec.Code == http.StatusForbidden && strings.Contains(tc.path, "observe") &&
			!strings.Contains(rec.Header().Get("WWW-Authenticate"), `scope="decide"`) {
			t.Errorf("%s %s: WWW-Authenticate %q does not name the decide scope", tc.token, tc.path, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestExplainErrors(t *testing.T) {
	s := newExplainServer(t, explainTestRuleset)
	for _, tc := range []struct {
		name, path, body string
		status           int
		code             string
	}{
		{"observe", "/v1/rules/explain?observe=maybe", `{"type":"send","account_id":"a"}`, http.StatusBadRequest, "invalid_parameter"},
		{"invalid event", "/v1/rules/explain", `{"type":"nope"}`, http.StatusBadRequest, "invalid_event"},
		{"key_leak", "/v1/rules/explain", `{"type":"key_leak","api_key_id":"k"}`, http.StatusBadRequest, "invalid_event"},
		{"bad json", "/v1/rules/explain", `{`, http.StatusBadRequest, "invalid_json"},
	} {
		rec := serve(s, "POST", tc.path, tc.body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) {
			t.Errorf("%s: %d %s, want %d %s", tc.name, rec.Code, rec.Body, tc.status, tc.code)
		}
	}

	rec := serve(newExplainServer(t, ""), "POST", "/v1/rules/explain", `{"type":"send","account_id":"a"}`)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"code":"no_ruleset"`) {
		t.Errorf("no ruleset: %d %s", rec.Code, rec.Body)
	}

	d := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) { return decision.Decision{}, nil })
	rec = serve(newTestServer(t, d, nil), "POST", "/v1/rules/explain", `{"type":"send","account_id":"a"}`)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"code":"not_configured"`) {
		t.Errorf("a decider that cannot explain: %d %s", rec.Code, rec.Body)
	}
}
