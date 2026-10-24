package app_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/app"
	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// gateConfig sets a gate a test can pass with two labels.
func gateConfig(yaml string) string {
	return strings.Replace(yaml, "gate:\n", "gate:\n  min_labeled: 2\n  min_precision: 0.3\n", 1)
}

type readyRuleset struct {
	Ruleset api.RulesetStatus `json:"ruleset"`
}

func (h *harness) rulesetStatus() api.RulesetStatus {
	h.t.Helper()
	var out readyRuleset
	h.do("GET", "/readyz?verbose", "", nil).json(h.t, &out)
	return out.Ruleset
}

// TestGateOnLoadThroughTheServer checks gate.on_load: enforce end to end:
// the enforced rules without labels are held in shadow mode at start,
// /readyz?verbose, the metrics and the reload answer say so, decisions
// carry the version of the ruleset they were made with, and a rule enforces
// once labels prove it and the ruleset is reloaded.
func TestGateOnLoadThroughTheServer(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{gate: "enforce", edit: gateConfig})

	st := h.rulesetStatus()
	if st.Gate != "enforce" || st.Source != "start" || st.FileVersion == "" || st.Version == st.FileVersion || len(st.Held) != 5 {
		t.Fatalf("ruleset status %+v, want the five enforced rules held", st)
	}
	for _, held := range st.Held {
		if held.Status != "insufficient_labels" {
			t.Errorf("held %+v, want insufficient_labels", held)
		}
	}
	m := h.metrics()
	for _, want := range []string{
		`catraca_ruleset_gate_failures{status="insufficient_labels"} 5`,
		`catraca_ruleset_gate_failures{status="unavailable"} 0`,
		`catraca_ruleset_loaded_timestamp_seconds{source="start"}`,
		`catraca_ruleset_rules{mode="enforce"} 0`,
		`catraca_ruleset_info{version="` + st.Version + `"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}

	// Held, blocked-sender matches in shadow mode, and the decisions say
	// which ruleset they were made with.
	var ids []string
	for i := range 2 {
		d, _ := h.decide(send(fmt.Sprintf("acct_spam_%d", i), "win@spam.example"))
		if d.Action != decision.Allow || len(d.Shadow) == 0 || d.Shadow[0].RuleID != "blocked-sender" || d.RulesetVersion != st.Version {
			t.Fatalf("decision while held: %+v", d)
		}
		ids = append(ids, d.ID)
	}
	for _, id := range ids {
		r := h.do("POST", "/v1/decisions/"+id+"/labels", token, audit.Label{RuleID: "blocked-sender", Verdict: audit.TruePositive, By: "reviewer"})
		if r.status != http.StatusCreated {
			t.Fatalf("label: %d %s", r.status, r.body)
		}
	}

	r := h.do("POST", "/v1/rules/reload", token, nil)
	if r.status != http.StatusOK {
		t.Fatalf("reload: %d %s", r.status, r.body)
	}
	var rel api.ReloadResponse
	r.json(t, &rel)
	if len(rel.Held) != 4 || !rel.Changed || rel.PreviousVersion != st.Version {
		t.Errorf("reload = %+v, want blocked-sender released and four held", rel)
	}
	for _, held := range rel.Held {
		if held.Rule == "blocked-sender" {
			t.Errorf("blocked-sender still held: %+v", rel.Held)
		}
	}
	if d, _ := h.decide(send("acct_spam_9", "win@spam.example")); d.Action != decision.Block || d.RulesetVersion != rel.Version {
		t.Errorf("decision once proven: %+v", d)
	}
	if st := h.rulesetStatus(); st.Source != "api" || st.Version != rel.Version {
		t.Errorf("status after the reload: %+v", st)
	}
}

// TestWatchLoadsTheEditedFile checks that the server's watch loads an
// edited ruleset file by itself, and says so.
func TestWatchLoadsTheEditedFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{})
	before := h.rulesetStatus()

	h.writeRules(strings.Replace(testRules, `event.from_domain == "spam.example"`, `event.from_domain == "junk.example"`, 1))
	now := time.Now()
	app.CheckRules(h.app, now)
	app.CheckRules(h.app, now.Add(time.Minute))

	st := h.rulesetStatus()
	if st.Source != "watch" || st.Version == before.Version || st.Version != h.app.Ruleset().Version() {
		t.Errorf("status %+v after an edit, want a new version from the watch (was %s)", st, before.Version)
	}
	if d, _ := h.decide(send("acct", "win@spam.example")); d.Action != decision.Allow {
		t.Errorf("decision after the edit: %+v", d)
	}
	var raw map[string]json.RawMessage
	h.do("GET", "/readyz", "", nil).json(t, &raw)
	if _, ok := raw["ruleset"]; ok {
		t.Error("/readyz without verbose shows the ruleset")
	}
}
