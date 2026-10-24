package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/rules"
)

const heldRules = `version: 1
rules:
  - id: burst
    when: account.sends_1m > 10
    reason: r
`

func TestReadyzVerboseRuleset(t *testing.T) {
	loaded := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, deciderFunc(nil), nil, func(o *Options) {
		o.Ruleset = func() RulesetStatus {
			return RulesetStatus{Version: "5b1e0c7d9a42", FileVersion: "098086f42c27", Path: "/etc/catraca/rules.yaml", Source: "watch",
				LoadedAt: loaded, Gate: "enforce", Held: []GateHold{{Rule: "burst", Status: "insufficient_labels"}}}
		}
	})
	if rec := serve(s, "GET", "/readyz", ""); strings.Contains(rec.Body.String(), "ruleset") {
		t.Errorf("readyz without verbose: %s", rec.Body)
	}
	rec := serve(s, "GET", "/readyz?verbose", "")
	want := `{"status":"ready","checks":{},"ruleset":{"version":"5b1e0c7d9a42","file_version":"098086f42c27","path":"/etc/catraca/rules.yaml",` +
		`"source":"watch","loaded_at":"2026-10-23T12:00:00Z","gate":"enforce","held":[{"rule":"burst","status":"insufficient_labels"}]}}`
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want {
		t.Errorf("readyz?verbose: %d %s\nwant %s", rec.Code, rec.Body, want)
	}
}

// TestReloadSaysWhatIsHeld checks that a reload answers with the rules the
// precision gate held back, as the ruleset status has them after it.
func TestReloadSaysWhatIsHeld(t *testing.T) {
	rs, err := rules.Parse([]byte(heldRules))
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, deciderFunc(nil), nil, func(o *Options) {
		o.Reload = func() (*rules.Ruleset, error) { return rs, nil }
		o.Ruleset = func() RulesetStatus {
			return RulesetStatus{Version: rs.Version(), Gate: "warn", Ungated: []GateHold{{Rule: "burst", Status: "below_precision"}}}
		}
	})
	rec := serve(s, "POST", "/v1/rules/reload", "")
	var got ReloadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 {
		t.Fatalf("reload: %d %s (%v)", rec.Code, rec.Body, err)
	}
	if len(got.Held) != 0 || len(got.Ungated) != 1 || got.Ungated[0] != (GateHold{Rule: "burst", Status: "below_precision"}) {
		t.Errorf("reload = %+v", got)
	}
}
