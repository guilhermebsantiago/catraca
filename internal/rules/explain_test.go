package rules

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

const explainTestRules = `version: 1
rules:
  - id: burst
    when: account.sends_1m > 10
    action: throttle
    retry_after: 90s
    mode: enforce
    on_error: open
    reason: burst
  - id: young
    when: account.age_hours < 24
    action: hold
    mode: shadow
    on_error: closed
    reason: young
  - id: leaked
    when: key.leaked
    action: block
    mode: enforce
    on_error: open
    reason: leaked
`

func TestExplain(t *testing.T) {
	rs, err := Parse([]byte(explainTestRules))
	if err != nil {
		t.Fatal(err)
	}
	set := signal.Set{Event: map[string]any{"type": "send"}, Account: map[string]any{"sends_1m": int64(11)}}
	x := rs.Explain(set)
	want := []RuleExplanation{
		{ID: "burst", Matched: true, Action: decision.Throttle, Mode: decision.Enforce, OnError: decision.FailOpen},
		{ID: "young", Matched: true, Action: decision.Hold, Mode: decision.Shadow, OnError: decision.FailClosed, Error: "signal account.age_hours is absent"},
		{ID: "leaked", Action: decision.Block, Mode: decision.Enforce, OnError: decision.FailOpen, Error: "signal key.leaked is absent"},
	}
	if len(x.Rules) != len(want) {
		t.Fatalf("rules = %+v", x.Rules)
	}
	for i := range want {
		if x.Rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, x.Rules[i], want[i])
		}
	}
	// The outcome is Apply's.
	out := rs.Apply(set)
	if x.Action != out.Action || x.RetryAfter != 90 || x.RulesetVersion != rs.Version() {
		t.Errorf("action %s retry_after %d version %q, want %s 90 %q", x.Action, x.RetryAfter, x.RulesetVersion, out.Action, rs.Version())
	}

	// An explanation's JSON reads back as the same signals.
	data, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSignals(data)
	if err != nil {
		t.Fatal(err)
	}
	if again := rs.Explain(back); again.Action != x.Action || back.Account["sends_1m"] != int64(11) || back.Key != nil {
		t.Errorf("read back: %+v, action %s", back, again.Action)
	}
}

func TestParseSignals(t *testing.T) {
	set, err := ParseSignals([]byte("event: {type: send, recipients: 3}\naccount: {bounce_rate_24h: 1, new_ip: true}\nkey: null\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Types follow the catalog: an integer written for a double is a double.
	if set.Event["recipients"] != int64(3) || set.Account["bounce_rate_24h"] != 1.0 || set.Account["new_ip"] != true || set.Key != nil {
		t.Errorf("set = %+v", set)
	}
	for _, bad := range []string{"", "account: {sends_1m: lots}", "nope: {}", "[1, 2]"} {
		var list ErrorList
		if _, err := ParseSignals([]byte(bad)); !errors.As(err, &list) {
			t.Errorf("%q: err = %v, want an ErrorList", bad, err)
		}
	}
}
