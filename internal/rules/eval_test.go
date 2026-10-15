package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// evalOne compiles a single rule with when and evaluates it against set.
func evalOne(t *testing.T, when string, set signal.Set) Result {
	t.Helper()
	src := fmt.Sprintf("version: 1\nlists:\n  shorteners: [bit.ly, t.co]\n  empty: []\nrules:\n  - id: r\n    when: %q\n    reason: r\n", when)
	rs := mustParse(t, src)
	return rs.Evaluate(set)[0]
}

func TestEvaluateExpressions(t *testing.T) {
	set := signal.Set{
		Event: map[string]any{
			"type":         "send",
			"from_domain":  "example.com",
			"to_domains":   []string{"gmail.com", "yahoo.com"},
			"link_domains": []string{"example.com", "t.co"},
			"recipients":   int64(2),
			"attributes":   map[string]string{"plan": "free"},
		},
		Account: map[string]any{
			"sends_1m":           int64(150),
			"sends_24h":          int64(4000),
			"complaints_24h":     int64(20),
			"age_hours":          float64(2.5),
			"complaint_rate_24h": 0.005,
			"new_ip":             true,
		},
		Key: map[string]any{"leaked": false},
	}
	tests := []struct {
		when string
		want bool
	}{
		{`event.type == "send"`, true},
		{`event.type == "feedback"`, false},
		// Ints and doubles compare without casts.
		{`account.age_hours < 24`, true},
		{`account.sends_1m > 100.5`, true},
		{`account.complaint_rate_24h > 0.003`, true},
		{`account.new_ip && !key.leaked`, true},
		{`key.leaked`, false},
		{`in_list("shorteners", "bit.ly")`, true},
		{`in_list("shorteners", event.from_domain)`, false},
		{`in_list("empty", "bit.ly")`, false},
		{`any_in_list("shorteners", event.link_domains)`, true},
		{`any_in_list("shorteners", event.to_domains)`, false},
		{`any_in_list("shorteners", [])`, false},
		{`domain_of("Alice <Alice@Example.COM>") == "example.com"`, true},
		{`domain_of("not an address") == ""`, true},
		{`ratio(account.complaints_24h, account.sends_24h) == 0.005`, true},
		{`ratio(3, 0) == 3.0`, true},
		{`ratio(1.5, 0.5) == 1.5`, true},
		{`event.to_domains.exists(d, d.endsWith("yahoo.com"))`, true},
		{`size(event.to_domains) == event.recipients`, true},
		{`event.attributes.plan == "free"`, true},
		{`has(account.sends_7d)`, false},
		{`account.?sends_7d.orValue(0) == 0`, true},
		{`event.attributes.?tier.orValue("none") == "none"`, true},
		// && and || absorb an error when the other side decides the result,
		// so a guard on the event short-circuits a missing signal.
		{`event.type == "feedback" && account.sends_7d > 1`, false},
		{`event.type == "send" || account.sends_7d > 1`, true},
	}
	for _, tt := range tests {
		t.Run(tt.when, func(t *testing.T) {
			res := evalOne(t, tt.when, set)
			if res.Err != nil {
				t.Fatalf("error: %v", res.Err)
			}
			if res.Matched != tt.want {
				t.Errorf("matched = %v, want %v", res.Matched, tt.want)
			}
		})
	}
}

func TestEvaluateErrors(t *testing.T) {
	set := signal.Set{
		Event:   map[string]any{"type": "send", "link_domains": []string{"a.com"}, "recipients": int64(1)},
		Account: map[string]any{"sends_1m": int64(5), "name": "acme"},
	}
	tests := []struct {
		name, when, want string
	}{
		{"absent signal", `event.type == "send" && account.sends_7d > 10`, "signal account.sends_7d is absent"},
		{"absent map", `key.leaked`, "signal key.leaked is absent"},
		{"absent map with a guard that passes", `event.type == "send" && key.leaked`, "signal key.leaked is absent"},
		{"index syntax", `account["sends_7d"] > 1`, "signal account.sends_7d is absent"},
		{"non-bool result", `account.sends_1m`, "when returned int, not bool"},
		{"wrong type in in_list", `in_list("shorteners", event.recipients)`, "value must be a string"},
		{"wrong type in ratio", `ratio(account.name, 1) > 0.5`, "ratio: want a number, not string"},
		{"wrong item type in any_in_list", `any_in_list("shorteners", [1, 2])`, "list items must be strings"},
		{"cost limit", `[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, [1,2,3,4,5,6,7,8,9,10].all(d, a+b+c+d > 0))))`, "cost limit exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := evalOne(t, tt.when, set)
			if res.Err == nil {
				t.Fatalf("no error, matched = %v", res.Matched)
			}
			if res.Matched {
				t.Error("an errored rule reports Matched")
			}
			if !strings.Contains(res.Err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", res.Err, tt.want)
			}
		})
	}
}

func TestEvaluateEmptySet(t *testing.T) {
	res := evalOne(t, `event.type == "send"`, signal.Set{})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "signal event.type is absent") {
		t.Errorf("error = %v, want event.type to be absent", res.Err)
	}
}

const combineRuleset = `version: 1
rules:
  - id: flag-enforced
    when: account.flag
    action: flag
    mode: enforce
    on_error: open
    reason: flagged
  - id: throttle-short
    when: account.throttle
    action: throttle
    retry_after: 30s
    mode: enforce
    on_error: open
    reason: slow down
  - id: throttle-long
    when: account.throttle
    action: throttle
    retry_after: 5m
    mode: enforce
    on_error: open
    reason: slow down a lot
  - id: throttle-shadow
    when: account.throttle
    action: throttle
    retry_after: 1h
    reason: would slow down
  - id: hold-enforced
    when: account.hold
    action: hold
    mode: enforce
    on_error: open
    reason: held
  - id: block-shadow
    when: account.block
    action: block
    effects: [notify]
    reason: would block
  - id: closed-enforced
    when: account.closed
    action: block
    mode: enforce
    on_error: closed
    effects: [revoke_key, notify]
    reason: blocked
  - id: closed-shadow
    when: account.closed
    action: hold
    on_error: closed
    reason: would hold
`

func TestApply(t *testing.T) {
	rs := mustParse(t, combineRuleset)
	signals := func(kv ...any) signal.Set {
		m := map[string]any{"flag": false, "throttle": false, "hold": false, "block": false, "closed": false}
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(m, kv[i].(string))
				continue
			}
			m[kv[i].(string)] = kv[i+1]
		}
		return signal.Set{Account: m}
	}
	tests := []struct {
		name       string
		set        signal.Set
		action     decision.Action
		retryAfter time.Duration
		enforced   []string
		shadow     []string
		errors     []string
		errored    []string
	}{
		{name: "nothing matches", set: signals(), action: decision.Allow},
		{name: "flag", set: signals("flag", true), action: decision.Flag, enforced: []string{"flag-enforced"}},
		{
			name: "throttle takes the largest enforced retry_after", set: signals("throttle", true),
			action: decision.Throttle, retryAfter: 5 * time.Minute,
			enforced: []string{"throttle-short", "throttle-long"}, shadow: []string{"throttle-shadow"},
		},
		{
			name: "hold outranks throttle and drops retry_after", set: signals("throttle", true, "hold", true, "flag", true),
			action:   decision.Hold,
			enforced: []string{"flag-enforced", "throttle-short", "throttle-long", "hold-enforced"}, shadow: []string{"throttle-shadow"},
		},
		{name: "shadow rules never change the action", set: signals("block", true), action: decision.Allow, shadow: []string{"block-shadow"}},
		{
			name: "fail open skips the rule", set: signals("hold", nil),
			action: decision.Allow, errors: []string{"hold-enforced"},
		},
		{
			name: "fail closed matches the rule in both modes", set: signals("closed", nil),
			action: decision.Block, enforced: []string{"closed-enforced"}, shadow: []string{"closed-shadow"},
			errors: []string{"closed-enforced", "closed-shadow"}, errored: []string{"closed-enforced", "closed-shadow"},
		},
		{
			name: "a closed rule that evaluates is not errored", set: signals("closed", true),
			action: decision.Block, enforced: []string{"closed-enforced"}, shadow: []string{"closed-shadow"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := rs.Apply(tt.set)
			if out.Action != tt.action {
				t.Errorf("action = %s, want %s", out.Action, tt.action)
			}
			if out.RetryAfter != tt.retryAfter {
				t.Errorf("retry_after = %s, want %s", out.RetryAfter, tt.retryAfter)
			}
			assertIDs(t, "enforced", matchIDs(out.Matches), tt.enforced)
			assertIDs(t, "shadow", matchIDs(out.Shadow), tt.shadow)
			var errIDs, erroredIDs []string
			for _, e := range out.Errors {
				errIDs = append(errIDs, e.RuleID)
			}
			for _, m := range append(out.Matches, out.Shadow...) {
				if m.Errored {
					erroredIDs = append(erroredIDs, m.RuleID)
				}
			}
			assertIDs(t, "errors", errIDs, tt.errors)
			assertIDs(t, "errored", erroredIDs, tt.errored)
			for _, m := range out.Matches {
				if m.Mode != decision.Enforce {
					t.Errorf("enforced match %s has mode %s", m.RuleID, m.Mode)
				}
			}
			for _, m := range out.Shadow {
				if m.Mode != decision.Shadow {
					t.Errorf("shadow match %s has mode %s", m.RuleID, m.Mode)
				}
			}
		})
	}
}

func TestApplyMatchCarriesRule(t *testing.T) {
	rs := mustParse(t, combineRuleset)
	out := rs.Apply(signal.Set{Account: map[string]any{"flag": false, "throttle": true, "hold": false, "block": false, "closed": true}})
	m := out.Matches[2]
	if m.RuleID != "closed-enforced" || m.Reason != "blocked" || m.Action != decision.Block || len(m.Effects) != 2 {
		t.Errorf("match = %+v", m)
	}
	if out.Matches[1].RetryAfter != 5*time.Minute {
		t.Errorf("throttle-long match retry_after = %s", out.Matches[1].RetryAfter)
	}
	// Matches get their own copy of the effects: a consumer that edits a
	// decision must not change the ruleset.
	m.Effects[0] = "changed"
	r, _ := rs.Rule("closed-enforced")
	if r.Effects[0] != "revoke_key" {
		t.Error("editing a match changed the rule's effects")
	}
}

func assertIDs(t *testing.T, field string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}
