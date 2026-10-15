package rules

import (
	"strings"
	"testing"
)

func TestLint(t *testing.T) {
	rs := mustParse(t, `version: 1
lists:
  used: [a.com, b.com, a.com]
  unused: [x]
  empty: []
rules:
  - id: enforced-no-on-error
    when: in_list("used", event.from_domain)
    mode: enforce
    reason: r
  - id: shadow-with-effects
    when: event.type == "send"
    effects: [notify]
    override: {by: a, reason: b, at: 2026-01-01}
    reason: r
  - id: constant
    when: "true"
    reason: r
  - id: typo
    when: account.send_1m > 10 && key.leaked && event.attributes.plan == "x"
    reason: r
  - id: closed-unguarded
    when: event.type == "send" && key.leaked && ip.sends_1m > 1 && domain.complaints_24h > 1
    on_error: closed
    reason: r
  - id: closed-guarded
    when: event.type == "send" && event.api_key_id != "" && key.leaked
    on_error: closed
    reason: r
`)
	got := rs.Lint()
	want := []string{
		`line 3: list used: "a.com" is listed twice`,
		`line 4: list unused: not used by any rule`,
		`line 5: list empty: not used by any rule`,
		`line 5: list empty: the list is empty`,
		`line 7: rule enforced-no-on-error: enforced rule inherits on_error "open" from defaults`,
		`line 11: rule shadow-with-effects: effects notify never run while the rule is in shadow mode`,
		`line 11: rule shadow-with-effects: override has no effect on a shadow rule`,
		`line 16: rule constant: when is a constant`,
		`line 19: rule typo: reads account.send_1m, which is not a known signal: it is always absent, so the rule always fails to evaluate (did you mean sends_1m?)`,
		`line 22: rule closed-unguarded: fails closed and reads key signals without checking event.api_key_id`,
		`line 22: rule closed-unguarded: fails closed and reads ip signals without checking event.ip`,
		`line 22: rule closed-unguarded: fails closed and reads domain signals without checking event.from_domain`,
	}
	if len(got) != len(want) {
		var lines []string
		for _, w := range got {
			lines = append(lines, w.String())
		}
		t.Fatalf("got %d warnings, want %d:\n%s", len(got), len(want), strings.Join(lines, "\n"))
	}
	for i := range want {
		if !strings.HasPrefix(got[i].String(), want[i]) {
			t.Errorf("warning %d:\n got  %s\n want %s...", i, got[i], want[i])
		}
	}
}

func TestLintEmptyRuleset(t *testing.T) {
	got := mustParse(t, "version: 1\nrules: []\n").Lint()
	if len(got) != 1 || !strings.Contains(got[0].Msg, "no rules") {
		t.Errorf("warnings = %v, want one about having no rules", got)
	}
}

func TestLintClean(t *testing.T) {
	rs := mustParse(t, `version: 1
lists:
  shorteners: [bit.ly]
rules:
  - id: shortener
    when: event.type == "send" && any_in_list("shorteners", event.link_domains) && account.age_hours < 72
    reason: r
  - id: enforced
    when: event.type == "send" && account.sends_1m > 100
    mode: enforce
    on_error: open
    effects: [notify]
    action: throttle
    retry_after: 1m
    reason: r
`)
	if got := rs.Lint(); len(got) != 0 {
		t.Errorf("warnings = %v, want none", got)
	}
}
