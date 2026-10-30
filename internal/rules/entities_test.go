package rules

import (
	"strings"
	"testing"
)

const entityRuleset = `version: 1
rules:
  - id: template-reuse
    when: >
      event.type == "send" && "content" in entity &&
      entity.content.distinct_accounts_24h >= 5 && account.age_hours < 72.0
    action: hold
    mode: enforce
    on_error: open
    reason: r
  - id: parent-index
    when: entity["parent"]["sends_24h"] > 100
    action: flag
    mode: enforce
    on_error: open
    reason: r
  - id: typo
    when: entity.content.distinct_account_24h > 1
    reason: r
  - id: undeclared
    when: entity.device.sends_1h > 1 || entity.contnt.sends_1h > 1
    reason: r
`

func TestLintEntitySignals(t *testing.T) {
	rs := mustParse(t, entityRuleset)
	var got []string
	for _, w := range rs.Lint() {
		got = append(got, w.String())
	}
	want := `line 17: rule typo: reads entity.content.distinct_account_24h, which is not an entity signal: it is always absent, so the rule always fails to evaluate (did you mean distinct_accounts_24h?)`
	found := false
	for _, g := range got {
		if strings.HasPrefix(g, "line 17:") {
			found = g == want
		}
		if strings.Contains(g, "template-reuse") || strings.Contains(g, "parent-index") {
			t.Errorf("unexpected warning %q", g)
		}
	}
	if !found {
		t.Errorf("Lint() = %q, want %q", got, want)
	}
}

func TestLintEntities(t *testing.T) {
	rs := mustParse(t, entityRuleset)
	var got []string
	for _, w := range rs.LintEntities([]string{"content", "parent"}) {
		got = append(got, w.String())
	}
	want := []string{
		`line 20: rule undeclared: reads entity.device, but engine.entities declares no entity device: it is always absent, so the rule always fails to evaluate`,
		`line 20: rule undeclared: reads entity.contnt, but engine.entities declares no entity contnt: it is always absent, so the rule always fails to evaluate (did you mean content?)`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("LintEntities() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if n := len(rs.LintEntities(nil)); n != 5 {
		t.Errorf("LintEntities(nil) has %d warnings, want 5: every entity read", n)
	}
}

func TestEntityFixtures(t *testing.T) {
	rs := mustParse(t, entityRuleset)
	cases, err := ParseFixtures([]byte(`base:
  event: {type: send}
  account: {age_hours: 2}
cases:
  - name: shared template on new accounts
    signals:
      entity: {content: {distinct_accounts_24h: 6, sends_1h: 6, sends_24h: 6, distinct_accounts_7d: 6}}
    expect: {action: hold, matches: [template-reuse]}
  - name: few accounts
    signals:
      entity: {content: {distinct_accounts_24h: 2}}
    expect: {action: allow}
  - name: no content hash
    expect: {action: allow}
  - name: parent volume
    signals:
      entity: {parent: {sends_24h: 101}}
    expect: {action: flag, matches: [parent-index]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := RunFixtures(rs, cases).Err(); err != nil {
		t.Error(err)
	}
}
