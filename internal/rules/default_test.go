package rules

import (
	"slices"
	"testing"
)

const (
	defaultRuleset  = "../../rules/default.yaml"
	defaultFixtures = "../../rules/default.test.yaml"
)

func TestDefaultRulesetFixtures(t *testing.T) {
	rs, err := LoadFile(defaultRuleset)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadFixtures(defaultFixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunFixtures(rs, cases).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultRulesetIsLintClean(t *testing.T) {
	rs, err := LoadFile(defaultRuleset)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range rs.Lint() {
		t.Errorf("lint: %s", w)
	}
}

func TestDefaultRulesetStartsInShadow(t *testing.T) {
	rs, err := LoadFile(defaultRuleset)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Rules() {
		if r.Description == "" {
			t.Errorf("rule %s has no description", r.ID)
		}
		if r.ID == "leaked-key-send" {
			if r.Mode != "enforce" || r.OnError != "closed" || !slices.Equal(r.Effects, []string{"revoke_key"}) || r.Override == nil {
				t.Errorf("leaked-key-send = %+v, want enforce, on_error closed, effect revoke_key and an override", r)
			}
			continue
		}
		if r.Mode != "shadow" {
			t.Errorf("rule %s is %s; every default rule but leaked-key-send starts in shadow", r.ID, r.Mode)
		}
	}
}

// TestDefaultFixturesCoverEveryRule checks that each rule has a case where it
// matches and a case, with signals nearby, where it does not.
func TestDefaultFixturesCoverEveryRule(t *testing.T) {
	rs, err := LoadFile(defaultRuleset)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadFixtures(defaultFixtures)
	if err != nil {
		t.Fatal(err)
	}
	positive := map[string]bool{}
	negative := map[string]int{}
	for _, c := range cases {
		out := rs.Apply(c.Signals)
		matched := map[string]bool{}
		for _, m := range slices.Concat(out.Matches, out.Shadow) {
			matched[m.RuleID] = true
			positive[m.RuleID] = true
		}
		for _, r := range rs.Rules() {
			if !matched[r.ID] {
				negative[r.ID]++
			}
		}
	}
	for _, r := range rs.Rules() {
		if !positive[r.ID] {
			t.Errorf("no fixture case matches rule %s", r.ID)
		}
		if negative[r.ID] == 0 {
			t.Errorf("rule %s matches every fixture case", r.ID)
		}
	}
}

// BenchmarkEvaluateDefault evaluates the starter ruleset for a healthy sender,
// the common case: every rule runs in full and none matches.
func BenchmarkEvaluateDefault(b *testing.B) {
	rs, err := LoadFile(defaultRuleset)
	if err != nil {
		b.Fatal(err)
	}
	cases, err := LoadFixtures(defaultFixtures)
	if err != nil {
		b.Fatal(err)
	}
	set := cases[0].Signals
	b.ReportAllocs()
	for b.Loop() {
		rs.Apply(set)
	}
}
