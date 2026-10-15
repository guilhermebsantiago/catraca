package decision

import (
	"slices"
	"testing"
)

func TestEffects(t *testing.T) {
	d := Decision{
		Matches: []Match{
			{RuleID: "a", Mode: Enforce, Effects: []string{"revoke_key", "notify"}},
			{RuleID: "b", Mode: Enforce, Effects: []string{"notify", "suspend_account"}},
			{RuleID: "c", Mode: Enforce, Effects: []string{"page_oncall"}, Errored: true},
		},
		Shadow: []Match{{RuleID: "d", Mode: Shadow, Effects: []string{"delete_account"}}},
	}
	want := []string{"revoke_key", "notify", "suspend_account"}
	if got := d.Effects(); !slices.Equal(got, want) {
		t.Errorf("Effects() = %v, want %v: deduplicated, without shadow or errored matches", got, want)
	}
	if got := (Decision{}).Effects(); len(got) != 0 {
		t.Errorf("Effects() of an empty decision = %v", got)
	}
}
