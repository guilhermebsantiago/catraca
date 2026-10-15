package decision

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
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

func TestRetryAfterIsSecondsInJSON(t *testing.T) {
	d := Decision{
		ID: "d1", Action: Throttle, RetryAfter: 1500 * time.Millisecond,
		Matches: []Match{{RuleID: "r", Reason: "x", Action: Throttle, Mode: Enforce, RetryAfter: time.Minute}},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"retry_after":2`) || !strings.Contains(s, `"retry_after":60`) {
		t.Fatalf("retry_after not in seconds: %s", s)
	}
	var back Decision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.RetryAfter != 2*time.Second || back.Matches[0].RetryAfter != time.Minute || back.ID != "d1" || back.Matches[0].RuleID != "r" {
		t.Fatalf("round trip lost data: %+v", back)
	}
	allow, _ := json.Marshal(Decision{ID: "d2", Action: Allow})
	if strings.Contains(string(allow), "retry_after") {
		t.Fatalf("allow decision carries retry_after: %s", allow)
	}
}

func TestRetrySeconds(t *testing.T) {
	for _, tt := range []struct {
		in   time.Duration
		want int64
	}{{0, 0}, {-time.Second, 0}, {time.Nanosecond, 1}, {time.Second, 1}, {1001 * time.Millisecond, 2}, {time.Minute, 60}} {
		if got := RetrySeconds(tt.in); got != tt.want {
			t.Errorf("RetrySeconds(%s) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
