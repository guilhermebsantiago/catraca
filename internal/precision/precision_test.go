package precision

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

func TestWilson(t *testing.T) {
	// Reference values computed independently with the closed-form Wilson
	// score interval at z = 1.959964.
	tests := []struct {
		successes, trials int
		lower, upper      float64
	}{
		{0, 0, 0, 1},
		{0, 5, 0, 0.434482},
		{0, 10, 0, 0.277533},
		{1, 1, 0.206549, 1},
		{1, 2, 0.094531, 0.905469},
		{5, 10, 0.236593, 0.763407},
		{9, 10, 0.595850, 0.982124},
		{10, 10, 0.722467, 1},
		{29, 30, 0.833296, 0.994091},
		{30, 30, 0.886487, 1},
		{34, 34, 0.898485, 1},
		{35, 35, 0.901099, 1},
		{45, 50, 0.786398, 0.956524},
		{81, 263, 0.255289, 0.366210},
		{95, 100, 0.888250, 0.978456},
		{96, 100, 0.901629, 0.984337},
		{97, 100, 0.915481, 0.989745},
	}
	for _, tt := range tests {
		lower, upper := Wilson(tt.successes, tt.trials)
		if math.Abs(lower-tt.lower) > 1e-6 || math.Abs(upper-tt.upper) > 1e-6 {
			t.Errorf("Wilson(%d, %d) = [%.6f, %.6f], want [%.6f, %.6f]",
				tt.successes, tt.trials, lower, upper, tt.lower, tt.upper)
		}
	}
}

func TestWilsonClampsBadInput(t *testing.T) {
	if lo, hi := Wilson(-3, 10); lo != 0 || math.Abs(hi-0.277533) > 1e-6 {
		t.Errorf("negative successes: got [%f, %f]", lo, hi)
	}
	if lo, hi := Wilson(12, 10); math.Abs(lo-0.722467) > 1e-6 || hi != 1 {
		t.Errorf("successes > trials: got [%f, %f]", lo, hi)
	}
}

func TestGateEvaluate(t *testing.T) {
	tests := []struct {
		name   string
		gate   Gate
		tp, fp int
		want   Status
	}{
		{"no labels", Gate{}, 0, 0, InsufficientLabels},
		{"few labels, all true", Gate{}, 20, 0, InsufficientLabels},
		{"few labels, clearly bad", Gate{}, 0, 5, BelowPrecision},
		{"few labels, upper bound above gate", Gate{}, 4, 1, InsufficientLabels},
		{"30 of 30 is not enough at 0.9", Gate{}, 30, 0, BelowPrecision},
		{"35 of 35 passes", Gate{}, 35, 0, Passes},
		{"96 of 100 passes", Gate{}, 96, 4, Passes},
		{"95 of 100 does not", Gate{}, 95, 5, BelowPrecision},
		{"custom gate passes", Gate{MinLabeled: 10, MinPrecision: 0.7}, 10, 0, Passes},
		{"custom gate needs labels", Gate{MinLabeled: 50, MinPrecision: 0.5}, 40, 0, InsufficientLabels},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := RuleStats{RuleID: "r", Mode: decision.Shadow, Matches: tt.tp + tt.fp + 7,
				Labeled: tt.tp + tt.fp, TruePositives: tt.tp, FalsePositives: tt.fp}
			got := tt.gate.Evaluate(s)
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (lower %.4f, upper %.4f)", got.Status, tt.want, got.Lower, got.Upper)
			}
			if got.Matches != s.Matches || got.Labeled != s.Labeled {
				t.Errorf("counts not carried over: %+v", got)
			}
		})
	}
}

func TestGateValidate(t *testing.T) {
	if err := DefaultGate().Validate(); err != nil {
		t.Errorf("default gate: %v", err)
	}
	for _, g := range []Gate{{MinLabeled: -1}, {MinPrecision: 1.5}, {MinPrecision: -0.1}} {
		if err := g.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error", g)
		}
	}
}

func TestEvaluateRulesAddsModes(t *testing.T) {
	stats := []RuleStats{
		{RuleID: "burst", Mode: decision.Shadow, Matches: 50, Labeled: 30, TruePositives: 30},
		{RuleID: "burst", Mode: decision.Enforce, Matches: 20, Errored: 1, Labeled: 10, TruePositives: 10},
		{RuleID: "removed", Mode: decision.Enforce, Matches: 9, Labeled: 9, FalsePositives: 9},
	}
	rules := []RuleInfo{{ID: "burst", Mode: decision.Enforce}, {ID: "silent", Mode: decision.Shadow}}
	got := Gate{}.EvaluateRules(rules, stats)
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	b := got[0]
	if b.RuleID != "burst" || b.Mode != decision.Enforce || b.Matches != 70 || b.Errored != 1 ||
		b.Labeled != 40 || b.TruePositives != 40 || b.Status != Passes {
		t.Errorf("burst = %+v", b)
	}
	s := got[1]
	if s.RuleID != "silent" || s.Matches != 0 || s.Status != InsufficientLabels || s.Lower != 0 || s.Upper != 1 {
		t.Errorf("silent = %+v", s)
	}
}

func TestCheckRuleset(t *testing.T) {
	stats := []RuleStats{
		{RuleID: "good", Mode: decision.Enforce, Matches: 100, Labeled: 40, TruePositives: 40},
		{RuleID: "bad", Mode: decision.Enforce, Matches: 100, Labeled: 40, TruePositives: 30, FalsePositives: 10},
		{RuleID: "bad-kept", Mode: decision.Enforce, Matches: 100, Labeled: 40, TruePositives: 30, FalsePositives: 10},
		{RuleID: "shadow-bad", Mode: decision.Shadow, Matches: 100, Labeled: 40, FalsePositives: 40},
	}
	rules := []RuleInfo{
		{ID: "good", Mode: decision.Enforce},
		{ID: "bad", Mode: decision.Enforce},
		{ID: "bad-kept", Mode: decision.Enforce, HasOverride: true},
		{ID: "new", Mode: decision.Enforce},
		{ID: "shadow-bad", Mode: decision.Shadow},
	}
	results, err := Gate{}.CheckRuleset(rules, stats)
	if len(results) != 4 {
		t.Errorf("got %d results, want one per enforced rule (4)", len(results))
	}
	var gerr *GateError
	if !errors.As(err, &gerr) {
		t.Fatalf("err = %v, want *GateError", err)
	}
	var failed []string
	for _, r := range gerr.Failed {
		failed = append(failed, r.RuleID)
	}
	if strings.Join(failed, ",") != "bad,new" {
		t.Errorf("failed = %v, want [bad new]", failed)
	}
	msg := err.Error()
	for _, want := range []string{"2 enforced rule(s)", "bad: below_precision", "new: insufficient_labels, no labeled matches"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}

	if _, err := (Gate{}).CheckRuleset(rules[:1], stats); err != nil {
		t.Errorf("only passing rules: err = %v", err)
	}
}

func TestReport(t *testing.T) {
	stats := []RuleStats{
		{RuleID: "promote-me", Mode: decision.Shadow, Matches: 200, Labeled: 100, TruePositives: 98, FalsePositives: 2},
		{RuleID: "retire-me", Mode: decision.Enforce, Matches: 80, Labeled: 50, TruePositives: 35, FalsePositives: 15},
		{RuleID: "fine", Mode: decision.Enforce, Matches: 80, Labeled: 50, TruePositives: 50},
	}
	rules := []RuleInfo{
		{ID: "promote-me", Mode: decision.Shadow},
		{ID: "retire-me", Mode: decision.Enforce, HasOverride: true},
		{ID: "fine", Mode: decision.Enforce},
		{ID: "unlabeled", Mode: decision.Shadow},
	}
	r := NewReport(Gate{}, rules, stats)
	if r.Gate != DefaultGate() {
		t.Errorf("gate = %+v, want defaults", r.Gate)
	}
	if len(r.Promote) != 1 || r.Promote[0].RuleID != "promote-me" {
		t.Errorf("promote = %+v", r.Promote)
	}
	if len(r.Retire) != 1 || r.Retire[0].RuleID != "retire-me" {
		t.Errorf("retire = %+v", r.Retire)
	}

	var text bytes.Buffer
	if err := r.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	for _, want := range []string{
		"RULE", "95% CI", "promote-me", "0.980", "[0.930, 0.994]",
		"below_precision (override)", "unlabeled", "Promote candidates", "Retire candidates",
		"retire-me: precision 0.700",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report does not contain %q:\n%s", want, out)
		}
	}

	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Gate  Gate `json:"gate"`
		Rules []struct {
			RuleID string  `json:"rule_id"`
			Lower  float64 `json:"precision_lower"`
			Status Status  `json:"status"`
		} `json:"rules"`
		Promote []Result `json:"promote"`
		Retire  []Result `json:"retire"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("report JSON: %v\n%s", err, buf.String())
	}
	if len(decoded.Rules) != 4 || decoded.Rules[0].Status != Passes || decoded.Rules[0].Lower < 0.9 {
		t.Errorf("decoded rules = %+v", decoded.Rules)
	}
	if decoded.Gate.MinLabeled != 30 || len(decoded.Promote) != 1 || len(decoded.Retire) != 1 {
		t.Errorf("decoded = %+v", decoded)
	}
}

func TestReportEmptyListsAreArrays(t *testing.T) {
	var buf bytes.Buffer
	if err := NewReport(Gate{}, nil, nil).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"promote": []`) || !strings.Contains(buf.String(), `"retire": []`) {
		t.Errorf("empty candidate lists should encode as []: %s", buf.String())
	}
}
