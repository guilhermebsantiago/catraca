package precision

import (
	"fmt"
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// Defaults for Gate, from docs/design.md.
const (
	DefaultMinLabeled   = 30
	DefaultMinPrecision = 0.9
)

// Gate is the bar a rule must clear before it enforces: at least MinLabeled
// labeled matches, and a Wilson 95% lower bound on precision of at least
// MinPrecision. Zero fields take the defaults.
type Gate struct {
	MinLabeled   int     `json:"min_labeled"`
	MinPrecision float64 `json:"min_precision"`
}

// DefaultGate returns the gate with the default values.
func DefaultGate() Gate {
	return Gate{MinLabeled: DefaultMinLabeled, MinPrecision: DefaultMinPrecision}
}

// Validate reports whether the gate's values make sense.
func (g Gate) Validate() error {
	if g.MinLabeled < 0 {
		return fmt.Errorf("precision: min_labeled must not be negative, got %d", g.MinLabeled)
	}
	if g.MinPrecision < 0 || g.MinPrecision > 1 {
		return fmt.Errorf("precision: min_precision must be in [0, 1], got %g", g.MinPrecision)
	}
	return nil
}

func (g Gate) withDefaults() Gate {
	if g.MinLabeled <= 0 {
		g.MinLabeled = DefaultMinLabeled
	}
	if g.MinPrecision <= 0 {
		g.MinPrecision = DefaultMinPrecision
	}
	return g
}

// Status is the outcome of evaluating a rule against the gate.
type Status string

const (
	// Passes means the rule has enough labels and its precision lower bound
	// clears the gate.
	Passes Status = "passes"
	// InsufficientLabels means there are too few labeled matches to tell.
	InsufficientLabels Status = "insufficient_labels"
	// BelowPrecision means the precision lower bound is under the gate, or,
	// with fewer labels than the minimum, that even the upper bound is: the
	// rule is already known to be worse than the gate allows.
	BelowPrecision Status = "below_precision"
)

// RuleStats are the labeled outcomes of one rule in one mode over a window,
// as the audit log counts them.
type RuleStats struct {
	RuleID string        `json:"rule_id"`
	Mode   decision.Mode `json:"mode"`
	// Matches is how many decisions the rule matched.
	Matches int `json:"matches"`
	// Errored is how many of those matches happened only because the rule
	// could not be evaluated and fails closed.
	Errored int `json:"errored"`
	// Labeled is how many matches carry a label; TruePositives and
	// FalsePositives split them.
	Labeled        int `json:"labeled"`
	TruePositives  int `json:"true_positives"`
	FalsePositives int `json:"false_positives"`
}

// Precision returns TruePositives / Labeled, or 0 with no labels.
func (s RuleStats) Precision() float64 {
	if s.Labeled == 0 {
		return 0
	}
	return float64(s.TruePositives) / float64(s.Labeled)
}

func (s *RuleStats) add(o RuleStats) {
	s.Matches += o.Matches
	s.Errored += o.Errored
	s.Labeled += o.Labeled
	s.TruePositives += o.TruePositives
	s.FalsePositives += o.FalsePositives
}

// RuleInfo is what the gate needs to know about a rule in the ruleset. It is
// defined here so this package does not depend on the rules package.
type RuleInfo struct {
	ID   string
	Mode decision.Mode
	// HasOverride is true when the rule records a decision to enforce it
	// without passing the gate.
	HasOverride bool
}

// Result is one rule evaluated against the gate. Counts add up the rule's
// matches in every mode: precision is a property of the rule's condition,
// and a rule promoted from shadow keeps the labels it earned there.
type Result struct {
	RuleID string `json:"rule_id"`
	// Mode is the rule's mode in the ruleset.
	Mode           decision.Mode `json:"mode"`
	Matches        int           `json:"matches"`
	Errored        int           `json:"errored"`
	Labeled        int           `json:"labeled"`
	TruePositives  int           `json:"true_positives"`
	FalsePositives int           `json:"false_positives"`
	// Precision is TruePositives / Labeled, or 0 with no labels. Lower and
	// Upper are its Wilson 95% interval.
	Precision float64 `json:"precision"`
	Lower     float64 `json:"precision_lower"`
	Upper     float64 `json:"precision_upper"`
	Status    Status  `json:"status"`
	// Override is true when the rule has an override in the ruleset.
	Override bool `json:"override,omitempty"`
}

// Evaluate places one rule's counts against the gate. Mode is taken from s.
func (g Gate) Evaluate(s RuleStats) Result {
	g = g.withDefaults()
	lower, upper := Wilson(s.TruePositives, s.Labeled)
	r := Result{
		RuleID:         s.RuleID,
		Mode:           s.Mode,
		Matches:        s.Matches,
		Errored:        s.Errored,
		Labeled:        s.Labeled,
		TruePositives:  s.TruePositives,
		FalsePositives: s.FalsePositives,
		Precision:      s.Precision(),
		Lower:          lower,
		Upper:          upper,
	}
	switch {
	case s.Labeled >= g.MinLabeled && lower >= g.MinPrecision:
		r.Status = Passes
	case s.Labeled >= g.MinLabeled:
		r.Status = BelowPrecision
	case s.Labeled > 0 && upper < g.MinPrecision:
		r.Status = BelowPrecision
	default:
		r.Status = InsufficientLabels
	}
	return r
}

// EvaluateRules evaluates every rule in rules, in order, adding up its stats
// across modes. Stats of rules that are not in rules are ignored.
func (g Gate) EvaluateRules(rules []RuleInfo, stats []RuleStats) []Result {
	byRule := make(map[string]RuleStats, len(stats))
	for _, s := range stats {
		agg := byRule[s.RuleID]
		agg.RuleID = s.RuleID
		agg.add(s)
		byRule[s.RuleID] = agg
	}
	out := make([]Result, 0, len(rules))
	for _, ri := range rules {
		s := byRule[ri.ID]
		s.RuleID = ri.ID
		s.Mode = ri.Mode
		r := g.Evaluate(s)
		r.Override = ri.HasOverride
		out = append(out, r)
	}
	return out
}

// CheckRuleset checks that every enforced rule passes the gate or has an
// override. It returns the result of every enforced rule and, when at least
// one fails, a *GateError listing the failures. This is what
// `catraca rules gate` runs in CI.
func (g Gate) CheckRuleset(rules []RuleInfo, stats []RuleStats) ([]Result, error) {
	var enforced []RuleInfo
	for _, ri := range rules {
		if ri.Mode == decision.Enforce {
			enforced = append(enforced, ri)
		}
	}
	results := g.EvaluateRules(enforced, stats)
	var failed []Result
	for _, r := range results {
		if r.Status != Passes && !r.Override {
			failed = append(failed, r)
		}
	}
	if len(failed) > 0 {
		return results, &GateError{Gate: g.withDefaults(), Failed: failed}
	}
	return results, nil
}

// GateError reports the enforced rules that do not pass the gate and have no
// override.
type GateError struct {
	Gate   Gate
	Failed []Result
}

func (e *GateError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d enforced rule(s) below the gate (min %d labels, precision lower bound >= %.2f) without an override:",
		len(e.Failed), e.Gate.MinLabeled, e.Gate.MinPrecision)
	for _, r := range e.Failed {
		fmt.Fprintf(&b, "\n  %s: %s, %s", r.RuleID, r.Status, describe(r))
	}
	return b.String()
}

// describe summarizes a result's evidence in one phrase.
func describe(r Result) string {
	if r.Labeled == 0 {
		return "no labeled matches"
	}
	return fmt.Sprintf("precision %.3f [%.3f, %.3f] on %d labeled matches",
		r.Precision, r.Lower, r.Upper, r.Labeled)
}
