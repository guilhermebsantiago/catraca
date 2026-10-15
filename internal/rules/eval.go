package rules

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"cel.dev/cel-go/common/types"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// Result is the evaluation of one rule.
type Result struct {
	Rule    *Rule
	Matched bool
	// Err is set when the rule could not be evaluated, for example because
	// it read a signal that is absent. Matched is then false; Combine
	// applies the rule's on_error policy.
	Err error
}

// Evaluate runs every rule against set, in file order.
func (rs *Ruleset) Evaluate(set signal.Set) []Result {
	act := newActivation(set)
	out := make([]Result, len(rs.rules))
	for i, r := range rs.rules {
		out[i] = Result{Rule: r}
		out[i].Matched, out[i].Err = r.eval(act)
	}
	return out
}

func (r *Rule) eval(act *activation) (bool, error) {
	val, _, err := r.program.Eval(act)
	if err != nil {
		return false, r.explain(act, err)
	}
	b, ok := val.(types.Bool)
	if !ok {
		return false, fmt.Errorf("when returned %s, not bool", val.Type().TypeName())
	}
	return bool(b), nil
}

// explain rewrites CEL's "no such key: sends_1m" as "signal account.sends_1m
// is absent", which is what an operator reading a decision needs to know.
func (r *Rule) explain(act *activation, err error) error {
	name, ok := strings.CutPrefix(err.Error(), "no such key: ")
	if !ok {
		return err
	}
	if missing := act.absent(r.expr.refs, name); len(missing) > 0 {
		return fmt.Errorf("signal %s is absent", strings.Join(missing, " or "))
	}
	return err
}

// Outcome is what a ruleset concludes for one signal set.
type Outcome struct {
	// Action is the most severe action among the enforced matches, or Allow.
	Action decision.Action
	// RetryAfter is the largest retry_after among the enforced throttle
	// matches, set only when Action is Throttle.
	RetryAfter time.Duration
	// Matches are the enforced rules that matched, in file order.
	Matches []decision.Match
	// Shadow are the shadow rules that matched, in file order.
	Shadow []decision.Match
	// Errors are the rules that could not be evaluated, whatever their
	// on_error policy.
	Errors []decision.RuleError
}

// Apply evaluates every rule against set and combines the results.
func (rs *Ruleset) Apply(set signal.Set) Outcome {
	return Combine(rs.Evaluate(set))
}

// Combine turns rule results into an outcome. A rule that failed to evaluate
// is skipped when it fails open and counts as matched, with Errored set, when
// it fails closed.
func Combine(results []Result) Outcome {
	out := Outcome{Action: decision.Allow}
	for _, res := range results {
		r := res.Rule
		matched, errored := res.Matched, false
		if res.Err != nil {
			out.Errors = append(out.Errors, decision.RuleError{RuleID: r.ID, Error: res.Err.Error()})
			if r.OnError != decision.FailClosed {
				continue
			}
			matched, errored = true, true
		}
		if !matched {
			continue
		}
		m := decision.Match{
			RuleID:     r.ID,
			Reason:     r.Reason,
			Action:     r.Action,
			Mode:       r.Mode,
			Effects:    slices.Clone(r.Effects),
			RetryAfter: r.RetryAfter,
			Errored:    errored,
		}
		if r.Mode != decision.Enforce {
			out.Shadow = append(out.Shadow, m)
			continue
		}
		out.Matches = append(out.Matches, m)
		out.Action = decision.Max(out.Action, r.Action)
		if r.Action == decision.Throttle {
			out.RetryAfter = max(out.RetryAfter, r.RetryAfter)
		}
	}
	if out.Action != decision.Throttle {
		out.RetryAfter = 0
	}
	return out
}
