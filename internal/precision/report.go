package precision

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// Report is the precision of every rule in a ruleset, with the rules worth
// acting on: shadow rules that pass the gate (promote) and enforced rules
// below it (retire). It is what `catraca report` prints.
type Report struct {
	Gate  Gate     `json:"gate"`
	Rules []Result `json:"rules"`
	// Promote lists shadow rules that pass the gate.
	Promote []Result `json:"promote"`
	// Retire lists enforced rules whose precision is below the gate,
	// including rules kept enforced by an override.
	Retire []Result `json:"retire"`
}

// NewReport evaluates rules against the gate.
func NewReport(g Gate, rules []RuleInfo, stats []RuleStats) Report {
	g = g.withDefaults()
	r := Report{
		Gate:    g,
		Rules:   g.EvaluateRules(rules, stats),
		Promote: []Result{},
		Retire:  []Result{},
	}
	for _, res := range r.Rules {
		switch {
		case res.Mode == decision.Shadow && res.Status == Passes:
			r.Promote = append(r.Promote, res)
		case res.Mode == decision.Enforce && res.Status == BelowPrecision:
			r.Retire = append(r.Retire, res)
		}
	}
	return r
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the report as a table followed by the promote and retire
// candidates.
func (r Report) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Gate: at least %d labeled matches and a precision lower bound of %.2f (Wilson 95%%)\n\n",
		r.Gate.MinLabeled, r.Gate.MinPrecision)
	fmt.Fprintln(tw, "RULE\tMODE\tMATCHES\tLABELED\tTP\tFP\tPRECISION\t95% CI\tSTATUS")
	for _, res := range r.Rules {
		prec, ci := "-", "-"
		if res.Labeled > 0 {
			prec = fmt.Sprintf("%.3f", res.Precision)
			ci = fmt.Sprintf("[%.3f, %.3f]", res.Lower, res.Upper)
		}
		status := string(res.Status)
		if res.Override {
			status += " (override)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
			res.RuleID, res.Mode, res.Matches, res.Labeled, res.TruePositives, res.FalsePositives, prec, ci, status)
	}
	writeCandidates(tw, "Promote candidates (shadow rules that pass the gate):", r.Promote)
	writeCandidates(tw, "Retire candidates (enforced rules below the gate):", r.Retire)
	return tw.Flush()
}

func writeCandidates(w io.Writer, title string, results []Result) {
	fmt.Fprintf(w, "\n%s\n", title)
	if len(results) == 0 {
		fmt.Fprintln(w, "  none")
		return
	}
	for _, res := range results {
		fmt.Fprintf(w, "  %s: %s\n", res.RuleID, describe(res))
	}
}
