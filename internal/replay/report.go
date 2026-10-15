package replay

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// Report is the result of a backtest. A match, in either mode, counts as
// predicting "abusive"; only labeled events are scored.
type Report struct {
	RulesetVersion string `json:"ruleset_version"`
	// Events is every replayed event; Labeled, Abusive and Legit count the
	// scored ones.
	Events  int `json:"events"`
	Labeled int `json:"labeled"`
	Abusive int `json:"abusive"`
	Legit   int `json:"legit"`
	// Degraded counts decisions made without some signals, which in a
	// backtest points at a catalog problem.
	Degraded int `json:"degraded"`
	// Rules has one entry per rule, in ruleset order.
	Rules []RuleReport `json:"rules"`
	// Enforced scores the effective action: an event is predicted abusive
	// when the enforced rules act on it (the action is not allow).
	Enforced Confusion `json:"enforced"`
	// Shadow scores the shadow rules together: an event is predicted
	// abusive when any shadow rule matches it.
	Shadow Confusion `json:"shadow"`
	// AllRules scores every rule together, as if all were enforced.
	AllRules Confusion `json:"all_rules"`
	// Actions breaks the effective action down by label.
	Actions []ActionCount `json:"actions"`
}

// RuleReport scores one rule.
type RuleReport struct {
	ID     string          `json:"id"`
	Mode   decision.Mode   `json:"mode"`
	Action decision.Action `json:"action"`
	Confusion
	// Errors counts the events, labeled or not, on which the rule could not
	// be evaluated.
	Errors int `json:"errors"`
}

// MarshalJSON writes the rule's fields and its scores in one flat object.
// Without it the embedded Confusion's MarshalJSON would be promoted and
// encode the scores alone.
func (r RuleReport) MarshalJSON() ([]byte, error) {
	head, err := json.Marshal(struct {
		ID     string          `json:"id"`
		Mode   decision.Mode   `json:"mode"`
		Action decision.Action `json:"action"`
		Errors int             `json:"errors"`
	}{r.ID, r.Mode, r.Action, r.Errors})
	if err != nil {
		return nil, err
	}
	scores, err := r.Confusion.MarshalJSON()
	if err != nil {
		return nil, err
	}
	// Both are non-empty objects: join them as {head..., scores...}.
	out := append(head[:len(head)-1], ',')
	return append(out, scores[1:]...), nil
}

// ActionCount is how many events got an action, by label.
type ActionCount struct {
	Action    decision.Action `json:"action"`
	Abusive   int             `json:"abusive"`
	Legit     int             `json:"legit"`
	Unlabeled int             `json:"unlabeled"`
}

// Confusion counts predictions against labels, with "abusive" as the
// positive class.
type Confusion struct {
	TP int `json:"tp"` // matched an abusive event
	FP int `json:"fp"` // matched a legit event
	FN int `json:"fn"` // missed an abusive event
	TN int `json:"tn"` // left a legit event alone
}

func (c *Confusion) add(predicted, abusive bool) {
	switch {
	case predicted && abusive:
		c.TP++
	case predicted:
		c.FP++
	case abusive:
		c.FN++
	default:
		c.TN++
	}
}

// Precision is TP / (TP + FP): of the events predicted abusive, the share
// that were. ok is false when nothing was predicted abusive.
func (c Confusion) Precision() (p float64, ok bool) { return ratio(c.TP, c.TP+c.FP) }

// Recall is TP / (TP + FN): of the abusive events, the share predicted. ok
// is false when there were no abusive events.
func (c Confusion) Recall() (r float64, ok bool) { return ratio(c.TP, c.TP+c.FN) }

// F1 is the harmonic mean of precision and recall. ok is false when either
// is undefined or both are zero.
func (c Confusion) F1() (f float64, ok bool) {
	p, okP := c.Precision()
	r, okR := c.Recall()
	if !okP || !okR || p+r == 0 {
		return 0, false
	}
	return 2 * p * r / (p + r), true
}

func ratio(num, den int) (float64, bool) {
	if den == 0 {
		return 0, false
	}
	return float64(num) / float64(den), true
}

// MarshalJSON adds precision, recall and f1 to the counts, as null when
// undefined.
func (c Confusion) MarshalJSON() ([]byte, error) {
	opt := func(v float64, ok bool) *float64 {
		if !ok {
			return nil
		}
		return &v
	}
	type counts Confusion
	return json.Marshal(struct {
		counts
		Precision *float64 `json:"precision"`
		Recall    *float64 `json:"recall"`
		F1        *float64 `json:"f1"`
	}{counts(c), opt(c.Precision()), opt(c.Recall()), opt(c.F1())})
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the report as aligned tables.
func (r *Report) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	p := func(format string, args ...any) { fmt.Fprintf(tw, format, args...) }

	p("ruleset %s: %d events, %d labeled (%d abusive, %d legit)\n", r.RulesetVersion, r.Events, r.Labeled, r.Abusive, r.Legit)
	if r.Degraded > 0 {
		p("warning: %d decisions were degraded: the catalog failed during the replay\n", r.Degraded)
	}
	for _, section := range []struct {
		mode  decision.Mode
		title string
	}{{decision.Enforce, "ENFORCED RULES"}, {decision.Shadow, "SHADOW RULES"}} {
		var rows []RuleReport
		for _, rr := range r.Rules {
			if rr.Mode == section.mode {
				rows = append(rows, rr)
			}
		}
		if len(rows) == 0 {
			continue
		}
		p("\n%s\taction\tTP\tFP\tFN\tTN\tprecision\trecall\tF1\terrors\n", section.title)
		for _, rr := range rows {
			p("%s\t%s\t%s\t%d\n", rr.ID, rr.Action, confusionCells(rr.Confusion), rr.Errors)
		}
	}

	p("\nCOMBINED\tTP\tFP\tFN\tTN\tprecision\trecall\tF1\n")
	p("enforced rules (effective action)\t%s\n", confusionCells(r.Enforced))
	p("shadow rules\t%s\n", confusionCells(r.Shadow))
	p("all rules, as if enforced\t%s\n", confusionCells(r.AllRules))

	p("\nEFFECTIVE ACTION\tabusive\tlegit\tunlabeled\n")
	for _, ac := range r.Actions {
		p("%s\t%d\t%d\t%d\n", ac.Action, ac.Abusive, ac.Legit, ac.Unlabeled)
	}
	return tw.Flush()
}

func confusionCells(c Confusion) string {
	f := func(v float64, ok bool) string {
		if !ok {
			return "-"
		}
		return fmt.Sprintf("%.3f", v)
	}
	return fmt.Sprintf("%d\t%d\t%d\t%d\t%s\t%s\t%s", c.TP, c.FP, c.FN, c.TN, f(c.Precision()), f(c.Recall()), f(c.F1()))
}
