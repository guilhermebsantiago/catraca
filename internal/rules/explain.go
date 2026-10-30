package rules

import (
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// Signals is a signal.Set as explanations show it: each map under its CEL
// name, null when it is absent altogether.
type Signals struct {
	Event   map[string]any `json:"event"`
	Account map[string]any `json:"account"`
	Key     map[string]any `json:"key"`
	IP      map[string]any `json:"ip"`
	Domain  map[string]any `json:"domain"`
}

// RuleExplanation is how one rule fared against a signal set.
type RuleExplanation struct {
	ID string `json:"id"`
	// Matched is whether the rule matched. A rule that could not be
	// evaluated matches when its on_error is closed, as in a decision.
	Matched bool             `json:"matched"`
	Action  decision.Action  `json:"action"`
	Mode    decision.Mode    `json:"mode"`
	OnError decision.OnError `json:"on_error"`
	// Error is why the rule could not be evaluated, such as an absent
	// signal.
	Error string `json:"error,omitempty"`
}

// Explanation is a ruleset's verdict on one signal set with every signal
// and every rule's result, for people learning which signals an event has
// and why it was decided as it was.
type Explanation struct {
	RulesetVersion string  `json:"ruleset_version"`
	Signals        Signals `json:"signals"`
	// Action is what a decision with these signals would be, and
	// RetryAfter its retry_after in seconds.
	Action     decision.Action   `json:"action"`
	RetryAfter int64             `json:"retry_after,omitempty"`
	Rules      []RuleExplanation `json:"rules"`
}

// Explain evaluates every rule against set, as Apply does, and keeps each
// rule's result.
func (rs *Ruleset) Explain(set signal.Set) Explanation {
	results := rs.Evaluate(set)
	out := Combine(results)
	x := Explanation{
		RulesetVersion: rs.Version(),
		Signals:        Signals{Event: set.Event, Account: set.Account, Key: set.Key, IP: set.IP, Domain: set.Domain},
		Action:         out.Action,
		RetryAfter:     decision.RetrySeconds(out.RetryAfter),
		Rules:          make([]RuleExplanation, len(results)),
	}
	for i, res := range results {
		r := res.Rule
		re := RuleExplanation{ID: r.ID, Matched: res.Matched, Action: r.Action, Mode: r.Mode, OnError: r.OnError}
		if res.Err != nil {
			re.Error = res.Err.Error()
			re.Matched = r.OnError == decision.FailClosed
		}
		x.Rules[i] = re
	}
	return x
}

// ParseSignals parses signal maps written as in a fixture case's signals,
// in YAML or JSON: the signals of an explanation can be read back. A map
// left out or null is absent, so rules that read it fail and follow their
// on_error. On failure the error is an ErrorList.
func ParseSignals(data []byte) (signal.Set, error) {
	return parseSignalsFile(data, "")
}

// LoadSignals reads and parses the signals file at path; see ParseSignals.
func LoadSignals(path string) (signal.Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return signal.Set{}, err
	}
	return parseSignalsFile(data, path)
}

func parseSignalsFile(data []byte, file string) (signal.Set, error) {
	e := &errs{file: file}
	root := parseDocument(data, e)
	if root == nil {
		return signal.Set{}, e.err()
	}
	// A whole explanation, as POST /v1/rules/explain answers it, holds its
	// signals under signals.
	if root.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if k := resolve(root.Content[i]); k.Kind == yaml.ScalarNode && k.Value == "signals" {
				root = resolve(root.Content[i+1])
				break
			}
		}
	}
	set := parseSignals(e, root, "", signal.Set{})
	return set, e.err()
}
