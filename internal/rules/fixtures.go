package rules

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// Case is one fixture: the signals an event had and what the ruleset should
// conclude from them.
type Case struct {
	Name string
	Line int
	// Signals are the file's base signals with the case's own on top.
	Signals signal.Set
	Expect  Expectation
}

// Expectation is what a case checks. Fields left unset are not checked. For
// the rule lists, nil means unchecked and an empty list means none: each set
// list must equal the rules that matched, in any order.
type Expectation struct {
	// Action is the final action, which depends on the rules' modes.
	Action decision.Action
	// RetryAfter is the final retry_after.
	RetryAfter *time.Duration
	// Enforced are the enforced rules that matched.
	Enforced []string
	// Shadow are the shadow rules that matched.
	Shadow []string
	// Matches are the rules that matched in either mode. It is the
	// expectation that keeps passing when a rule is promoted from shadow to
	// enforce.
	Matches []string
	// Errors are the rules that failed to evaluate.
	Errors []string
}

var (
	fixtureFields = []string{"base", "cases"}
	caseFields    = []string{"name", "signals", "expect"}
	expectFields  = []string{"action", "retry_after", "enforced", "shadow", "matches", "errors"}
)

// ParseFixtures parses a fixture file. On failure the error is an ErrorList.
func ParseFixtures(data []byte) ([]Case, error) {
	return parseFixtures(data, "")
}

// LoadFixtures reads and parses the fixture file at path.
func LoadFixtures(path string) ([]Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseFixtures(data, path)
}

func parseFixtures(data []byte, file string) ([]Case, error) {
	e := &errs{file: file}
	root := parseDocument(data, e)
	if root == nil || !mapping(e, root, "", "a fixture file") {
		return nil, e.err()
	}
	var baseNode, casesNode *yaml.Node
	fields(e, root, "", fixtureFields, func(key string, _, v *yaml.Node) {
		if key == "base" {
			baseNode = v
		} else {
			casesNode = v
		}
	})
	// The base is read first so cases build on it wherever it appears.
	var base signal.Set
	if baseNode != nil {
		base = parseSignals(e, baseNode, "base", signal.Set{})
	}

	var cases []Case
	switch {
	case casesNode == nil:
		e.add(root.Line, "", "cases is required")
	case casesNode.Kind != yaml.SequenceNode:
		e.add(casesNode.Line, "", "cases must be a list")
	default:
		names := map[string]int{}
		for i, n := range casesNode.Content {
			c, ok := parseCase(e, resolve(n), i, base)
			if !ok {
				continue
			}
			if prev, dup := names[c.Name]; dup {
				e.add(c.Line, fmt.Sprintf("case %q", c.Name), "name is already used by the case on line %d", prev)
				continue
			}
			names[c.Name] = c.Line
			cases = append(cases, c)
		}
	}
	if err := e.err(); err != nil {
		return nil, err
	}
	return cases, nil
}

func parseCase(e *errs, n *yaml.Node, index int, base signal.Set) (Case, bool) {
	where := fmt.Sprintf("case #%d", index+1)
	if !mapping(e, n, where, "a case") {
		return Case{}, false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k, v := n.Content[i], resolve(n.Content[i+1]); k.Value == "name" && v.Kind == yaml.ScalarNode && v.Value != "" {
			where = fmt.Sprintf("case %q", v.Value)
		}
	}
	before := len(e.list)
	c := Case{Line: n.Line, Signals: base}
	var expectSeen bool
	fields(e, n, where, caseFields, func(key string, _, v *yaml.Node) {
		switch key {
		case "name":
			c.Name = strings.TrimSpace(str(e, v, where, "name"))
		case "signals":
			c.Signals = parseSignals(e, v, where, base)
		case "expect":
			expectSeen = true
			c.Expect = parseExpect(e, v, where)
		}
	})
	if c.Name == "" {
		e.add(n.Line, where, "name is required")
	}
	if !expectSeen {
		e.add(n.Line, where, "expect is required")
	}
	return c, len(e.list) == before
}

// parseSignals reads signal maps on top of base, which is not modified. A
// null signal is removed and a null map is dropped, which makes them absent
// as when the store fails.
func parseSignals(e *errs, n *yaml.Node, where string, base signal.Set) signal.Set {
	set := base
	if isNull(n) || !mapping(e, n, where, "signals") {
		return set
	}
	fields(e, n, where, variables, func(name string, _, v *yaml.Node) {
		var m *map[string]any
		switch name {
		case "event":
			m = &set.Event
		case "account":
			m = &set.Account
		case "key":
			m = &set.Key
		case "ip":
			m = &set.IP
		case "domain":
			m = &set.Domain
		}
		if isNull(v) {
			*m = nil
			return
		}
		*m = parseSignalMap(e, v, where, name, *m)
	})
	return set
}

func parseSignalMap(e *errs, n *yaml.Node, where, mapName string, base map[string]any) map[string]any {
	m := maps.Clone(base)
	if m == nil {
		m = map[string]any{}
	}
	if !mapping(e, n, where, "signals."+mapName) {
		return m
	}
	fields(e, n, where, nil, func(name string, _, v *yaml.Node) {
		if isNull(v) {
			delete(m, name)
			return
		}
		kind := knownSignals[mapName][name]
		if kind == 0 {
			kind = guessKind(v)
		}
		val, err := signalValue(v, kind)
		if err != nil {
			e.add(v.Line, where, "%s.%s: %v", mapName, name, err)
			return
		}
		m[name] = val
	})
	return m
}

// guessKind picks the kind of a signal the catalog does not define from how
// its value is written.
func guessKind(n *yaml.Node) signalKind {
	switch {
	case n.Kind == yaml.SequenceNode:
		return kindStrings
	case n.Kind == yaml.MappingNode:
		return kindStringMap
	}
	switch n.ShortTag() {
	case "!!int":
		return kindInt
	case "!!float":
		return kindFloat
	case "!!bool":
		return kindBool
	}
	return kindString
}

// signalValue converts n to the Go type the catalog uses for kind.
func signalValue(n *yaml.Node, kind signalKind) (any, error) {
	wrong := fmt.Errorf("want %s", kind)
	switch kind {
	case kindStrings:
		if n.Kind != yaml.SequenceNode {
			return nil, wrong
		}
		out := make([]string, 0, len(n.Content))
		for _, item := range n.Content {
			if item = resolve(item); item.Kind != yaml.ScalarNode {
				return nil, wrong
			}
			out = append(out, item.Value)
		}
		return out, nil
	case kindStringMap:
		if n.Kind != yaml.MappingNode {
			return nil, wrong
		}
		out := make(map[string]string, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := resolve(n.Content[i]), resolve(n.Content[i+1])
			if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
				return nil, wrong
			}
			out[k.Value] = v.Value
		}
		return out, nil
	}
	if n.Kind != yaml.ScalarNode {
		return nil, wrong
	}
	switch kind {
	case kindInt:
		var i int64
		if n.ShortTag() != "!!int" || n.Decode(&i) != nil {
			return nil, wrong
		}
		return i, nil
	case kindFloat:
		var f float64
		if (n.ShortTag() != "!!int" && n.ShortTag() != "!!float") || n.Decode(&f) != nil {
			return nil, wrong
		}
		return f, nil
	case kindBool:
		if n.ShortTag() != "!!bool" {
			return nil, wrong
		}
		var b bool
		if err := n.Decode(&b); err != nil {
			return nil, wrong
		}
		return b, nil
	}
	return n.Value, nil
}

func parseExpect(e *errs, n *yaml.Node, where string) Expectation {
	var x Expectation
	if !mapping(e, n, where, "expect") {
		return x
	}
	var checked bool
	fields(e, n, where, expectFields, func(key string, _, v *yaml.Node) {
		checked = true
		switch key {
		case "action":
			s := str(e, v, where, "expect.action")
			a, err := decision.ParseAction(s)
			if err != nil {
				e.add(v.Line, where, "expect.action: %v", err)
				return
			}
			x.Action = a
		case "retry_after":
			s := str(e, v, where, "expect.retry_after")
			d, err := time.ParseDuration(s)
			if err != nil || d < 0 {
				e.add(v.Line, where, "expect.retry_after must be a duration such as 60s, not %q", s)
				return
			}
			x.RetryAfter = &d
		case "enforced":
			x.Enforced = strs(e, v, where, "expect.enforced")
		case "shadow":
			x.Shadow = strs(e, v, where, "expect.shadow")
		case "matches":
			x.Matches = strs(e, v, where, "expect.matches")
		case "errors":
			x.Errors = strs(e, v, where, "expect.errors")
		}
	})
	if !checked {
		e.add(n.Line, where, "expect must check something: %s", strings.Join(expectFields, ", "))
	}
	return x
}

// CaseResult is the outcome of one fixture case.
type CaseResult struct {
	Name string
	Line int
	// Diffs explain each expectation that did not hold. A case passed when
	// it has none.
	Diffs []string
}

// Passed reports whether every expectation of the case held.
func (r CaseResult) Passed() bool { return len(r.Diffs) == 0 }

// FixtureReport is the outcome of running fixtures against a ruleset.
type FixtureReport struct {
	RulesetVersion string
	Results        []CaseResult
}

// Failed returns the cases that did not pass.
func (r FixtureReport) Failed() []CaseResult {
	var out []CaseResult
	for _, c := range r.Results {
		if !c.Passed() {
			out = append(out, c)
		}
	}
	return out
}

// Err returns an error describing every failed case, or nil when all passed.
func (r FixtureReport) Err() error {
	failed := r.Failed()
	if len(failed) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d fixture cases failed:", len(failed), len(r.Results))
	for _, c := range failed {
		writeCase(&b, c)
	}
	return errors.New(b.String())
}

// WriteText writes one line per case and the failures' diffs to w.
func (r FixtureReport) WriteText(w io.Writer) error {
	var b strings.Builder
	for _, c := range r.Results {
		if c.Passed() {
			fmt.Fprintf(&b, "ok    %s\n", c.Name)
			continue
		}
		writeCase(&b, c)
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%d cases, %d failed (ruleset %s)\n", len(r.Results), len(r.Failed()), r.RulesetVersion)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeCase(b *strings.Builder, c CaseResult) {
	fmt.Fprintf(b, "\nFAIL  %s (line %d)", c.Name, c.Line)
	for _, d := range c.Diffs {
		fmt.Fprintf(b, "\n        %s", d)
	}
}

// RunFixtures evaluates each case against rs and compares the outcome with
// its expectations.
func RunFixtures(rs *Ruleset, cases []Case) FixtureReport {
	report := FixtureReport{RulesetVersion: rs.Version(), Results: make([]CaseResult, 0, len(cases))}
	for _, c := range cases {
		report.Results = append(report.Results, runCase(rs, c))
	}
	return report
}

func runCase(rs *Ruleset, c Case) CaseResult {
	res := CaseResult{Name: c.Name, Line: c.Line}
	x := c.Expect
	for _, list := range [][]string{x.Enforced, x.Shadow, x.Matches, x.Errors} {
		for _, id := range list {
			if _, ok := rs.Rule(id); !ok {
				res.Diffs = append(res.Diffs, fmt.Sprintf("unknown rule %s%s", id, suggest(id, ruleIDs(rs))))
			}
		}
	}

	out := rs.Apply(c.Signals)
	enforced, shadow := matchIDs(out.Matches), matchIDs(out.Shadow)
	errored := make([]string, len(out.Errors))
	for i, re := range out.Errors {
		errored[i] = re.RuleID
	}

	if x.Action != "" && x.Action != out.Action {
		res.Diffs = append(res.Diffs, fmt.Sprintf("action: want %s, got %s", x.Action, out.Action))
	}
	if x.RetryAfter != nil && *x.RetryAfter != out.RetryAfter {
		res.Diffs = append(res.Diffs, fmt.Sprintf("retry_after: want %s, got %s", *x.RetryAfter, out.RetryAfter))
	}
	res.Diffs = appendSetDiff(res.Diffs, "enforced", x.Enforced, enforced)
	res.Diffs = appendSetDiff(res.Diffs, "shadow", x.Shadow, shadow)
	res.Diffs = appendSetDiff(res.Diffs, "matches", x.Matches, slices.Concat(enforced, shadow))
	res.Diffs = appendSetDiff(res.Diffs, "errors", x.Errors, errored)

	// Evaluation errors usually explain a failure, for example a signal the
	// case forgot to set, so show them whenever the case fails.
	if len(res.Diffs) > 0 {
		for _, re := range out.Errors {
			res.Diffs = append(res.Diffs, fmt.Sprintf("note: rule %s failed to evaluate: %s", re.RuleID, re.Error))
		}
	}
	return res
}

func matchIDs(ms []decision.Match) []string {
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.RuleID
	}
	return ids
}

func ruleIDs(rs *Ruleset) []string {
	ids := make([]string, len(rs.rules))
	for i, r := range rs.rules {
		ids[i] = r.ID
	}
	return ids
}

// appendSetDiff compares want and got as sets. A nil want is not checked.
func appendSetDiff(diffs []string, field string, want, got []string) []string {
	if want == nil {
		return diffs
	}
	var missing, unexpected []string
	for _, id := range want {
		if !slices.Contains(got, id) {
			missing = append(missing, id)
		}
	}
	for _, id := range got {
		if !slices.Contains(want, id) {
			unexpected = append(unexpected, id)
		}
	}
	if len(missing) == 0 && len(unexpected) == 0 {
		return diffs
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing "+strings.Join(missing, ", "))
	}
	if len(unexpected) > 0 {
		parts = append(parts, "unexpected "+strings.Join(unexpected, ", "))
	}
	return append(diffs, fmt.Sprintf("%s: want [%s], got [%s] (%s)",
		field, strings.Join(want, ", "), strings.Join(got, ", "), strings.Join(parts, "; ")))
}
