package rules

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// Warning is a lint finding: the ruleset loads and works, but something in
// it is probably a mistake.
type Warning struct {
	Line int
	// Where names the rule or list the warning is about.
	Where string
	Msg   string
}

func (w Warning) String() string {
	var b strings.Builder
	if w.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", w.Line)
	}
	if w.Where != "" {
		fmt.Fprintf(&b, "%s: ", w.Where)
	}
	b.WriteString(w.Msg)
	return b.String()
}

// Lint returns warnings about the ruleset, ordered by line.
func (rs *Ruleset) Lint() []Warning {
	var out []Warning
	warn := func(line int, where, format string, args ...any) {
		out = append(out, Warning{Line: line, Where: where, Msg: fmt.Sprintf(format, args...)})
	}

	if len(rs.rules) == 0 {
		warn(0, "", "the ruleset has no rules: every event is allowed")
	}
	used := map[string]bool{}
	for _, r := range rs.rules {
		where := "rule " + r.ID
		for _, l := range r.expr.lists {
			used[l] = true
		}
		enforced := r.Mode == decision.Enforce

		if enforced && !r.onErrorSet {
			warn(r.Line, where, "enforced rule inherits on_error %q from defaults; state on_error so reviewers see what happens when it cannot be evaluated", r.OnError)
		}
		if !enforced && len(r.Effects) > 0 {
			warn(r.Line, where, "effects %s never run while the rule is in shadow mode", strings.Join(r.Effects, ", "))
		}
		if !enforced && r.Override != nil {
			warn(r.Line, where, "override has no effect on a shadow rule")
		}
		if r.expr.constant {
			warn(r.Line, where, "when is a constant, so the rule matches every event or none")
		}
		for _, ref := range r.expr.refs {
			names, known := knownSignals[ref.Map]
			if _, ok := names[ref.Name]; known && !ok {
				warn(r.Line, where, "reads %s, which is not a known signal: it is always absent, so the rule always fails to evaluate%s",
					ref, suggest(ref.Name, slices.Sorted(maps.Keys(names))))
			}
		}
		if r.OnError == decision.FailClosed {
			for _, g := range presenceGuards {
				if readsMap(r.expr.refs, g.Map) && !slices.Contains(r.expr.refs, signalRef{"event", g.Guard}) {
					warn(r.Line, where, "fails closed and reads %s signals without checking event.%s: events without one fail to evaluate and match", g.Map, g.Guard)
				}
			}
		}
	}

	for _, name := range slices.Sorted(maps.Keys(rs.lists)) {
		where, line, items := "list "+name, rs.listLines[name], rs.lists[name]
		if !used[name] {
			warn(line, where, "not used by any rule")
		}
		if len(items) == 0 {
			warn(line, where, "the list is empty")
		}
		seen := map[string]bool{}
		for _, item := range items {
			if seen[item] {
				warn(line, where, "%q is listed twice", item)
			}
			seen[item] = true
		}
	}

	slices.SortStableFunc(out, func(a, b Warning) int { return a.Line - b.Line })
	return out
}

func readsMap(refs []signalRef, m string) bool {
	return slices.ContainsFunc(refs, func(r signalRef) bool { return r.Map == m })
}
