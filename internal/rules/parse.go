package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

var (
	ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

var (
	topFields      = []string{"version", "defaults", "lists", "rules"}
	defaultsFields = []string{"mode", "on_error"}
	ruleFields     = []string{"id", "description", "when", "action", "mode", "on_error", "effects", "retry_after", "reason", "owner", "tags", "override"}
	overrideFields = []string{"by", "reason", "at"}
)

func parse(data []byte, file string) (*Ruleset, error) {
	e := &errs{file: file}
	root := parseDocument(data, e)
	if root == nil {
		return nil, e.err()
	}
	if !mapping(e, root, "", "a ruleset") {
		return nil, e.err()
	}

	rs := &Ruleset{
		defaults:  defaults{mode: decision.Shadow, onError: decision.FailOpen},
		lists:     map[string][]string{},
		byID:      map[string]*Rule{},
		listLines: map[string]int{},
	}
	var formatSeen bool
	var rulesNode *yaml.Node
	fields(e, root, "", topFields, func(key string, _, v *yaml.Node) {
		switch key {
		case "version":
			formatSeen = true
			if v.ShortTag() != "!!int" || v.Value != fmt.Sprint(Format) {
				e.add(v.Line, "", "version must be %d, the only ruleset format so far", Format)
			}
		case "defaults":
			parseDefaults(e, v, &rs.defaults)
		case "lists":
			parseLists(e, v, rs)
		case "rules":
			rulesNode = v
		}
	})
	if !formatSeen {
		e.add(root.Line, "", "version is required (write version: %d)", Format)
	}

	// Rules are read last so defaults apply wherever they appear in the file.
	var sources []ruleSource
	switch {
	case rulesNode == nil:
		e.add(root.Line, "", "rules is required")
	case isNull(rulesNode):
	case rulesNode.Kind != yaml.SequenceNode:
		e.add(rulesNode.Line, "", "rules must be a list")
	default:
		for i, n := range rulesNode.Content {
			r, src := parseRule(e, resolve(n), i, rs.defaults)
			if r == nil {
				continue
			}
			switch prev, dup := rs.byID[r.ID]; {
			case r.ID == "":
			case dup:
				e.add(r.Line, src.where, "id is already used by the rule on line %d", prev.Line)
			default:
				rs.byID[r.ID] = r
			}
			// A rule with problems is still compiled, so that one run
			// reports its CEL errors too; any error fails the load.
			rs.rules = append(rs.rules, r)
			sources = append(sources, src)
		}
	}

	if err := compile(rs, sources, e); err != nil {
		return nil, err
	}
	if len(e.list) > 0 {
		return nil, e.err()
	}
	v, err := rs.computeVersion()
	if err != nil {
		return nil, fmt.Errorf("rules: hash ruleset: %w", err)
	}
	rs.version = v
	return rs, nil
}

func parseDefaults(e *errs, n *yaml.Node, d *defaults) {
	if isNull(n) || !mapping(e, n, "defaults", "defaults") {
		return
	}
	fields(e, n, "defaults", defaultsFields, func(key string, _, v *yaml.Node) {
		switch key {
		case "mode":
			if m, ok := parseMode(e, v, "defaults"); ok {
				d.mode = m
			}
		case "on_error":
			if o, ok := parseOnError(e, v, "defaults"); ok {
				d.onError = o
			}
		}
	})
}

func parseLists(e *errs, n *yaml.Node, rs *Ruleset) {
	if isNull(n) || !mapping(e, n, "lists", "lists") {
		return
	}
	fields(e, n, "lists", nil, func(name string, k, v *yaml.Node) {
		if !namePattern.MatchString(name) {
			e.add(k.Line, "lists", "list name %q must be lowercase letters, digits and underscores, starting with a letter", name)
			return
		}
		items := strs(e, v, "list "+name, "a list")
		if items == nil {
			return
		}
		rs.lists[name] = items
		rs.listLines[name] = k.Line
	})
}

// ruleSource is where a rule came from, for compile errors.
type ruleSource struct {
	where string
	// when is the node of the rule's expression, nil when it has none.
	when *yaml.Node
}

// parseRule reads one rule and applies defaults.
func parseRule(e *errs, n *yaml.Node, index int, d defaults) (*Rule, ruleSource) {
	where := fmt.Sprintf("rule #%d", index+1)
	if n.Kind != yaml.MappingNode {
		e.add(n.Line, where, "a rule must be a mapping")
		return nil, ruleSource{}
	}
	r := &Rule{Line: n.Line, Action: decision.Flag, Mode: d.mode, OnError: d.onError}
	// The id names the rule in every other message, so read it first.
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k, v := n.Content[i], resolve(n.Content[i+1]); k.Value == "id" && v.Kind == yaml.ScalarNode && v.Value != "" {
			where = "rule " + v.Value
		}
	}

	var when *yaml.Node
	var retryAfterLine int
	fields(e, n, where, ruleFields, func(key string, k, v *yaml.Node) {
		switch key {
		case "id":
			r.ID = str(e, v, where, "id")
			if r.ID != "" && !ruleIDPattern.MatchString(r.ID) {
				e.add(v.Line, where, "id must be kebab-case: lowercase letters and digits separated by single dashes, starting with a letter")
			}
		case "description":
			r.Description = strings.TrimSpace(str(e, v, where, "description"))
		case "when":
			r.When = strings.TrimSpace(str(e, v, where, "when"))
			when = v
		case "action":
			s := str(e, v, where, "action")
			a, err := decision.ParseAction(s)
			switch {
			case err != nil:
				e.add(v.Line, where, "unknown action %q (want flag, throttle, hold or block)", s)
			case a == decision.Allow:
				e.add(v.Line, where, "allow is not a rule action: a rule that matches must flag, throttle, hold or block")
			default:
				r.Action = a
			}
		case "mode":
			if m, ok := parseMode(e, v, where); ok {
				r.Mode = m
			}
		case "on_error":
			if o, ok := parseOnError(e, v, where); ok {
				r.OnError = o
				r.onErrorSet = true
			}
		case "effects":
			r.Effects = parseEffects(e, v, where)
		case "retry_after":
			retryAfterLine = v.Line
			s := str(e, v, where, "retry_after")
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				e.add(v.Line, where, "retry_after must be a positive duration such as 30s or 5m, not %q", s)
				break
			}
			r.RetryAfter = d
		case "reason":
			r.Reason = strings.TrimSpace(str(e, v, where, "reason"))
		case "owner":
			r.Owner = strings.TrimSpace(str(e, v, where, "owner"))
		case "tags":
			r.Tags = strs(e, v, where, "tags")
		case "override":
			r.Override = parseOverride(e, v, where)
		}
	})

	if r.ID == "" {
		e.add(n.Line, where, "id is required")
	}
	if r.When == "" {
		e.add(n.Line, where, "when is required")
	}
	if r.Reason == "" {
		e.add(n.Line, where, "reason is required: it is shown to the platform and written to the audit log")
	}
	switch {
	case r.Action == decision.Throttle && r.RetryAfter == 0 && retryAfterLine == 0:
		e.add(n.Line, where, "throttle rules need retry_after")
	case r.Action != decision.Throttle && retryAfterLine != 0:
		e.add(retryAfterLine, where, "retry_after is only for throttle rules")
		r.RetryAfter = 0
	}
	return r, ruleSource{where: where, when: when}
}

func parseMode(e *errs, v *yaml.Node, where string) (decision.Mode, bool) {
	m, err := decision.ParseMode(str(e, v, where, "mode"))
	if err != nil {
		e.add(v.Line, where, "%v", err)
		return "", false
	}
	return m, true
}

func parseOnError(e *errs, v *yaml.Node, where string) (decision.OnError, bool) {
	switch s := str(e, v, where, "on_error"); decision.OnError(s) {
	case decision.FailOpen, decision.FailClosed:
		return decision.OnError(s), true
	default:
		e.add(v.Line, where, "unknown on_error %q (want open or closed)", s)
		return "", false
	}
}

func parseEffects(e *errs, v *yaml.Node, where string) []string {
	effects := strs(e, v, where, "effects")
	seen := map[string]bool{}
	out := effects[:0]
	for _, name := range effects {
		switch {
		case !namePattern.MatchString(name):
			e.add(v.Line, where, "effect %q must be lowercase letters, digits and underscores, starting with a letter", name)
		case seen[name]:
			e.add(v.Line, where, "effect %s is listed twice", name)
		default:
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseOverride(e *errs, v *yaml.Node, where string) *Override {
	if !mapping(e, v, where, "override") {
		return nil
	}
	o := &Override{}
	var atSet bool
	fields(e, v, where, overrideFields, func(key string, _, f *yaml.Node) {
		switch key {
		case "by":
			o.By = strings.TrimSpace(str(e, f, where, "override.by"))
		case "reason":
			o.Reason = strings.TrimSpace(str(e, f, where, "override.reason"))
		case "at":
			atSet = true
			s := str(e, f, where, "override.at")
			at, err := parseTime(s)
			if err != nil {
				e.add(f.Line, where, "override.at must be a date (2006-01-02) or an RFC 3339 time, not %q", s)
			}
			o.At = at
		}
	})
	if o.By == "" {
		e.add(v.Line, where, "override.by is required: who decided to enforce the rule")
	}
	if o.Reason == "" {
		e.add(v.Line, where, "override.reason is required: why the rule is enforced before passing the gate")
	}
	if !atSet {
		e.add(v.Line, where, "override.at is required: when the decision was made")
	}
	return o
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	return t.UTC(), err
}
