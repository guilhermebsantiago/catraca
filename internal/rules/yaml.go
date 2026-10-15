package rules

import (
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The ruleset and fixture parsers walk yaml.Node trees by hand instead of
// decoding into structs: that is how unknown and repeated fields become
// errors with line numbers, and how a single run reports every mistake.

// parseDocument decodes data and returns its root node, or nil after
// recording why there is none.
func parseDocument(data []byte, e *errs) *yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		e.addYAML(err)
		return nil
	}
	if len(doc.Content) == 0 {
		e.add(0, "", "the file is empty")
		return nil
	}
	return resolve(doc.Content[0])
}

// resolve follows YAML aliases (*name) to the node they point at.
func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// fields calls fn for each key of mapping m, after rejecting keys that are
// not in known, repeated, or not plain strings. ctx names the rule or case
// for error messages.
func fields(e *errs, m *yaml.Node, ctx string, known []string, fn func(key string, k, v *yaml.Node)) {
	seen := make(map[string]bool, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := resolve(m.Content[i]), resolve(m.Content[i+1])
		switch {
		case k.Kind != yaml.ScalarNode:
			e.add(k.Line, ctx, "keys must be plain strings")
		case k.Value == "<<":
			e.add(k.Line, ctx, "YAML merge keys (<<) are not supported; use defaults for shared settings")
		case seen[k.Value]:
			e.add(k.Line, ctx, "%s is set twice", k.Value)
		case known != nil && !slices.Contains(known, k.Value):
			e.add(k.Line, ctx, "unknown field %q%s", k.Value, suggest(k.Value, known))
		default:
			seen[k.Value] = true
			fn(k.Value, k, v)
		}
	}
}

// mapping reports whether n is a mapping, recording an error otherwise.
func mapping(e *errs, n *yaml.Node, ctx, what string) bool {
	if n.Kind != yaml.MappingNode {
		e.add(n.Line, ctx, "%s must be a mapping", what)
		return false
	}
	return true
}

// str returns the text of scalar n. A null value is the empty string.
func str(e *errs, n *yaml.Node, ctx, field string) string {
	if n.Kind != yaml.ScalarNode {
		e.add(n.Line, ctx, "%s must be a string", field)
		return ""
	}
	if isNull(n) {
		return ""
	}
	return n.Value
}

// strs returns the items of sequence n, which must be non-empty strings. A
// null value is an empty list.
func strs(e *errs, n *yaml.Node, ctx, field string) []string {
	if isNull(n) {
		return []string{}
	}
	if n.Kind != yaml.SequenceNode {
		e.add(n.Line, ctx, "%s must be a list", field)
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		item = resolve(item)
		if item.Kind != yaml.ScalarNode || isNull(item) || strings.TrimSpace(item.Value) == "" {
			e.add(item.Line, ctx, "%s must contain only non-empty strings", field)
			continue
		}
		out = append(out, item.Value)
	}
	return out
}
