package rules

import "github.com/guilhermebsantiago/catraca/internal/signal"

// signalKind is the Go type a signal has in a signal.Set.
type signalKind int

const (
	kindInt       signalKind = iota + 1 // int64
	kindFloat                           // float64
	kindBool                            // bool
	kindString                          // string
	kindStrings                         // []string
	kindStringMap                       // map[string]string
)

func (k signalKind) String() string {
	switch k {
	case kindInt:
		return "an integer"
	case kindFloat:
		return "a number"
	case kindBool:
		return "true or false"
	case kindString:
		return "a string"
	case kindStrings:
		return "a list of strings"
	case kindStringMap:
		return "a mapping of strings"
	}
	return "unknown"
}

// kindOfType maps the CEL types of signal.Spec to kinds.
var kindOfType = map[string]signalKind{
	"int":                 kindInt,
	"double":              kindFloat,
	"bool":                kindBool,
	"string":              kindString,
	"list(string)":        kindStrings,
	"map(string, string)": kindStringMap,
}

// knownSignals are the signals the catalog computes, by map and name, built
// from signal.Specs so the two cannot disagree. Lint warns about rules that
// read anything else, since such a rule always fails to evaluate, and
// fixtures use the kinds to give values the types the catalog produces
// (age_hours: 2 becomes float64(2)).
var knownSignals = indexSpecs(signal.Specs())

// entitySignals are the signals of every entity, by name: what
// entity.<name>.<signal> may read.
var entitySignals = indexSpecs(signal.EntitySpecs())["entity"]

func indexSpecs(specs []signal.Spec) map[string]map[string]signalKind {
	out := map[string]map[string]signalKind{}
	for _, s := range specs {
		if out[s.Map] == nil {
			out[s.Map] = map[string]signalKind{}
		}
		// A type missing from kindOfType gets kind 0, and fixtures guess
		// its kind from the YAML value; a test keeps that from happening.
		out[s.Map][s.Name] = kindOfType[s.Type]
	}
	return out
}

// presenceGuards name, for each map that is absent on some events, the event
// signal that says whether it is present. They describe the catalog's
// behavior rather than its signal list, so they are kept here, on top of
// signal.Specs; a test checks that they name known signals.
var presenceGuards = []struct{ Map, Guard string }{
	{"key", "api_key_id"},
	{"ip", "ip"},
	{"domain", "from_domain"},
}
