package rules

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// These tests catch drift between the catalog's signal list and what rules
// assume about it.

func TestEverySignalTypeHasAKind(t *testing.T) {
	for _, s := range signal.Specs() {
		if _, ok := kindOfType[s.Type]; !ok {
			t.Errorf("%s.%s has type %q, which rules has no kind for: add it to kindOfType", s.Map, s.Name, s.Type)
		}
	}
}

func TestKnownSignalsAreTheCatalogs(t *testing.T) {
	specs := signal.Specs()
	n := 0
	for _, names := range knownSignals {
		n += len(names)
	}
	if n != len(specs) {
		t.Errorf("rules knows %d signals, the catalog produces %d", n, len(specs))
	}
	for _, s := range specs {
		if _, ok := knownSignals[s.Map][s.Name]; !ok {
			t.Errorf("rules does not know %s.%s", s.Map, s.Name)
		}
	}
}

// TestSignalMapsAreVariables checks that every map the catalog fills is a
// CEL variable rules can read, and the other way round. The entity map holds
// a map per configured entity, whose signals are signal.EntitySpecs.
func TestSignalMapsAreVariables(t *testing.T) {
	got := slices.Sorted(maps.Keys(knownSignals))
	got = append(got, "entity")
	slices.Sort(got)
	want := slices.Sorted(slices.Values(variables))
	if !slices.Equal(got, want) {
		t.Errorf("signal maps = %v, CEL variables = %v", got, want)
	}
}

func TestPresenceGuardsAreSignals(t *testing.T) {
	for _, g := range presenceGuards {
		if _, ok := knownSignals[g.Map]; !ok {
			t.Errorf("presence guard for unknown map %q", g.Map)
		}
		if kind := knownSignals["event"][g.Guard]; kind != kindString {
			t.Errorf("presence guard of %s is event.%s, which is not a string event signal", g.Map, g.Guard)
		}
	}
}

// TestFixtureValuesHaveCatalogTypes checks that a fixture value for each
// signal gets the Go type the catalog produces for its CEL type.
func TestFixtureValuesHaveCatalogTypes(t *testing.T) {
	samples := map[string]struct {
		yaml string
		want reflect.Type
	}{
		"int":                 {"3", reflect.TypeFor[int64]()},
		"double":              {"3", reflect.TypeFor[float64]()},
		"bool":                {"true", reflect.TypeFor[bool]()},
		"string":              {"x", reflect.TypeFor[string]()},
		"list(string)":        {"[a, b]", reflect.TypeFor[[]string]()},
		"map(string, string)": {"{a: b}", reflect.TypeFor[map[string]string]()},
	}
	for _, s := range signal.Specs() {
		sample, ok := samples[s.Type]
		if !ok {
			t.Errorf("%s.%s: no sample for type %q", s.Map, s.Name, s.Type)
			continue
		}
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(sample.yaml), &doc); err != nil {
			t.Fatal(err)
		}
		v, err := signalValue(doc.Content[0], knownSignals[s.Map][s.Name])
		if err != nil {
			t.Errorf("%s.%s: %v", s.Map, s.Name, err)
			continue
		}
		if got := reflect.TypeOf(v); got != sample.want {
			t.Errorf("%s.%s: fixture value is a %v, the catalog's is a %v", s.Map, s.Name, got, sample.want)
		}
	}
}
