package rules

import (
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/signal"
)

func TestKnownSignalsMatchCatalog(t *testing.T) {
	catalog := map[string]bool{}
	for _, s := range signal.Specs() {
		catalog[s.Map+"."+s.Name] = true
	}
	for m, names := range knownSignals {
		for n := range names {
			if !catalog[m+"."+n] {
				t.Errorf("rules knows %s.%s but the catalog does not produce it", m, n)
			}
		}
	}
	for name := range catalog {
		found := false
		for m, names := range knownSignals {
			for n := range names {
				if m+"."+n == name {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("the catalog produces %s but rules does not know it", name)
		}
	}
}
