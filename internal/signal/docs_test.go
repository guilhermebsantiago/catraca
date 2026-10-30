package signal

import (
	"bufio"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	// docMapHeading opens the table of one map's signals: "## `account`".
	docMapHeading = regexp.MustCompile("^## `([a-z]+)`$")
	// docSignalRow is a row of that table: "| `sends_1m` | int | ...".
	docSignalRow = regexp.MustCompile("^\\| `([a-z0-9_]+)` \\| ([a-z(), ]+?) \\|")
	// docSignalRef is a signal named anywhere in the text: `key.leaked`.
	docSignalRef = regexp.MustCompile("`(event|account|key|ip|domain)\\.([a-z0-9_]+)`")
)

// docEventFields are names in docs/signals.md that look like signals but
// are fields of the event as the platform sends it.
var docEventFields = []string{"account.action", "account.created_at"}

// TestSpecsAreDocumented keeps docs/signals.md and Specs in step: every
// signal the catalog produces is in its map's table with its type, every
// row of those tables is a signal, and every map.name the page mentions
// exists.
func TestSpecsAreDocumented(t *testing.T) {
	f, err := os.Open("../../docs/signals.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	documented := map[string]string{} // "map.name" to type
	var refs []string
	var section string // the map whose table is being read, if any
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		for _, m := range docSignalRef.FindAllStringSubmatch(text, -1) {
			refs = append(refs, m[1]+"."+m[2])
		}
		if strings.HasPrefix(text, "#") {
			section = ""
			if m := docMapHeading.FindStringSubmatch(text); m != nil {
				section = m[1]
			}
			continue
		}
		if section == "" {
			continue
		}
		if m := docSignalRow.FindStringSubmatch(text); m != nil {
			name := section + "." + m[1]
			if _, ok := documented[name]; ok {
				t.Errorf("docs/signals.md:%d: %s is documented twice", line, name)
			}
			documented[name] = m[2]
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	produced := map[string]string{}
	// Every declared entity has the same signals, under entity.<name>; the
	// page documents them once, in the entity table.
	for _, s := range append(Specs(), EntitySpecs()...) {
		name := s.Map + "." + s.Name
		produced[name] = s.Type
		switch typ, ok := documented[name]; {
		case !ok:
			t.Errorf("%s is not in the %s table of docs/signals.md", name, s.Map)
		case typ != s.Type:
			t.Errorf("docs/signals.md gives %s type %s, the catalog %s", name, typ, s.Type)
		}
	}
	for name := range documented {
		if _, ok := produced[name]; !ok {
			t.Errorf("docs/signals.md documents %s, which the catalog does not produce", name)
		}
	}
	for _, name := range refs {
		if _, ok := produced[name]; !ok && !slices.Contains(docEventFields, name) {
			t.Errorf("docs/signals.md names %s, which the catalog does not produce", name)
		}
	}
	if len(documented) == 0 {
		t.Fatal("no signal tables found in docs/signals.md; did its headings change?")
	}
}
