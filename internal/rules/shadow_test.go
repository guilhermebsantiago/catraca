package rules

import (
	"errors"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// TestWithShadow checks that a copy with rules held in shadow decides as
// the file would with those rules written in shadow mode, has the version
// that file would have, and leaves the original alone.
func TestWithShadow(t *testing.T) {
	rs := mustParse(t, designExample)
	held, err := rs.WithShadow("leaked-key-send", "no-such-rule")
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := held.Rule("leaked-key-send"); r.Mode != decision.Shadow {
		t.Errorf("held rule mode = %s, want shadow", r.Mode)
	}
	if r, _ := rs.Rule("leaked-key-send"); r.Mode != decision.Enforce {
		t.Errorf("the original changed: mode = %s", r.Mode)
	}
	if held.Rules()[1] != rs.Rules()[1] {
		t.Error("a rule that is not held was copied")
	}

	// The same ruleset written with the rule in shadow mode.
	written := mustParse(t, strings.Replace(designExample, "    mode: enforce\n", "    mode: shadow\n", 1))
	if held.Version() != written.Version() || held.Version() == rs.Version() {
		t.Errorf("version %s, want %s as written in shadow mode, not the file's %s", held.Version(), written.Version(), rs.Version())
	}

	set := signal.Set{
		Event:   map[string]any{"type": "send"},
		Account: map[string]any{"age_hours": 100.0, "sends_1m": int64(1)},
		Key:     map[string]any{"leaked": true},
	}
	if out := rs.Apply(set); out.Action != decision.Block {
		t.Fatalf("file: action %s, want block", out.Action)
	}
	out := held.Apply(set)
	if out.Action != decision.Allow || len(out.Matches) != 0 || len(out.Shadow) != 1 || out.Shadow[0].RuleID != "leaked-key-send" {
		t.Errorf("held: %+v, want allow with leaked-key-send matched in shadow", out)
	}

	if same, err := rs.WithShadow(); err != nil || same != rs {
		t.Errorf("WithShadow() = %p, %v; want the ruleset itself", same, err)
	}
}

func TestParseFile(t *testing.T) {
	rs, err := ParseFile([]byte(designExample), "rules.yaml")
	if err != nil || rs.Version() != mustParse(t, designExample).Version() {
		t.Fatalf("ParseFile = %v, %v", rs, err)
	}
	_, err = ParseFile([]byte("version: 1\nrules: [oops\n"), "rules.yaml")
	var list ErrorList
	if !errors.As(err, &list) || !strings.HasPrefix(list.Error(), "rules.yaml:") {
		t.Errorf("error %v, want an ErrorList naming the file", err)
	}
}
