package rules

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

const fixtureRuleset = `version: 1
rules:
  - id: burst
    when: event.type == "send" && account.sends_1m > 100
    action: throttle
    retry_after: 1m
    mode: enforce
    on_error: open
    reason: burst
  - id: young
    when: event.type == "send" && account.age_hours < 24
    action: flag
    reason: young
  - id: leaked
    when: event.type == "send" && event.api_key_id != "" && key.leaked
    action: block
    mode: enforce
    on_error: closed
    reason: leaked
`

func TestParseFixturesBaseAndOverrides(t *testing.T) {
	cases, err := ParseFixtures([]byte(`base:
  event: {type: send, api_key_id: k1, to_domains: [a.com], attributes: {plan: free}}
  account: {sends_1m: 1, age_hours: 100}
  key: {leaked: false}
cases:
  - name: base only
    expect: {action: allow}
  - name: override and add
    signals:
      account: {sends_1m: 150, custom: 7}
    expect: {action: throttle}
  - name: remove a signal and a map
    signals:
      account: {age_hours: null}
      key: null
    expect: {errors: [leaked]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 3 {
		t.Fatalf("got %d cases", len(cases))
	}
	base := cases[0].Signals
	if base.Event["type"] != "send" || !reflect.DeepEqual(base.Event["to_domains"], []string{"a.com"}) ||
		!reflect.DeepEqual(base.Event["attributes"], map[string]string{"plan": "free"}) {
		t.Errorf("base event = %v", base.Event)
	}
	// Signals take the types the catalog uses, however they are written.
	if base.Account["sends_1m"] != int64(1) || base.Account["age_hours"] != float64(100) || base.Key["leaked"] != false {
		t.Errorf("base types: account = %#v, key = %#v", base.Account, base.Key)
	}

	over := cases[1].Signals
	if over.Account["sends_1m"] != int64(150) || over.Account["age_hours"] != float64(100) || over.Account["custom"] != int64(7) {
		t.Errorf("override account = %#v", over.Account)
	}
	if base.Account["sends_1m"] != int64(1) {
		t.Error("a case modified the base")
	}

	removed := cases[2].Signals
	if _, ok := removed.Account["age_hours"]; ok || removed.Key != nil || removed.Account["sends_1m"] != int64(1) {
		t.Errorf("removal: account = %v, key = %v", removed.Account, removed.Key)
	}
	if cases[1].Line != 8 {
		t.Errorf("case line = %d, want 8", cases[1].Line)
	}
}

func TestParseFixturesExpectations(t *testing.T) {
	cases, err := ParseFixtures([]byte(`cases:
  - name: everything
    expect:
      action: throttle
      retry_after: 1m
      enforced: [burst]
      shadow: []
      matches: [burst]
      errors: []
  - name: zero retry
    expect: {retry_after: "0"}
`))
	if err != nil {
		t.Fatal(err)
	}
	x := cases[0].Expect
	if x.Action != decision.Throttle || x.RetryAfter == nil || *x.RetryAfter != time.Minute {
		t.Errorf("action/retry_after = %s/%v", x.Action, x.RetryAfter)
	}
	if !reflect.DeepEqual(x.Enforced, []string{"burst"}) || x.Shadow == nil || len(x.Shadow) != 0 || x.Errors == nil {
		t.Errorf("lists = %#v", x)
	}
	if cases[1].Expect.Enforced != nil || *cases[1].Expect.RetryAfter != 0 {
		t.Errorf("unset lists must stay nil: %#v", cases[1].Expect)
	}
}

func TestParseFixturesErrors(t *testing.T) {
	tests := []struct {
		name, src string
		want      []string
	}{
		{"empty", "", []string{"the file is empty"}},
		{"no cases", "base: {}\n", []string{"cases is required"}},
		{"cases not a list", "cases: {}\n", []string{"line 1: cases must be a list"}},
		{"unknown top-level field", "case: []\ncases: []\n", []string{`line 1: unknown field "case" (did you mean cases?)`}},
		{"missing name and expect", "cases:\n  - signals: {}\n", []string{"line 2: case #1: name is required", "line 2: case #1: expect is required"}},
		{"unknown case field", "cases:\n  - name: a\n    expected: {action: allow}\n", []string{`line 3: case "a": unknown field "expected" (did you mean expect?)`}},
		{"empty expect", "cases:\n  - name: a\n    expect: {}\n", []string{`line 3: case "a": expect must check something`}},
		{"unknown expectation", "cases:\n  - name: a\n    expect: {verdict: allow}\n", []string{`unknown field "verdict"`}},
		{"bad action", "cases:\n  - name: a\n    expect: {action: nuke}\n", []string{`expect.action: unknown action "nuke"`}},
		{"bad retry_after", "cases:\n  - name: a\n    expect: {retry_after: soon}\n", []string{`expect.retry_after must be a duration`}},
		{"unknown map", "cases:\n  - name: a\n    signals: {acount: {}}\n    expect: {action: allow}\n", []string{`line 3: case "a": unknown field "acount" (did you mean account?)`}},
		{"wrong signal type", "cases:\n  - name: a\n    signals:\n      account: {sends_1m: lots, age_hours: [1], new_ip: 1}\n      event: {to_domains: a.com, attributes: [x]}\n    expect: {action: allow}\n", []string{
			"line 4: case \"a\": account.sends_1m: want an integer",
			"account.age_hours: want a number",
			"account.new_ip: want true or false",
			"line 5: case \"a\": event.to_domains: want a list of strings",
			"event.attributes: want a mapping of strings",
		}},
		{"float for an integer", "cases:\n  - name: a\n    signals: {account: {sends_1m: 1.5}}\n    expect: {action: allow}\n", []string{"account.sends_1m: want an integer"}},
		{"duplicate names", "cases:\n  - name: a\n    expect: {action: allow}\n  - name: a\n    expect: {action: allow}\n", []string{`line 4: case "a": name is already used by the case on line 2`}},
		{"bad base", "base: {account: {sends_1m: x}}\ncases: []\n", []string{"line 1: base: account.sends_1m: want an integer"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFixtures([]byte(tt.src))
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not contain %q:\n%v", w, err)
				}
			}
		})
	}
}

func TestRunFixtures(t *testing.T) {
	rs := mustParse(t, fixtureRuleset)
	cases, err := ParseFixtures([]byte(`base:
  event: {type: send, api_key_id: k1}
  account: {sends_1m: 1, age_hours: 100}
  key: {leaked: false}
cases:
  - name: quiet
    expect: {action: allow, matches: [], errors: []}
  - name: burst from a young account
    signals: {account: {sends_1m: 150, age_hours: 2}}
    expect:
      action: throttle
      retry_after: 1m
      enforced: [burst]
      shadow: [young]
      matches: [young, burst]
  - name: store down
    signals: {account: null, key: null}
    expect:
      action: block
      enforced: [leaked]
      errors: [burst, young, leaked]
  - name: wrong on purpose
    signals: {account: {sends_1m: 150}}
    expect:
      action: block
      retry_after: 30s
      enforced: [leaked, burst]
      shadow: [young]
      matches: [burts]
      errors: []
  - name: forgot a signal
    signals: {account: {sends_1m: null}}
    expect: {matches: [burst]}
`))
	if err != nil {
		t.Fatal(err)
	}
	report := RunFixtures(rs, cases)
	if report.RulesetVersion != rs.Version() || len(report.Results) != 5 {
		t.Fatalf("report = %+v", report)
	}
	failed := report.Failed()
	if len(failed) != 2 || failed[0].Name != "wrong on purpose" || failed[1].Name != "forgot a signal" {
		t.Fatalf("failed = %+v", failed)
	}
	wantDiffs := []string{
		"unknown rule burts (did you mean burst?)",
		"action: want block, got throttle",
		"retry_after: want 30s, got 1m0s",
		"enforced: want [leaked, burst], got [burst] (missing leaked)",
		"shadow: want [young], got [] (missing young)",
		"matches: want [burts], got [burst] (missing burts; unexpected burst)",
	}
	if !reflect.DeepEqual(failed[0].Diffs, wantDiffs) {
		t.Errorf("diffs:\n got  %q\n want %q", failed[0].Diffs, wantDiffs)
	}
	wantDiffs = []string{
		"matches: want [burst], got [] (missing burst)",
		"note: rule burst failed to evaluate: signal account.sends_1m is absent",
	}
	if !reflect.DeepEqual(failed[1].Diffs, wantDiffs) {
		t.Errorf("diffs:\n got  %q\n want %q", failed[1].Diffs, wantDiffs)
	}

	err = report.Err()
	if err == nil || !strings.Contains(err.Error(), "2 of 5 fixture cases failed") ||
		!strings.Contains(err.Error(), "FAIL  wrong on purpose (line 22)") {
		t.Errorf("Err() = %v", err)
	}

	var b strings.Builder
	if err := report.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ok    quiet\n", "FAIL  forgot a signal (line 31)", "        action: want block, got throttle", "5 cases, 2 failed (ruleset " + rs.Version() + ")"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("WriteText output does not contain %q:\n%s", want, b.String())
		}
	}
}

func TestRunFixturesAllPass(t *testing.T) {
	rs := mustParse(t, fixtureRuleset)
	cases, err := ParseFixtures([]byte("cases:\n  - name: nothing\n    signals: {event: {type: feedback}}\n    expect: {action: allow}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := RunFixtures(rs, cases).Err(); err != nil {
		t.Errorf("Err() = %v", err)
	}
}

func TestLoadFixtures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cases.yaml")
	if err := os.WriteFile(path, []byte("cases:\n  - name: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFixtures(path); err == nil || !strings.Contains(err.Error(), path+`:2: case "a": expect is required`) {
		t.Errorf("error = %v", err)
	}
	if _, err := LoadFixtures(path + ".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: error = %v", err)
	}
}
