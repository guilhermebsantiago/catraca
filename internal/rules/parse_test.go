package rules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// mustParse parses src or fails the test.
func mustParse(t *testing.T, src string) *Ruleset {
	t.Helper()
	rs, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse:\n%v", err)
	}
	return rs
}

const designExample = `version: 1
defaults:
  mode: shadow        # new rules never enforce by accident
  on_error: open
lists:
  url_shorteners: [bit.ly, tinyurl.com, t.co, is.gd]
rules:
  - id: leaked-key-send
    description: A key reported leaked is used to send
    when: event.type == "send" && key.leaked
    action: block
    mode: enforce
    on_error: closed
    effects: [revoke_key]
    reason: API key was found in public and must be rotated
  - id: new-account-burst
    when: event.type == "send" && account.age_hours < 24.0 && account.sends_1m > 100
    action: throttle
    retry_after: 60s
    reason: New account sending at burst volume
`

func TestParseDesignExample(t *testing.T) {
	rs := mustParse(t, designExample)

	if len(rs.Rules()) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs.Rules()))
	}
	leaked, ok := rs.Rule("leaked-key-send")
	if !ok {
		t.Fatal("leaked-key-send not found")
	}
	if leaked.Action != decision.Block || leaked.Mode != decision.Enforce || leaked.OnError != decision.FailClosed {
		t.Errorf("leaked-key-send = %s/%s/%s, want block/enforce/closed", leaked.Action, leaked.Mode, leaked.OnError)
	}
	if leaked.Line != 8 {
		t.Errorf("leaked-key-send line = %d, want 8", leaked.Line)
	}
	burst, _ := rs.Rule("new-account-burst")
	if burst.Mode != decision.Shadow || burst.OnError != decision.FailOpen {
		t.Errorf("new-account-burst defaults = %s/%s, want shadow/open", burst.Mode, burst.OnError)
	}
	if burst.RetryAfter != time.Minute {
		t.Errorf("retry_after = %s, want 1m", burst.RetryAfter)
	}
	if got := rs.Lists()["url_shorteners"]; len(got) != 4 {
		t.Errorf("url_shorteners = %v", got)
	}
	if len(rs.Version()) != 12 {
		t.Errorf("version %q is not 12 hex characters", rs.Version())
	}
	if _, ok := rs.Rule("missing"); ok {
		t.Error("Rule(missing) found something")
	}
}

func TestParseDefaults(t *testing.T) {
	t.Run("shadow and open when nothing is set", func(t *testing.T) {
		rs := mustParse(t, "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n")
		r := rs.Rules()[0]
		if r.Mode != decision.Shadow || r.OnError != decision.FailOpen || r.Action != decision.Flag {
			t.Errorf("got %s/%s/%s, want shadow/open/flag", r.Mode, r.OnError, r.Action)
		}
	})
	t.Run("defaults apply wherever they appear", func(t *testing.T) {
		rs := mustParse(t, "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\ndefaults:\n  mode: enforce\n  on_error: closed\n")
		r := rs.Rules()[0]
		if r.Mode != decision.Enforce || r.OnError != decision.FailClosed {
			t.Errorf("got %s/%s, want enforce/closed", r.Mode, r.OnError)
		}
	})
	t.Run("rule fields win over defaults", func(t *testing.T) {
		rs := mustParse(t, "version: 1\ndefaults: {mode: enforce, on_error: closed}\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    mode: shadow\n    on_error: open\n")
		r := rs.Rules()[0]
		if r.Mode != decision.Shadow || r.OnError != decision.FailOpen {
			t.Errorf("got %s/%s, want shadow/open", r.Mode, r.OnError)
		}
	})
}

func TestParseOptionalFields(t *testing.T) {
	rs := mustParse(t, `version: 1
rules:
  - id: held
    description: |
      Several lines
      of description.
    when: |
      event.type == "send" &&
        account.sends_1h > 10
    action: hold
    mode: enforce
    on_error: open
    effects: [notify, suspend_account]
    reason: "  padded  "
    owner: abuse-team
    tags: [volume, test]
    override:
      by: alice
      reason: measured offline
      at: 2026-09-01
`)
	r := rs.Rules()[0]
	if r.Description != "Several lines\nof description." {
		t.Errorf("description = %q", r.Description)
	}
	if r.Reason != "padded" {
		t.Errorf("reason = %q, want it trimmed", r.Reason)
	}
	if r.Owner != "abuse-team" || len(r.Tags) != 2 || len(r.Effects) != 2 {
		t.Errorf("owner/tags/effects = %q/%v/%v", r.Owner, r.Tags, r.Effects)
	}
	want := &Override{By: "alice", Reason: "measured offline", At: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	if r.Override == nil || *r.Override != *want {
		t.Errorf("override = %+v, want %+v", r.Override, want)
	}
}

func TestParseOverrideRFC3339(t *testing.T) {
	rs := mustParse(t, "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    mode: enforce\n    on_error: open\n    override: {by: bob, reason: why, at: \"2026-09-01T10:30:00-03:00\"}\n")
	if got, want := rs.Rules()[0].Override.At, time.Date(2026, 9, 1, 13, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("at = %s, want %s", got, want)
	}
}

func TestParseEmptyRules(t *testing.T) {
	for _, src := range []string{"version: 1\nrules: []\n", "version: 1\nrules:\n"} {
		rs := mustParse(t, src)
		if len(rs.Rules()) != 0 {
			t.Errorf("%q: got %d rules", src, len(rs.Rules()))
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		// want are substrings expected in the error, each with its line.
		want []string
	}{
		{"empty file", "", []string{"the file is empty"}},
		{"syntax error", "version: 1\nrules: [\n", []string{"line 2: did not find expected node content"}},
		{"not a mapping", "- a\n- b\n", []string{"line 1: a ruleset must be a mapping"}},
		{"missing version and rules", "lists: {}\n", []string{"version is required", "rules is required"}},
		{"wrong version", "version: 2\nrules: []\n", []string{"line 1: version must be 1"}},
		{"unknown top-level field", "version: 1\nrules: []\nrule: []\n", []string{`line 3: unknown field "rule" (did you mean rules?)`}},
		{"repeated field", "version: 1\nrules: []\nrules: []\n", []string{"line 3: rules is set twice"}},
		{"unknown defaults field", "version: 1\ndefaults: {action: block}\nrules: []\n", []string{`line 2: defaults: unknown field "action"`}},
		{"bad default mode", "version: 1\ndefaults: {mode: loud}\nrules: []\n", []string{`line 2: defaults: unknown mode "loud"`}},
		{"bad default on_error", "version: 1\ndefaults: {on_error: maybe}\nrules: []\n", []string{`line 2: defaults: unknown on_error "maybe"`}},
		{"bad list name", "version: 1\nlists: {Bad-Name: [a]}\nrules: []\n", []string{`line 2: lists: list name "Bad-Name"`}},
		{"list is not a list", "version: 1\nlists: {a: b}\nrules: []\n", []string{"line 2: list a: a list must be a list"}},
		{"empty list item", "version: 1\nlists:\n  a: [x, '']\nrules: []\n", []string{"line 3: list a: a list must contain only non-empty strings"}},
		{"rules not a list", "version: 1\nrules: {}\n", []string{"line 2: rules must be a list"}},
		{"rule not a mapping", "version: 1\nrules:\n  - just text\n", []string{"line 3: rule #1: a rule must be a mapping"}},
		{"missing required fields", "version: 1\nrules:\n  - description: nothing else\n", []string{
			"line 3: rule #1: id is required", "line 3: rule #1: when is required", "line 3: rule #1: reason is required",
		}},
		{"id not kebab-case", "version: 1\nrules:\n  - id: Not_Kebab\n    when: 'true'\n    reason: r\n", []string{"line 3: rule Not_Kebab: id must be kebab-case"}},
		{"id with trailing dash", "version: 1\nrules:\n  - id: bad-\n    when: 'true'\n    reason: r\n", []string{"id must be kebab-case"}},
		{"duplicate id", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n  - id: a\n    when: 'true'\n    reason: r\n", []string{
			"line 6: rule a: id is already used by the rule on line 3",
		}},
		{"unknown rule field with suggestion", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    retry: 5s\n", []string{
			`line 6: rule a: unknown field "retry" (did you mean retry_after?)`,
		}},
		{"typo in rule field", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    on_eror: open\n", []string{
			`unknown field "on_eror" (did you mean on_error?)`,
		}},
		{"merge keys", "version: 1\nrules:\n  - id: a\n    <<: {when: 'true'}\n    reason: r\n", []string{"line 4: rule a: YAML merge keys"}},
		{"unknown action", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    action: nuke\n", []string{`line 6: rule a: unknown action "nuke"`}},
		{"allow is not an action", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    action: allow\n", []string{"line 6: rule a: allow is not a rule action"}},
		{"unknown mode", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    mode: maybe\n", []string{`line 6: rule a: unknown mode "maybe"`}},
		{"unknown on_error", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    on_error: ajar\n", []string{`line 6: rule a: unknown on_error "ajar"`}},
		{"throttle without retry_after", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    action: throttle\n", []string{"line 3: rule a: throttle rules need retry_after"}},
		{"retry_after on a block rule", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    action: block\n    retry_after: 5s\n", []string{"line 7: rule a: retry_after is only for throttle rules"}},
		{"bad retry_after", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    action: throttle\n    retry_after: soon\n", []string{`line 7: rule a: retry_after must be a positive duration`}},
		{"negative retry_after", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    action: throttle\n    retry_after: -5s\n", []string{"retry_after must be a positive duration"}},
		{"bad effect name", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    effects: [Revoke-Key]\n", []string{`line 6: rule a: effect "Revoke-Key"`}},
		{"repeated effect", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    effects: [notify, notify]\n", []string{"effect notify is listed twice"}},
		{"effects not a list", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    effects: notify\n", []string{"line 6: rule a: effects must be a list"}},
		{"override missing fields", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    override: {by: alice}\n", []string{
			"override.reason is required", "override.at is required",
		}},
		{"override unknown field", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    override: {by: a, reason: b, at: 2026-01-01, when: now}\n", []string{`rule a: unknown field "when"`}},
		{"override bad date", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    override: {by: a, reason: b, at: yesterday}\n", []string{`override.at must be a date`}},
		{"override not a mapping", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    override: yes\n", []string{"override must be a mapping"}},
		{"description is a list", "version: 1\nrules:\n  - id: a\n    when: 'true'\n    reason: r\n    description: [a]\n", []string{"description must be a string"}},
		{"CEL syntax error", "version: 1\nrules:\n  - id: a\n    when: event.type ==\n    reason: r\n", []string{"line 4: rule a: when:"}},
		{"CEL undeclared reference", "version: 1\nrules:\n  - id: a\n    when: event.type == send\n    reason: r\n", []string{"line 4: rule a: when: undeclared reference to 'send' (at column 15 of the expression)"}},
		{"CEL error on a later line of a block", "version: 1\nrules:\n  - id: a\n    when: |\n      event.type == \"send\" &&\n        nope > 1\n    reason: r\n", []string{"line 6: rule a: when: undeclared reference to 'nope'"}},
		{"non-bool when", "version: 1\nrules:\n  - id: a\n    when: account.sends_1m + 1\n    reason: r\n", []string{"line 4: rule a: when must return a bool, not int"}},
		{"unknown list", "version: 1\nlists: {url_shorteners: [bit.ly]}\nrules:\n  - id: a\n    when: in_list(\"url_shortener\", event.from_domain)\n    reason: r\n", []string{
			`line 5: rule a: when: in_list: unknown list "url_shortener" (did you mean url_shorteners?)`,
		}},
		{"list name not a literal", "version: 1\nlists: {l: [a]}\nrules:\n  - id: a\n    when: any_in_list(event.type, event.to_domains)\n    reason: r\n", []string{
			"any_in_list: the list name must be a string literal",
		}},
		{"unknown function", "version: 1\nrules:\n  - id: a\n    when: is_spam(event)\n    reason: r\n", []string{"undeclared reference to 'is_spam'"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src))
			if err == nil {
				t.Fatal("Parse succeeded, want an error")
			}
			var list ErrorList
			if !errors.As(err, &list) {
				t.Fatalf("error is %T, want ErrorList: %v", err, err)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not contain %q:\n%v", w, err)
				}
			}
		})
	}
}

func TestParseReportsEveryError(t *testing.T) {
	_, err := Parse([]byte(`version: 1
rules:
  - id: one
    when: nope
    reason: r
  - id: two
    reason: r
  - id: three
    when: 'true'
    action: nuke
    reason: r
`))
	var list ErrorList
	if !errors.As(err, &list) || len(list) != 3 {
		t.Fatalf("want 3 errors, got:\n%v", err)
	}
	for i, line := range []int{4, 6, 10} {
		if list[i].Line != line {
			t.Errorf("error %d is on line %d, want %d: %v", i, list[i].Line, line, list[i])
		}
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nrules:\n  - id: a\n    reason: r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), path+":3: rule a: when is required") {
		t.Errorf("error = %v, want it to name the file and line", err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: error = %v, want os.ErrNotExist", err)
	}
}

func TestVersion(t *testing.T) {
	base := mustParse(t, designExample)

	t.Run("comments, formatting and key order do not change it", func(t *testing.T) {
		reformatted := mustParse(t, `# a comment
version: 1
lists:
  url_shorteners:
    - bit.ly
    - tinyurl.com
    - t.co
    - is.gd
defaults: {on_error: open, mode: shadow}
rules:
  - reason: API key was found in public and must be rotated
    id: leaked-key-send
    when: >-
      event.type == "send" && key.leaked
    description: A key reported leaked is used to send
    action: block
    mode: enforce
    effects:
      - revoke_key
    on_error: closed
  - id: new-account-burst
    when: event.type == "send" && account.age_hours < 24.0 && account.sends_1m > 100
    action: throttle
    retry_after: 1m
    reason: New account sending at burst volume
`)
		if reformatted.Version() != base.Version() {
			t.Errorf("version changed from %s to %s", base.Version(), reformatted.Version())
		}
	})
	t.Run("an equivalent default does not change it", func(t *testing.T) {
		explicit := mustParse(t, strings.Replace(designExample, "    reason: New account sending at burst volume\n",
			"    reason: New account sending at burst volume\n    mode: shadow\n    on_error: open\n", 1))
		if explicit.Version() != base.Version() {
			t.Errorf("version changed from %s to %s", base.Version(), explicit.Version())
		}
	})
	for name, change := range map[string][2]string{
		"a threshold":  {"sends_1m > 100", "sends_1m > 101"},
		"a mode":       {"    mode: enforce\n", "    mode: shadow\n"},
		"a reason":     {"must be rotated", "must be revoked"},
		"a list entry": {"is.gd]", "is.gd, v.gd]"},
		"a default":    {"  mode: shadow ", "  mode: enforce "},
	} {
		t.Run(name+" changes it", func(t *testing.T) {
			changed := mustParse(t, strings.Replace(designExample, change[0], change[1], 1))
			if changed.Version() == base.Version() {
				t.Errorf("version stayed %s after changing %s", base.Version(), name)
			}
		})
	}
}

func TestRulesetMarshalJSON(t *testing.T) {
	rs := mustParse(t, designExample)
	data, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version string              `json:"version"`
		Format  int                 `json:"format"`
		Lists   map[string][]string `json:"lists"`
		Rules   []map[string]any    `json:"rules"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != rs.Version() || got.Format != 1 || len(got.Lists["url_shorteners"]) != 4 || len(got.Rules) != 2 {
		t.Errorf("unexpected JSON: %s", data)
	}
	burst := got.Rules[1]
	if burst["retry_after"] != "1m0s" || burst["mode"] != "shadow" || burst["on_error"] != "open" {
		t.Errorf("new-account-burst JSON = %v, want retry_after 1m0s with defaults applied", burst)
	}
	if _, ok := got.Rules[0]["retry_after"]; ok {
		t.Errorf("leaked-key-send JSON has retry_after: %v", got.Rules[0])
	}
}

func TestErrorFormat(t *testing.T) {
	tests := []struct {
		err  Error
		want string
	}{
		{Error{File: "r.yaml", Line: 3, Where: "rule a", Msg: "bad"}, "r.yaml:3: rule a: bad"},
		{Error{File: "r.yaml", Msg: "bad"}, "r.yaml: bad"},
		{Error{Line: 3, Msg: "bad"}, "line 3: bad"},
		{Error{Msg: "bad"}, "bad"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
}
