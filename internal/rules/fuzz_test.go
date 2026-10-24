package rules

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// addFiles adds the contents of files, relative to this package, as seeds.
func addFiles(f *testing.F, files ...string) {
	f.Helper()
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
}

// FuzzParse parses any YAML as a ruleset. Parse never panics; it either
// fails with an ErrorList whose entries say something, or returns a
// compiled ruleset whose version is stable and which evaluates, lints and
// encodes without panicking.
func FuzzParse(f *testing.F) {
	addFiles(f, defaultRuleset, "../../examples/demo/rules.yaml")
	for _, seed := range []string{
		combineRuleset,
		"",
		"version: 1\nrules: []\n",
		"version: 1\nrules:\n",
		"version: 2\nrules: []\n",
		"version: 1\nlists:\n  l: &a [x, y]\n  m: *a\nrules:\n  - &r {id: r, when: 'in_list(\"l\", \"x\")', reason: r}\n  - *r\n",
		"version: 1\ndefaults: {mode: enforce, on_error: closed}\nrules:\n  - id: t\n    when: |\n      account.sends_1m >\n        100\n    action: throttle\n    retry_after: 90s\n    reason: slow\n",
		"version: 1\nrules:\n  - id: o\n    when: key.leaked\n    reason: o\n    mode: enforce\n    override: {by: me, reason: urgent, at: 2026-10-15}\n",
		"version: 1\nrules:\n  - id: bad\n    when: 'in_list(event.type, \"x\")'\n    reason: x\n  - {id: Bad_Id, when: '1 +', action: allow, reason: ''}\n",
		"version: 1\nrules:\n  - <<: {id: m}\n    when: true\n",
		"[1, 2, 3]",
		"version: 1\nrules: {a: b}\n",
		"version: 1\nrules:\n  - id: big\n    when: '" + strings.Repeat("(", 300) + "true" + strings.Repeat(")", 300) + "'\n    reason: deep\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rs, err := Parse(data)
		if err != nil {
			var list ErrorList
			if !errors.As(err, &list) || len(list) == 0 {
				t.Fatalf("Parse error %v (%T) is not a non-empty ErrorList", err, err)
			}
			for _, e := range list {
				if e.Msg == "" {
					t.Errorf("an error without a message: %+v", e)
				}
			}
			return
		}
		again, err := Parse(data)
		if err != nil || again.Version() != rs.Version() {
			t.Fatalf("parsing again: version %q, error %v; first version %q", again.Version(), err, rs.Version())
		}
		for _, r := range rs.Rules() {
			if r.program == nil {
				t.Errorf("rule %s has no program", r.ID)
			}
		}
		if _, err := rs.MarshalJSON(); err != nil {
			t.Errorf("MarshalJSON: %v", err)
		}
		rs.Lint()
		checkOutcome(t, rs, rs.Evaluate(signal.Set{}))
		checkOutcome(t, rs, rs.Evaluate(everySignal()))
	})
}

// FuzzParseFixtures parses any YAML as a fixture file and runs what parses
// against the starter ruleset.
func FuzzParseFixtures(f *testing.F) {
	addFiles(f, defaultFixtures)
	for _, seed := range []string{
		"cases: []\n",
		"base:\n  event: {type: send}\ncases:\n  - name: a\n    signals: {account: {sends_1m: 5, age_hours: 1.5, new_ip: true}}\n    expect: {action: allow, matches: []}\n",
		"cases:\n  - name: b\n    signals:\n      event: {to_domains: [a.example], attributes: {plan: free}}\n      key: {leaked: true}\n    expect: {action: block, retry_after: 30s, enforced: [leaked-key-send], errors: []}\n",
		"cases:\n  - name: c\n    signals: {account: {sends_1m: [1, 2]}}\n  - name: c\n",
	} {
		f.Add([]byte(seed))
	}
	rs, err := LoadFile(defaultRuleset)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cases, err := ParseFixtures(data)
		if err != nil {
			var list ErrorList
			if !errors.As(err, &list) || len(list) == 0 {
				t.Fatalf("ParseFixtures error %v (%T) is not a non-empty ErrorList", err, err)
			}
			return
		}
		report := RunFixtures(rs, cases)
		_ = report.WriteText(io.Discard)
		if len(report.Results) != len(cases) {
			t.Errorf("report has %d cases, want %d", len(report.Results), len(cases))
		}
		for _, c := range cases {
			checkOutcome(t, rs, rs.Evaluate(c.Signals))
		}
	})
}

// FuzzEvaluate compiles an expression into four rules, one per mode and
// on_error policy, and evaluates it, and the starter ruleset, over a signal
// set generated from data, with signals missing and of every type, expected
// or not. Nothing panics, the four rules agree, and each rule's on_error
// decides what an error does.
func FuzzEvaluate(f *testing.F) {
	for _, when := range []string{
		`event.type == "send" && account.age_hours < 24.0 && account.sends_1m > 100`,
		`key.leaked`,
		`account.sends_1m`,
		`in_list("shorteners", event.from_domain)`,
		`any_in_list("shorteners", event.link_domains)`,
		`any_in_list("shorteners", event.attributes)`,
		`domain_of(event.from_domain) == "x"`,
		`ratio(account.complaints_24h, account.sends_24h) > 0.003`,
		`event.to_domains.exists(d, d.endsWith("yahoo.com"))`,
		`size(event.to_domains) == event.recipients`,
		`event.attributes.plan == "free"`,
		`account.?sends_7d.orValue(0) == 0`,
		`has(account.sends_7d) || account.new_ip`,
		`event.type == "feedback" && account.sends_7d > 1`,
		`account["sends_" + event.type] > 0`,
		`int(account.age_hours) > 1 && double(account.sends_1m) < 1e300`,
		`account.sends_1m / account.sends_1h > 0`,
		`event.recipients % 0 == 1`,
		`event.to_domains[3] == "x"`,
		`[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, [1,2,3,4,5,6,7,8,9,10].all(d, a+b+c+d > 0))))`,
		`event.attributes.map(k, event.attributes[k]).size() > 2`,
		`string(account.sends_1m) == "5" && bool(key.leaked)`,
		`dyn(event.recipients) == dyn("1")`,
	} {
		f.Add(when, []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"))
		f.Add(when, []byte{})
	}
	starter, err := LoadFile(defaultRuleset)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, when string, data []byte) {
		set := generateSignals(data)
		checkOutcome(t, starter, starter.Evaluate(set))

		if !utf8.ValidString(when) {
			return
		}
		rs, err := Parse([]byte(fmt.Sprintf(policyRuleset, when)))
		if err != nil {
			return
		}
		results := rs.Evaluate(set)
		first := results[0]
		for _, res := range results[1:] {
			if res.Matched != first.Matched || (res.Err == nil) != (first.Err == nil) {
				t.Fatalf("one expression, one set, two results: %s %v %v, %s %v %v",
					first.Rule.ID, first.Matched, first.Err, res.Rule.ID, res.Matched, res.Err)
			}
		}
		if first.Err != nil && first.Matched {
			t.Errorf("an errored rule matched")
		}
		out := checkOutcome(t, rs, results)
		var enforced, shadow, errored []string
		for _, m := range out.Matches {
			enforced = append(enforced, m.RuleID)
		}
		for _, m := range out.Shadow {
			shadow = append(shadow, m.RuleID)
		}
		for _, e := range out.Errors {
			errored = append(errored, e.RuleID)
		}
		want := struct {
			action                    decision.Action
			enforced, shadow, errored []string
		}{action: decision.Allow}
		switch {
		case first.Err != nil:
			// Open skips the rule; closed matches it, without effects.
			want.action = decision.Block
			want.enforced, want.shadow = []string{"closed-enforce"}, []string{"closed-shadow"}
			want.errored = []string{"open-enforce", "closed-enforce", "open-shadow", "closed-shadow"}
		case first.Matched:
			want.action = decision.Block
			want.enforced, want.shadow = []string{"open-enforce", "closed-enforce"}, []string{"open-shadow", "closed-shadow"}
		}
		if out.Action != want.action || !slices.Equal(enforced, want.enforced) || !slices.Equal(shadow, want.shadow) || !slices.Equal(errored, want.errored) {
			t.Fatalf("outcome %s enforced %v shadow %v errors %v; want %s %v %v %v (matched %v, error %v)",
				out.Action, enforced, shadow, errored, want.action, want.enforced, want.shadow, want.errored, first.Matched, first.Err)
		}
		d := decision.Decision{Matches: out.Matches}
		if wantEffects := first.Err == nil && first.Matched; (len(d.Effects()) > 0) != wantEffects {
			t.Errorf("effects %v with matched %v and error %v", d.Effects(), first.Matched, first.Err)
		}
	})
}

// policyRuleset holds one expression, %q, in a rule per mode and on_error.
// The expression is a YAML double-quoted string, whose escapes include Go's.
const policyRuleset = `version: 1
lists:
  shorteners: [bit.ly, t.co]
rules:
  - {id: open-enforce, when: %[1]q, mode: enforce, on_error: open, action: hold, reason: r}
  - {id: closed-enforce, when: %[1]q, mode: enforce, on_error: closed, action: block, effects: [notify], reason: r}
  - {id: open-shadow, when: %[1]q, mode: shadow, on_error: open, action: flag, reason: r}
  - {id: closed-shadow, when: %[1]q, mode: shadow, on_error: closed, action: throttle, retry_after: 1m, reason: r}
`

// checkOutcome combines results and checks what holds for any ruleset: each
// rule is reported once, where its mode and on_error put it, and the action
// is the most severe enforced match.
func checkOutcome(t *testing.T, rs *Ruleset, results []Result) Outcome {
	t.Helper()
	if len(results) != len(rs.Rules()) {
		t.Fatalf("%d results for %d rules", len(results), len(rs.Rules()))
	}
	out := Combine(results)
	action, retry := decision.Allow, time.Duration(0)
	var i, j, k int
	for _, res := range results {
		r := res.Rule
		if res.Err != nil {
			if k >= len(out.Errors) || out.Errors[k].RuleID != r.ID {
				t.Fatalf("rule %s failed with %v but is not reported in order in %v", r.ID, res.Err, out.Errors)
			}
			k++
		}
		matched := res.Matched || (res.Err != nil && r.OnError == decision.FailClosed)
		if !matched {
			continue
		}
		var m decision.Match
		if r.Mode == decision.Enforce {
			if i >= len(out.Matches) {
				t.Fatalf("enforced rule %s matched but is missing from %v", r.ID, out.Matches)
			}
			m = out.Matches[i]
			i++
			action = decision.Max(action, r.Action)
			if r.Action == decision.Throttle {
				retry = max(retry, r.RetryAfter)
			}
		} else {
			if j >= len(out.Shadow) {
				t.Fatalf("shadow rule %s matched but is missing from %v", r.ID, out.Shadow)
			}
			m = out.Shadow[j]
			j++
		}
		if m.RuleID != r.ID || m.Errored != (res.Err != nil) || m.Mode != r.Mode || m.Action != r.Action {
			t.Errorf("match %+v for rule %s with error %v", m, r.ID, res.Err)
		}
	}
	if i != len(out.Matches) || j != len(out.Shadow) || k != len(out.Errors) {
		t.Errorf("outcome lists more than the results: %+v", out)
	}
	if action != decision.Throttle {
		retry = 0
	}
	if out.Action != action || out.RetryAfter != retry {
		t.Errorf("outcome %s %v, want %s %v", out.Action, out.RetryAfter, action, retry)
	}
	return out
}

// everySignal is a set with every signal the catalog produces, each with a
// value of its type.
func everySignal() signal.Set {
	maps := map[string]map[string]any{}
	for _, s := range signal.Specs() {
		if maps[s.Map] == nil {
			maps[s.Map] = map[string]any{}
		}
		maps[s.Map][s.Name] = valueOf(s.Type, 1)
	}
	return signal.Set{Event: maps["event"], Account: maps["account"], Key: maps["key"], IP: maps["ip"], Domain: maps["domain"]}
}

func valueOf(typ string, n byte) any {
	switch typ {
	case "string":
		return []string{"send", "feedback", "bit.ly", "", "permanent", "signup"}[int(n)%6]
	case "int":
		return int64(n) * 37
	case "double":
		return float64(n) / 7
	case "bool":
		return n%2 == 1
	case "list(string)":
		return []string{"t.co", "mail.example"}[:int(n)%3]
	default: // map(string, string)
		return map[string]string{"plan": "free", "tier": string(rune('a' + n%26))}
	}
}

// generateSignals reads a signal set from data: for each map whether it is
// there, and for each signal of the catalog, and a few it does not make,
// whether it is there and with a value of which type.
func generateSignals(data []byte) signal.Set {
	next := func() byte {
		if len(data) == 0 {
			return 0
		}
		b := data[0]
		data = data[1:]
		return b
	}
	odd := []func(n byte) any{
		func(n byte) any { return int(n) },
		func(n byte) any { return uint64(n) << 60 },
		func(n byte) any { return float32(n) / 3 },
		func(n byte) any { return []float64{math.NaN(), math.Inf(int(n%2)*2 - 1)}[n%2] },
		func(n byte) any { return math.MaxInt64 - int64(n) },
		func(byte) any { return nil },
		func(n byte) any { return []any{int64(n), "x", nil} },
		func(n byte) any { return map[string]any{"plan": int64(n)} },
		func(n byte) any { return map[int]string{int(n): "x"} },
		func(n byte) any { return []byte{n} },
		func(n byte) any { return time.Duration(n) * time.Second },
		func(n byte) any { return time.Unix(int64(n), 0) },
		func(n byte) any { return struct{ N byte }{n} },
		func(n byte) any { return &n },
		func(n byte) any { return string([]byte{0xff, n}) },
	}
	types := []string{"string", "int", "double", "bool", "list(string)", "map(string, string)"}
	maps := map[string]map[string]any{}
	present := map[string]bool{}
	for _, m := range variables {
		present[m] = next()%4 != 0
	}
	specs := append(signal.Specs(), signal.Spec{Map: "account", Name: "plan"}, signal.Spec{Map: "event", Name: "extra"})
	for _, s := range specs {
		if !present[s.Map] {
			continue
		}
		if maps[s.Map] == nil {
			maps[s.Map] = map[string]any{}
		}
		kind, n := next(), next()
		switch {
		case kind < 64:
			// Absent.
		case kind < 192 && s.Type != "":
			maps[s.Map][s.Name] = valueOf(s.Type, n)
		case kind < 224:
			maps[s.Map][s.Name] = valueOf(types[int(kind)%len(types)], n)
		default:
			maps[s.Map][s.Name] = odd[int(kind)%len(odd)](n)
		}
	}
	return signal.Set{Event: maps["event"], Account: maps["account"], Key: maps["key"], IP: maps["ip"], Domain: maps["domain"]}
}
