package replay

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// countingCatalog is a tiny in-memory catalog: it counts sends per account
// and remembers leaked keys.
type countingCatalog struct {
	sends  map[string]int64
	leaked map[string]bool
	closed bool
}

func newCountingCatalog() (signal.Catalog, error) {
	return &countingCatalog{sends: map[string]int64{}, leaked: map[string]bool{}}, nil
}

func (c *countingCatalog) Observe(_ context.Context, ev event.Event) (signal.Set, error) {
	if ev.Type == event.Send {
		c.sends[ev.AccountID]++
	}
	set := signal.Set{
		Event:   map[string]any{"type": string(ev.Type), "api_key_id": ev.APIKeyID},
		Account: map[string]any{"sends_1h": c.sends[ev.AccountID]},
	}
	if ev.APIKeyID != "" {
		set.Key = map[string]any{"leaked": c.leaked[ev.APIKeyID]}
	}
	return set, nil
}

func (c *countingCatalog) MarkLeaked(_ context.Context, apiKeyID string) error {
	c.leaked[apiKeyID] = true
	return nil
}

func (c *countingCatalog) Close() error {
	c.closed = true
	return nil
}

const replayRuleset = `version: 1
rules:
  - id: volume
    when: event.type == "send" && account.sends_1h > 2
    action: block
    mode: enforce
    on_error: open
    reason: too many sends
  - id: leaked
    when: event.type == "send" && event.api_key_id != "" && key.leaked
    action: block
    mode: enforce
    on_error: closed
    reason: leaked key
  - id: eager
    when: event.type == "send" && account.sends_1h >= 2
    action: hold
    reason: would hold early
`

const replayEvents = `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}, "label": "legit"}
{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:01:00Z"}, "label": "legit"}

{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:02:00Z"}, "label": "abusive"}
{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:02:00Z"}, "label": "abusive"}
{"event": {"type": "send", "account_id": "b", "time": "2026-10-01T10:03:00Z"}, "label": "legit"}
{"event": {"type": "feedback", "account_id": "a", "time": "2026-10-01T10:04:00Z", "feedback": {"kind": "complaint"}}}
{"event": {"type": "key_leak", "api_key_id": "k2", "time": "2026-10-01T10:05:00Z"}}
{"event": {"type": "send", "account_id": "c", "api_key_id": "k2", "time": "2026-10-01T10:06:00Z"}, "label": "abusive"}
{"event": {"type": "send", "account_id": "d", "time": "2026-10-01T10:07:00Z"}, "label": "legit"}
`

func runReplay(t *testing.T, input string) *Report {
	t.Helper()
	rs, err := rules.Parse([]byte(replayRuleset))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), rs, newCountingCatalog, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRun(t *testing.T) {
	r := runReplay(t, replayEvents)

	if r.Events != 9 || r.Labeled != 7 || r.Abusive != 3 || r.Legit != 4 || r.Degraded != 0 {
		t.Errorf("counts = events %d labeled %d abusive %d legit %d degraded %d", r.Events, r.Labeled, r.Abusive, r.Legit, r.Degraded)
	}
	want := map[string]Confusion{
		"volume": {TP: 2, FP: 0, FN: 1, TN: 4},
		"leaked": {TP: 1, FP: 0, FN: 2, TN: 4},
		"eager":  {TP: 2, FP: 1, FN: 1, TN: 3},
	}
	for _, rr := range r.Rules {
		if rr.Confusion != want[rr.ID] {
			t.Errorf("rule %s = %+v, want %+v", rr.ID, rr.Confusion, want[rr.ID])
		}
	}
	if r.Rules[2].Mode != decision.Shadow || r.Rules[2].Action != decision.Hold {
		t.Errorf("eager = %+v", r.Rules[2])
	}
	if r.Enforced != (Confusion{TP: 3, FP: 0, FN: 0, TN: 4}) {
		t.Errorf("enforced = %+v", r.Enforced)
	}
	if r.Shadow != (Confusion{TP: 2, FP: 1, FN: 1, TN: 3}) {
		t.Errorf("shadow = %+v", r.Shadow)
	}
	if r.AllRules != (Confusion{TP: 3, FP: 1, FN: 0, TN: 3}) {
		t.Errorf("all rules = %+v", r.AllRules)
	}
	wantActions := map[decision.Action]ActionCount{
		decision.Allow: {Action: decision.Allow, Legit: 4, Unlabeled: 2},
		decision.Block: {Action: decision.Block, Abusive: 3},
	}
	for _, ac := range r.Actions {
		if w := wantActions[ac.Action]; ac != w && !(w == ActionCount{} && ac == ActionCount{Action: ac.Action}) {
			t.Errorf("action %s = %+v, want %+v", ac.Action, ac, w)
		}
	}
	if r.RulesetVersion == "" {
		t.Error("report has no ruleset version")
	}
}

func TestConfusionMetrics(t *testing.T) {
	c := Confusion{TP: 2, FP: 1, FN: 1, TN: 3}
	if p, ok := c.Precision(); !ok || p != 2.0/3 {
		t.Errorf("precision = %v %v", p, ok)
	}
	if r, ok := c.Recall(); !ok || r != 2.0/3 {
		t.Errorf("recall = %v %v", r, ok)
	}
	if f, ok := c.F1(); !ok || f < 0.6666 || f > 0.6667 {
		t.Errorf("f1 = %v %v", f, ok)
	}
	empty := Confusion{TN: 5}
	if _, ok := empty.Precision(); ok {
		t.Error("precision is defined without predictions")
	}
	if _, ok := empty.Recall(); ok {
		t.Error("recall is defined without abusive events")
	}
	if _, ok := (Confusion{FP: 1, FN: 1}).F1(); ok {
		t.Error("f1 is defined when precision and recall are both zero")
	}
}

func TestReportJSON(t *testing.T) {
	r := runReplay(t, replayEvents)
	var b strings.Builder
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Events int `json:"events"`
		Rules  []struct {
			ID        string   `json:"id"`
			TP        int      `json:"tp"`
			Precision *float64 `json:"precision"`
			Recall    *float64 `json:"recall"`
			F1        *float64 `json:"f1"`
			Errors    int      `json:"errors"`
		} `json:"rules"`
		Enforced map[string]any `json:"enforced"`
		Actions  []ActionCount  `json:"actions"`
	}
	if err := json.Unmarshal([]byte(b.String()), &got); err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if got.Events != 9 || len(got.Rules) != 3 || got.Rules[0].ID != "volume" || got.Rules[0].TP != 2 {
		t.Errorf("JSON = %s", b.String())
	}
	if got.Rules[0].Precision == nil || *got.Rules[0].Precision != 1 || got.Rules[0].F1 == nil {
		t.Errorf("volume precision/f1 missing: %s", b.String())
	}
	if got.Enforced["precision"] != 1.0 || len(got.Actions) != 5 {
		t.Errorf("enforced = %v, actions = %v", got.Enforced, got.Actions)
	}

	// Undefined ratios are null, not 0 or NaN.
	data, err := json.Marshal(Confusion{TN: 3})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"tp":0,"fp":0,"fn":0,"tn":3,"precision":null,"recall":null,"f1":null}` {
		t.Errorf("empty confusion JSON = %s", data)
	}
}

func TestReportText(t *testing.T) {
	r := runReplay(t, replayEvents)
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"9 events, 7 labeled (3 abusive, 4 legit)",
		"ENFORCED RULES",
		"SHADOW RULES",
		"COMBINED",
		"EFFECTIVE ACTION",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q:\n%s", want, out)
		}
	}
	lines := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines[f[0]] = strings.Join(f, " ")
		}
	}
	for first, want := range map[string]string{
		"volume": "volume block 2 0 1 4 1.000 0.667 0.800 0",
		"leaked": "leaked block 1 0 2 4 1.000 0.333 0.500 0",
		"eager":  "eager hold 2 1 1 3 0.667 0.667 0.667 0",
		"block":  "block 3 0 0",
		"allow":  "allow 0 4 2",
		"shadow": "shadow rules 2 1 1 3 0.667 0.667 0.667",
	} {
		if lines[first] != want {
			t.Errorf("row %q = %q, want %q", first, lines[first], want)
		}
	}
	if strings.Contains(out, "warning") {
		t.Errorf("unexpected warning in:\n%s", out)
	}
}

func TestReportTextMarksUndefinedRatios(t *testing.T) {
	r := runReplay(t, `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}, "label": "legit"}`+"\n")
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "volume") || !strings.Contains(b.String(), "-") {
		t.Errorf("undefined ratios are not shown as '-':\n%s", b.String())
	}
}

func TestRunCountsErrorsAndDegraded(t *testing.T) {
	rs, err := rules.Parse([]byte(`version: 1
rules:
  - id: needs-age
    when: account.age_hours < 24
    reason: young
`))
	if err != nil {
		t.Fatal(err)
	}
	failing := func() (signal.Catalog, error) {
		cat, _ := newCountingCatalog()
		return failingCatalog{cat}, nil
	}
	r, err := Run(context.Background(), rs, failing, strings.NewReader(replayEvents))
	if err != nil {
		t.Fatal(err)
	}
	if r.Rules[0].Errors != 9 || r.Degraded != 9 {
		t.Errorf("errors = %d degraded = %d, want 9 each", r.Rules[0].Errors, r.Degraded)
	}
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "warning: 9 decisions were degraded") {
		t.Errorf("text report does not warn about degraded decisions:\n%s", b.String())
	}
}

type failingCatalog struct{ signal.Catalog }

func (f failingCatalog) Observe(ctx context.Context, ev event.Event) (signal.Set, error) {
	set, _ := f.Catalog.Observe(ctx, ev)
	return signal.Set{Event: set.Event}, errors.New("store down")
}

func TestRunErrors(t *testing.T) {
	ok := `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}, "label": "legit"}` + "\n"
	tests := []struct {
		name, input, want string
	}{
		{"bad JSON", ok + "{not json}\n", "replay: line 2:"},
		{"unknown label", `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}, "label": "spam"}`, `line 1: unknown label "spam"`},
		{"unknown field", `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}, "lable": "legit"}`, `line 1: json: unknown field "lable"`},
		{"two values", `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T10:00:00Z"}} {}`, "line 1: more than one JSON value"},
		{"no time", `{"event": {"type": "send", "account_id": "a"}, "label": "legit"}`, "line 1: event has no time"},
		{"invalid event", `{"event": {"type": "send", "time": "2026-10-01T10:00:00Z"}, "label": "legit"}`, "line 1: invalid event: event: account_id is required"},
		{"out of order", ok + `{"event": {"type": "send", "account_id": "a", "time": "2026-10-01T09:59:59Z"}, "label": "legit"}`, "line 2: event at 2026-10-01T09:59:59Z is older than the line before it"},
		{"line too long", `{"event": {"type": "send", "account_id": "` + strings.Repeat("a", maxLine) + `"}}`, "longer than"},
	}
	rs, err := rules.Parse([]byte(replayRuleset))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), rs, newCountingCatalog, strings.NewReader(tt.input))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestRunSetup(t *testing.T) {
	rs, err := rules.Parse([]byte(replayRuleset))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), nil, newCountingCatalog, strings.NewReader("")); err == nil {
		t.Error("Run without a ruleset succeeded")
	}
	if _, err := Run(context.Background(), rs, nil, strings.NewReader("")); err == nil {
		t.Error("Run without a catalog factory succeeded")
	}
	broken := func() (signal.Catalog, error) { return nil, errors.New("no memory") }
	if _, err := Run(context.Background(), rs, broken, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "no memory") {
		t.Errorf("factory error = %v", err)
	}

	var cat *countingCatalog
	factory := func() (signal.Catalog, error) {
		c, err := newCountingCatalog()
		cat = c.(*countingCatalog)
		return c, err
	}
	if _, err := Run(context.Background(), rs, factory, strings.NewReader(replayEvents)); err != nil {
		t.Fatal(err)
	}
	if !cat.closed {
		t.Error("Run did not close its catalog")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, rs, newCountingCatalog, strings.NewReader(replayEvents)); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled run error = %v", err)
	}
}

func TestRunFile(t *testing.T) {
	rs, err := rules.Parse([]byte(replayRuleset))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(replayEvents), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := RunFile(context.Background(), rs, newCountingCatalog, path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Events != 9 {
		t.Errorf("events = %d", r.Events)
	}
	if _, err := RunFile(context.Background(), rs, newCountingCatalog, path+".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file error = %v", err)
	}
}
