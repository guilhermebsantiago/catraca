package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

const explainRuleset = `version: 1
rules:
  - id: burst
    when: event.type == "send" && account.sends_1m > 1
    action: throttle
    retry_after: 30s
    mode: enforce
    on_error: open
    reason: burst
  - id: many-recipients
    when: event.recipients > 0
    action: hold
    mode: shadow
    on_error: open
    reason: many recipients
  - id: strict
    when: account.sends_1h > 100
    action: block
    mode: enforce
    on_error: closed
    reason: strict
`

// newExplainEngine returns an engine over a real catalog on the memory
// store, so tests see what explaining does to the counters, and the
// channel its recorder writes to.
func newExplainEngine(t *testing.T) (*Engine, chan recorded) {
	t.Helper()
	rs, err := rules.Parse([]byte(explainRuleset))
	if err != nil {
		t.Fatal(err)
	}
	rec := &chanRecorder{ch: make(chan recorded, 16)}
	e, err := New(Options{
		Catalog:  signal.NewCatalog(store.NewMemory(), signal.Options{}),
		Rules:    rules.NewHolder(rs),
		Recorder: rec,
		Deadline: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	return e, rec.ch
}

func explainEvent(id string) event.Event {
	return event.Event{Type: event.Send, ID: id, AccountID: "acct_1", From: "a@example.com", To: []string{"b@example.org"}}
}

func ruleByID(t *testing.T, x Explanation, id string) rules.RuleExplanation {
	t.Helper()
	for _, r := range x.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s is not in the explanation: %+v", id, x.Rules)
	return rules.RuleExplanation{}
}

func TestExplainWithoutObserveCountsNothing(t *testing.T) {
	e, records := newExplainEngine(t)
	ctx := context.Background()
	x, err := e.Explain(ctx, explainEvent(""), false)
	if err != nil {
		t.Fatal(err)
	}
	if x.Observed || x.Counted || x.Degraded || x.Duplicate {
		t.Errorf("explain without observe: %+v", x)
	}
	if x.Signals.Event["recipients"] != int64(1) || x.Signals.Account != nil {
		t.Errorf("signals = %+v, want event signals alone", x.Signals)
	}
	if r := ruleByID(t, x, "burst"); r.Matched || r.Error != "signal account.sends_1m is absent" {
		t.Errorf("burst = %+v, want unmatched with the absent signal", r)
	}
	// strict fails closed, so it matches and blocks, as it would in a
	// decision made without the store.
	if r := ruleByID(t, x, "strict"); !r.Matched || r.Error == "" || r.OnError != decision.FailClosed {
		t.Errorf("strict = %+v, want matched by failing closed", r)
	}
	if r := ruleByID(t, x, "many-recipients"); !r.Matched || r.Mode != decision.Shadow || r.Action != decision.Hold {
		t.Errorf("many-recipients = %+v", r)
	}
	if x.Action != decision.Block || x.RulesetVersion == "" {
		t.Errorf("action %s, version %q", x.Action, x.RulesetVersion)
	}

	d, err := e.Decide(ctx, explainEvent(""))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("%d decisions recorded, want only the one decided", len(records))
	}
	x, err = e.Explain(ctx, explainEvent("e1"), true)
	if err != nil {
		t.Fatal(err)
	}
	// The decided event counted once and the observed explanation once.
	if got := x.Signals.Account["sends_1m"]; got != int64(2) || !x.Counted || !x.Observed {
		t.Errorf("after one decision and one observed explanation: sends_1m = %v, %+v (decision %s)", got, x, d.ID)
	}
}

func TestExplainObserveDecidedEventCountsNothingAgain(t *testing.T) {
	e, _ := newExplainEngine(t)
	ctx := context.Background()
	if _, err := e.Decide(ctx, explainEvent("evt_1")); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		x, err := e.Explain(ctx, explainEvent("evt_1"), true)
		if err != nil {
			t.Fatal(err)
		}
		if !x.Observed || x.Counted || !x.Duplicate || x.Degraded {
			t.Errorf("explanation %d of a decided event: %+v", i, x)
		}
		if got := x.Signals.Account["sends_1m"]; got != int64(1) {
			t.Errorf("explanation %d: sends_1m = %v, want the decided event alone", i, got)
		}
		if r := ruleByID(t, x, "burst"); r.Matched || r.Error != "" {
			t.Errorf("burst = %+v", r)
		}
		if x.Action != decision.Allow {
			t.Errorf("action = %s", x.Action)
		}
	}
}

func TestExplainObserveDegraded(t *testing.T) {
	h := newHarness(t, Options{})
	h.cat.err = errors.New("store down")
	h.cat.set = signal.Set{Event: map[string]any{"type": "send"}}
	x, err := h.eng.Explain(context.Background(), sendEvent(), true)
	if err != nil {
		t.Fatal(err)
	}
	if x.Observed || x.Counted || !x.Degraded {
		t.Errorf("explanation with the store down: %+v", x)
	}
}

func TestExplainRefuses(t *testing.T) {
	e, _ := newExplainEngine(t)
	ctx := context.Background()
	for name, ev := range map[string]event.Event{
		"invalid":  {Type: "nope"},
		"key_leak": {Type: event.KeyLeak, APIKeyID: "key_1"},
	} {
		if _, err := e.Explain(ctx, ev, true); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: err = %v, want ErrInvalidEvent", name, err)
		}
	}

	h := newHarness(t, Options{})
	h.holder.Store(nil)
	if _, err := h.eng.Explain(ctx, sendEvent(), false); !errors.Is(err, ErrNoRuleset) {
		t.Errorf("no ruleset: err = %v", err)
	}
}
