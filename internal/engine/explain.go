package engine

import (
	"context"
	"fmt"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// Explanation is what Explain found for one event: every signal, every
// rule's result and whether the event counted.
type Explanation struct {
	rules.Explanation
	// Observed is true when the signals were read from the store. Without
	// it only those that need no store are present.
	Observed bool `json:"observed"`
	// Counted is true when observing the event counted it, as deciding it
	// would have: it was observed, its id had not counted already, and the
	// store did not fail on it.
	Counted bool `json:"counted"`
	// Duplicate is true when the event's id had counted already, so
	// observing it counted nothing again.
	Duplicate bool `json:"duplicate,omitempty"`
	// Degraded is true when observing was asked for and the store failed
	// or was skipped: the signals it holds are absent.
	Degraded bool `json:"degraded,omitempty"`
}

// Explain evaluates the current ruleset against ev's signals and returns
// them with each rule's result, without making a decision: nothing is
// recorded, measured as a decision or dispatched.
//
// Without observe the store is not called, so nothing counts and only the
// signals that need no store are present (Set.Event, and key.leaked for a
// key the catalog knows leaked). With observe the signals are read as
// Decide reads them, which counts the event unless its id counted already:
// to explain a decided event without counting it again, send it with the
// id it was decided with, within the catalog's dedupe TTL. Explanation.Counted
// says which happened.
//
// A key_leak event is refused with ErrInvalidEvent: observing one marks
// its key leaked.
func (e *Engine) Explain(ctx context.Context, ev event.Event, observe bool) (Explanation, error) {
	now := e.now()
	if err := ev.Validate(); err != nil {
		return Explanation{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	if ev.Type == event.KeyLeak {
		return Explanation{}, fmt.Errorf("%w: key_leak events cannot be explained: observing one marks its key leaked", ErrInvalidEvent)
	}
	rs := e.rules.Current()
	if rs == nil {
		return Explanation{}, ErrNoRuleset
	}
	ev = detach(ev)
	ev.Normalize(now)
	if err := e.boundTime(&ev, now); err != nil {
		return Explanation{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}

	octx, call, cancel := e.storeContext(ctx, !observe, opObserve)
	set, err := e.catalog.Observe(octx, ev)
	cancel()
	e.storeDone(ctx, call, err)

	x := Explanation{Explanation: rs.Explain(set)}
	if !observe {
		return x, nil
	}
	x.Observed = !call.skip && err == nil
	x.Degraded = err != nil
	x.Duplicate = set.Duplicate
	// As in a decision, a store that answered late most likely applied the
	// batch; one that failed or was skipped did not.
	x.Counted = !call.skip && !set.Duplicate && (err == nil || late(err))
	return x, nil
}
