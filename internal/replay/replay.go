// Package replay backtests a ruleset on labeled events: it runs them, in
// time order, through a fresh signal catalog and the same engine that serves
// production, and measures how each rule's matches line up with the labels.
package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// Label is the ground truth for an event.
type Label string

const (
	Abusive Label = "abusive"
	Legit   Label = "legit"
	// Unlabeled events still feed the counters, so later events see the
	// signals they had, but they are left out of the scores.
	Unlabeled Label = ""
)

// Example is one line of a replay file.
type Example struct {
	Event event.Event `json:"event"`
	Label Label       `json:"label,omitempty"`
}

// CatalogFactory returns a new, empty catalog. Each run gets its own, so the
// counters start from zero and only see the replayed events.
type CatalogFactory func() (signal.Catalog, error)

// maxLine bounds one JSONL line; events are small, so a longer line is
// almost certainly not an event.
const maxLine = 4 << 20

// observeDeadline replaces the engine's production deadline: a backtest must
// not lose signals to a slow moment on the machine running it.
const observeDeadline = time.Minute

// RunFile backtests rs on the JSONL file at path. See Run.
func RunFile(ctx context.Context, rs *rules.Ruleset, newCatalog CatalogFactory, path string) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Run(ctx, rs, newCatalog, f)
}

// Run backtests rs on r, one JSON Example per line, with events in time
// order. Every event, labeled or not, is decided as production would decide
// it; labeled events are scored. A malformed line, an invalid event or an
// event older than the one before it stops the run with an error naming the
// line.
func Run(ctx context.Context, rs *rules.Ruleset, newCatalog CatalogFactory, r io.Reader) (*Report, error) {
	if rs == nil || newCatalog == nil {
		return nil, errors.New("replay: a ruleset and a catalog factory are required")
	}
	cat, err := newCatalog()
	if err != nil {
		return nil, fmt.Errorf("replay: create catalog: %w", err)
	}
	defer cat.Close()
	eng, err := engine.New(engine.Options{
		Catalog:  cat,
		Rules:    rules.NewHolder(rs),
		Deadline: observeDeadline,
		// Replayed events are historical: bounding their times by the wall
		// clock would refuse them all.
		TrustEventTime: true,
	})
	if err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}

	t := newTally(rs)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	var last time.Time
	for line := 1; sc.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		ex, err := decodeLine(raw)
		if err != nil {
			return nil, fmt.Errorf("replay: line %d: %w", line, err)
		}
		if ex.Event.Time.Before(last) {
			return nil, fmt.Errorf("replay: line %d: event at %s is older than the line before it (%s); sort the file by time",
				line, ex.Event.Time.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano))
		}
		last = ex.Event.Time
		d, err := eng.Decide(ctx, ex.Event)
		if err != nil {
			return nil, fmt.Errorf("replay: line %d: %w", line, err)
		}
		t.add(ex.Label, d)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("replay: a line is longer than %d bytes", maxLine)
		}
		return nil, fmt.Errorf("replay: %w", err)
	}
	return t.report(), nil
}

func decodeLine(raw []byte) (Example, error) {
	var ex Example
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ex); err != nil {
		return ex, err
	}
	if dec.More() {
		return ex, errors.New("more than one JSON value on the line")
	}
	switch ex.Label {
	case Abusive, Legit, Unlabeled:
	default:
		return ex, fmt.Errorf("unknown label %q (want abusive, legit or none)", ex.Label)
	}
	if ex.Event.Time.IsZero() {
		return ex, errors.New("event has no time; replay needs it to rebuild the counters")
	}
	return ex, nil
}

// tally accumulates a report while events are replayed.
type tally struct {
	rep    Report
	index  map[string]int
	action map[decision.Action]*ActionCount
}

func newTally(rs *rules.Ruleset) *tally {
	t := &tally{
		rep:    Report{RulesetVersion: rs.Version()},
		index:  map[string]int{},
		action: map[decision.Action]*ActionCount{},
	}
	for i, r := range rs.Rules() {
		t.index[r.ID] = i
		t.rep.Rules = append(t.rep.Rules, RuleReport{ID: r.ID, Mode: r.Mode, Action: r.Action})
	}
	for _, a := range actions {
		t.rep.Actions = append(t.rep.Actions, ActionCount{Action: a})
	}
	for i := range t.rep.Actions {
		t.action[t.rep.Actions[i].Action] = &t.rep.Actions[i]
	}
	return t
}

var actions = []decision.Action{decision.Allow, decision.Flag, decision.Throttle, decision.Hold, decision.Block}

func (t *tally) add(label Label, d decision.Decision) {
	t.rep.Events++
	if d.Degraded {
		t.rep.Degraded++
	}
	matched := make([]bool, len(t.rep.Rules))
	for _, m := range d.Matches {
		matched[t.index[m.RuleID]] = true
	}
	for _, m := range d.Shadow {
		matched[t.index[m.RuleID]] = true
	}
	for _, re := range d.Errors {
		t.rep.Rules[t.index[re.RuleID]].Errors++
	}

	ac := t.action[d.Action]
	switch label {
	case Abusive:
		ac.Abusive++
	case Legit:
		ac.Legit++
	default:
		ac.Unlabeled++
		return
	}
	t.rep.Labeled++
	abusive := label == Abusive
	if abusive {
		t.rep.Abusive++
	} else {
		t.rep.Legit++
	}
	var anyShadow bool
	for i := range t.rep.Rules {
		t.rep.Rules[i].Confusion.add(matched[i], abusive)
		if matched[i] && t.rep.Rules[i].Mode == decision.Shadow {
			anyShadow = true
		}
	}
	t.rep.Enforced.add(d.Action != decision.Allow, abusive)
	t.rep.Shadow.add(anyShadow, abusive)
	t.rep.AllRules.add(len(d.Matches)+len(d.Shadow) > 0, abusive)
}

func (t *tally) report() *Report {
	r := t.rep
	return &r
}
