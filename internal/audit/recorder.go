package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

const (
	// writeAttempts is how many times a batch is tried before its decisions
	// are counted as failed.
	writeAttempts = 3
	writeTimeout  = 10 * time.Second
	// drainTimeout bounds how long Close keeps writing queued decisions to a
	// database that keeps failing.
	drainTimeout = 30 * time.Second
	// dropLogEvery rate-limits drop warnings: a full buffer drops at the
	// rate decisions arrive, and one line per drop would flood the log.
	dropLogEvery = 10 * time.Second
)

// RecorderStats counts what happened to recorded decisions since the DB was
// opened. Export them as metrics.
type RecorderStats struct {
	// Recorded decisions were written to the database.
	Recorded uint64
	// Dropped decisions were never queued: the buffer was full, the DB was
	// closed, or the decision had no ID.
	Dropped uint64
	// Failed decisions were queued but could not be written.
	Failed uint64
	// Queued decisions are waiting to be written.
	Queued int
}

// RecorderStats returns the recorder's counters.
func (db *DB) RecorderStats() RecorderStats {
	return RecorderStats{
		Recorded: db.recorded.Load(),
		Dropped:  db.dropped.Load(),
		Failed:   db.failed.Load(),
		Queued:   int(max(0, db.pending.Load())),
	}
}

// row is a decision ready to insert, built in Record so the writer holds no
// references to the caller's event or decision.
type row struct {
	id             string
	eventID        string
	decidedAt      int64
	action         string
	eventType      string
	accountID      string
	apiKeyID       string
	rulesetVersion string
	degraded       bool
	decisionJSON   string
	eventJSON      string
	matches        []matchRow
}

type matchRow struct {
	ruleID  string
	mode    decision.Mode
	action  string
	reason  string
	errored bool
}

// Record queues d and ev to be written by the background writer. It never
// blocks and never fails: when the buffer is full or the DB is closed, the
// decision is dropped, counted in RecorderStats and logged. ctx is unused; it
// is there to satisfy the engine's Recorder interface.
func (db *DB) Record(_ context.Context, ev event.Event, d decision.Decision) {
	r, err := db.newRow(ev, d)
	if err != nil {
		db.drop(err.Error())
		return
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		db.drop("audit log closed")
		return
	}
	db.pending.Add(1)
	select {
	case db.queue <- r:
	default:
		db.pending.Add(-1)
		db.drop("buffer full")
	}
}

func (db *DB) newRow(ev event.Event, d decision.Decision) (row, error) {
	if d.ID == "" {
		return row{}, errors.New("decision has no id")
	}
	if d.Time.IsZero() {
		d.Time = time.Now().UTC()
	}
	decisionJSON, err := json.Marshal(d)
	if err != nil {
		return row{}, fmt.Errorf("encode decision: %w", err)
	}
	eventJSON, err := json.Marshal(NewStoredEvent(ev, db.opts.EventMode))
	if err != nil {
		return row{}, fmt.Errorf("encode event: %w", err)
	}
	r := row{
		id:             d.ID,
		eventID:        d.EventID,
		decidedAt:      toMicros(d.Time),
		action:         string(d.Action),
		eventType:      string(ev.Type),
		accountID:      ev.AccountID,
		apiKeyID:       ev.APIKeyID,
		rulesetVersion: d.RulesetVersion,
		degraded:       d.Degraded,
		decisionJSON:   string(decisionJSON),
		eventJSON:      string(eventJSON),
		matches:        make([]matchRow, 0, len(d.Matches)+len(d.Shadow)),
	}
	if r.eventID == "" {
		r.eventID = ev.ID
	}
	// The list a match is in decides its mode: Matches are enforced and
	// Shadow are shadow, whatever Match.Mode says.
	for _, m := range d.Matches {
		r.matches = append(r.matches, matchRow{m.RuleID, decision.Enforce, string(m.Action), m.Reason, m.Errored})
	}
	for _, m := range d.Shadow {
		r.matches = append(r.matches, matchRow{m.RuleID, decision.Shadow, string(m.Action), m.Reason, m.Errored})
	}
	return r, nil
}

func (db *DB) drop(reason string) {
	total := db.dropped.Add(1)
	db.droppedSinceLog.Add(1)
	now := time.Now().UnixNano()
	last := db.lastDropLog.Load()
	if now-last < int64(dropLogEvery) || !db.lastDropLog.CompareAndSwap(last, now) {
		return
	}
	db.log.Warn("audit: dropped decisions", "count", db.droppedSinceLog.Swap(0), "reason", reason, "total", total)
}

// Flush writes every decision queued before the call and returns the error
// of the last failed write, if any.
func (db *DB) Flush(ctx context.Context) error {
	reply := make(chan error, 1)
	select {
	case db.flushReq <- reply:
	case <-db.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// writer is the single goroutine that writes queued decisions in batches. It
// exits after Close, once the queue is drained.
func (db *DB) writer() {
	defer close(db.done)
	ticker := time.NewTicker(db.opts.FlushInterval)
	defer ticker.Stop()
	batch := make([]row, 0, db.opts.BatchSize)
	write := func() error {
		err := db.writeBatch(batch)
		batch = batch[:0]
		return err
	}
	for {
		select {
		case r, ok := <-db.queue:
			if !ok {
				write()
				return
			}
			batch = append(batch, r)
			if len(batch) >= db.opts.BatchSize {
				write()
			}
		case <-ticker.C:
			write()
		case reply := <-db.flushReq:
			var lastErr error
			// Drain what is queued now; decisions recorded during the
			// flush may wait for the next one.
			for n := len(db.queue); n > 0; n-- {
				r, ok := <-db.queue
				if !ok {
					break
				}
				batch = append(batch, r)
				if len(batch) >= db.opts.BatchSize {
					if err := write(); err != nil {
						lastErr = err
					}
				}
			}
			if err := write(); err != nil {
				lastErr = err
			}
			reply <- lastErr
		}
	}
}

// writeBatch writes rows in one transaction, retrying a few times. The
// writer blocks meanwhile, so Record starts dropping if the database stays
// down: losing audit records is better than slowing every decision. While
// closing, each batch gets one attempt, and none after drainTimeout.
func (db *DB) writeBatch(rows []row) error {
	if len(rows) == 0 {
		return nil
	}
	n := int64(len(rows))
	defer db.pending.Add(-n)
	attempts := writeAttempts
	if since := db.closingSince.Load(); since != 0 {
		if time.Since(time.Unix(0, since)) > drainTimeout {
			db.failed.Add(uint64(n))
			db.log.Error("audit: gave up writing decisions on close", "count", n)
			return fmt.Errorf("audit: gave up writing %d decisions on close", n)
		}
		attempts = 1
	}
	var err error
	for attempt := range attempts {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 100 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err = db.insertRows(ctx, rows)
		cancel()
		if err == nil {
			db.recorded.Add(uint64(n))
			return nil
		}
	}
	db.failed.Add(uint64(n))
	db.log.Error("audit: writing decisions failed", "count", n, "attempts", attempts, "err", err)
	return fmt.Errorf("audit: write %d decisions: %w", n, err)
}

var (
	decisionCols = []string{"id", "event_id", "decided_at_us", "action", "event_type", "account_id",
		"api_key_id", "ruleset_version", "degraded", "decision_json", "event_json"}
	matchCols = []string{"decision_id", "rule_id", "mode", "action", "reason", "errored", "decided_at_us"}
)

func (db *DB) insertRows(ctx context.Context, rows []row) error {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	decisions := make([][]any, 0, len(rows))
	var matches [][]any
	for _, r := range rows {
		decisions = append(decisions, []any{r.id, r.eventID, r.decidedAt, r.action, r.eventType, r.accountID,
			r.apiKeyID, r.rulesetVersion, r.degraded, r.decisionJSON, r.eventJSON})
		for _, m := range r.matches {
			matches = append(matches, []any{r.id, m.ruleID, string(m.mode), m.action, m.reason, m.errored, r.decidedAt})
		}
	}
	if _, err := db.dialect.insertMany(ctx, tx, "decisions", decisionCols, decisions); err != nil {
		return err
	}
	if len(matches) > 0 {
		if _, err := db.dialect.insertMany(ctx, tx, "matches", matchCols, matches); err != nil {
			return err
		}
	}
	return tx.Commit()
}
