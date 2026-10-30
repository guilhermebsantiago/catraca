package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/precision"
)

const (
	defaultReviewLimit = 50
	maxReviewLimit     = 1000
)

// Get returns a decision, its stored event and its labels. A decision that is
// still queued is written first, so a decision can be read as soon as it is
// recorded.
func (db *DB) Get(ctx context.Context, decisionID string) (Entry, error) {
	e, err := db.get(ctx, decisionID)
	if errors.Is(err, ErrNotFound) && db.flushIfPending(ctx) {
		e, err = db.get(ctx, decisionID)
	}
	return e, err
}

// flushIfPending flushes when decisions are waiting to be written and
// reports whether it is worth looking again. A flush that failed for some
// rows still wrote the others, so only a context that ended says no.
func (db *DB) flushIfPending(ctx context.Context) bool {
	if db.pending.Load() <= 0 {
		return false
	}
	err := db.Flush(ctx)
	return err == nil || ctx.Err() == nil
}

func (db *DB) get(ctx context.Context, id string) (Entry, error) {
	var decisionJSON, eventJSON []byte
	err := db.db.QueryRowContext(ctx,
		db.dialect.rebind("SELECT decision_json, event_json FROM decisions WHERE id = ?"), id,
	).Scan(&decisionJSON, &eventJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if err != nil {
		return Entry{}, fmt.Errorf("audit: get decision: %w", err)
	}
	var e Entry
	if err := json.Unmarshal(decisionJSON, &e.Decision); err != nil {
		return Entry{}, fmt.Errorf("audit: decode decision %q: %w", id, err)
	}
	if err := json.Unmarshal(eventJSON, &e.Event); err != nil {
		return Entry{}, fmt.Errorf("audit: decode event of decision %q: %w", id, err)
	}

	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(
		"SELECT rule_id, verdict, labeled_by, reason, client, labeled_at_us FROM labels WHERE decision_id = ? ORDER BY id"), id)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: get labels: %w", err)
	}
	defer rows.Close()
	e.Labels = []Label{}
	for rows.Next() {
		var l Label
		var at int64
		if err := rows.Scan(&l.RuleID, &l.Verdict, &l.By, &l.Reason, &l.Client, &at); err != nil {
			return Entry{}, fmt.Errorf("audit: get labels: %w", err)
		}
		l.Time = fromMicros(at)
		e.Labels = append(e.Labels, l)
	}
	if err := rows.Err(); err != nil {
		return Entry{}, fmt.Errorf("audit: get labels: %w", err)
	}
	return e, nil
}

// Label attaches l to a decision. It returns an error wrapping ErrNotFound
// when the decision is not in the log, ErrRuleNotMatched when l names a rule
// that did not match it, and ErrInvalidLabel when l is malformed.
//
// Labels accumulate: every label is kept, and the counts use, for each
// match, the latest label that applies to it, whether it names the rule or
// covers the whole decision. Labeling a decision no rule matched is allowed;
// it is kept for backtesting and counts for no rule.
func (db *DB) Label(ctx context.Context, decisionID string, l Label) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if l.Time.IsZero() {
		l.Time = time.Now()
	}
	err := db.label(ctx, decisionID, l)
	if errors.Is(err, ErrNotFound) && db.flushIfPending(ctx) {
		err = db.label(ctx, decisionID, l)
	}
	return err
}

func (db *DB) label(ctx context.Context, id string, l Label) error {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: label: %w", err)
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx, db.dialect.rebind("SELECT 1 FROM decisions WHERE id = ?"), id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("audit: label: %w", err)
	}
	if l.RuleID != "" {
		err = tx.QueryRowContext(ctx,
			db.dialect.rebind("SELECT 1 FROM matches WHERE decision_id = ? AND rule_id = ?"), id, l.RuleID,
		).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: rule %q, decision %q", ErrRuleNotMatched, l.RuleID, id)
		}
		if err != nil {
			return fmt.Errorf("audit: label: %w", err)
		}
	}

	at := toMicros(l.Time)
	if _, err := tx.ExecContext(ctx, db.dialect.rebind(`INSERT INTO labels
    (decision_id, rule_id, verdict, labeled_by, reason, client, labeled_at_us, created_at_us)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		id, l.RuleID, string(l.Verdict), l.By, l.Reason, l.Client, at, toMicros(time.Now())); err != nil {
		return fmt.Errorf("audit: label: %w", err)
	}

	// A label older than the one a match already carries does not replace
	// it. On a tie the newer label wins, as it was given later.
	update := "UPDATE matches SET verdict = ?, labeled_at_us = ? " +
		"WHERE decision_id = ? AND (labeled_at_us IS NULL OR labeled_at_us <= ?)"
	args := []any{string(l.Verdict), at, id, at}
	if l.RuleID != "" {
		update += " AND rule_id = ?"
		args = append(args, l.RuleID)
	}
	if _, err := tx.ExecContext(ctx, db.dialect.rebind(update), args...); err != nil {
		return fmt.Errorf("audit: label: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: label: %w", err)
	}
	return nil
}

// ruleStatsQuery is RuleStats' query, on the time from which to count.
const ruleStatsQuery = `SELECT m.rule_id, m.mode,
    COUNT(*),
    COUNT(*) FILTER (WHERE m.errored),
    COUNT(m.verdict),
    COUNT(*) FILTER (WHERE m.verdict = 'true_positive'),
    COUNT(*) FILTER (WHERE m.verdict = 'false_positive')
FROM matches m
WHERE m.decided_at_us >= ?
    AND m.decision_id NOT IN (SELECT id FROM decisions
        WHERE decision_json->>'duplicate' IS NOT NULL)
GROUP BY m.rule_id, m.mode
ORDER BY m.rule_id, m.mode`

// RuleStats counts, per rule and mode, the matches decided at or after since
// and their labels, ordered by rule and mode. Feed the result to the
// precision package. Decisions still queued are not counted; call Flush
// first if that matters.
//
// Matches of duplicate decisions, made for a retried event that had
// counted already, are left out: the first decision for the event counts
// them once. A decision is a duplicate when its decision_json carries the
// duplicate key, which is only written when true. The decisions_duplicate
// partial index holds just those, and matches_stats covers the count with
// each match's decision id, so the query reads two indexes and no JSON
// (migration 0007).
func (db *DB) RuleStats(ctx context.Context, since time.Time) ([]precision.RuleStats, error) {
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(ruleStatsQuery), toMicros(since))
	if err != nil {
		return nil, fmt.Errorf("audit: rule stats: %w", err)
	}
	defer rows.Close()
	out := []precision.RuleStats{}
	for rows.Next() {
		var s precision.RuleStats
		if err := rows.Scan(&s.RuleID, &s.Mode, &s.Matches, &s.Errored, &s.Labeled,
			&s.TruePositives, &s.FalsePositives); err != nil {
			return nil, fmt.Errorf("audit: rule stats: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: rule stats: %w", err)
	}
	return out, nil
}

// ReviewQueue returns up to limit unlabeled matches, newest first, for a
// reviewer to label. An empty ruleID or mode matches any rule or mode. limit
// defaults to 50 and is capped at 1000.
func (db *DB) ReviewQueue(ctx context.Context, ruleID string, mode decision.Mode, limit int) ([]ReviewItem, error) {
	if mode != "" {
		if _, err := decision.ParseMode(string(mode)); err != nil {
			return nil, fmt.Errorf("audit: review queue: %w", err)
		}
	}
	if limit <= 0 {
		limit = defaultReviewLimit
	}
	limit = min(limit, maxReviewLimit)

	q := `SELECT m.decision_id, m.rule_id, m.mode, m.action, m.reason, m.errored, m.decided_at_us, d.event_json
FROM matches m JOIN decisions d ON d.id = m.decision_id
WHERE m.verdict IS NULL`
	var args []any
	if ruleID != "" {
		q += " AND m.rule_id = ?"
		args = append(args, ruleID)
	}
	if mode != "" {
		q += " AND m.mode = ?"
		args = append(args, string(mode))
	}
	q += " ORDER BY m.decided_at_us DESC, m.decision_id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("audit: review queue: %w", err)
	}
	defer rows.Close()
	items := []ReviewItem{}
	for rows.Next() {
		var it ReviewItem
		var at int64
		var eventJSON []byte
		if err := rows.Scan(&it.DecisionID, &it.RuleID, &it.Mode, &it.Action, &it.Reason, &it.Errored, &at, &eventJSON); err != nil {
			return nil, fmt.Errorf("audit: review queue: %w", err)
		}
		it.Time = fromMicros(at)
		if err := json.Unmarshal(eventJSON, &it.Event); err != nil {
			return nil, fmt.Errorf("audit: review queue: decode event of decision %q: %w", it.DecisionID, err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: review queue: %w", err)
	}
	return items, nil
}
