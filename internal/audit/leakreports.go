package audit

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LeakReports is a durable queue of leaked-key reports from secret
// scanning, one per token and place it was found. The secretscan package
// stores a batch's reports before it acknowledges the batch and processes
// them from here, so a report outlives a restart and an outage of whatever
// it needs; *DB implements it in the audit database. Like the Outbox, a
// report is claimed under a lease, so several processes can share the queue
// without working on the same report at once.
type LeakReports interface {
	// AddLeakReports stores reports as pending and returns how many were
	// new. A report whose Key is already stored, whatever its status, is
	// skipped, so a report delivered twice is processed once.
	AddLeakReports(ctx context.Context, reports []LeakReport) (int, error)
	// LeakReportsByKey returns the stored reports with the given keys, in
	// no particular order. Keys that are not stored are left out.
	LeakReportsByKey(ctx context.Context, keys []string) ([]LeakReport, error)
	// ClaimLeakReports leases up to limit pending reports due at now,
	// oldest first, and counts an attempt for each. A claimed report is not
	// claimed again until the lease ends, so if its worker dies it is
	// retried.
	ClaimLeakReports(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]LeakReport, error)
	// FinishLeakReport records a report as done. It applies to a pending or
	// a dead report alike, because a success is the final word even if a
	// later claim of the same report failed; a report already done keeps
	// its first outcome.
	FinishLeakReport(ctx context.Context, id int64, a LeakAttempt) error
	// RetryLeakReport records a failed attempt and schedules the next one.
	// It applies only while a.Attempt is still the report's latest claim.
	RetryLeakReport(ctx context.Context, id int64, a LeakAttempt, next time.Time) error
	// MarkLeakReportDead records a failed attempt after which the report is
	// given up, until someone requeues it. It applies only while a.Attempt
	// is still the report's latest claim.
	MarkLeakReportDead(ctx context.Context, id int64, a LeakAttempt) error
}

// LeakReportStatus is where a report is in its life.
type LeakReportStatus string

const (
	// LeakReportPending reports are waiting for their next attempt.
	LeakReportPending LeakReportStatus = "pending"
	// LeakReportDone reports were processed: the token is not a key, or its
	// key_leak event was decided.
	LeakReportDone LeakReportStatus = "done"
	// LeakReportDead reports failed for longer than their bounds allow and
	// are not retried until someone requeues them.
	LeakReportDead LeakReportStatus = "dead"
)

// ParseLeakReportStatus parses a status name.
func ParseLeakReportStatus(s string) (LeakReportStatus, error) {
	switch st := LeakReportStatus(s); st {
	case LeakReportPending, LeakReportDone, LeakReportDead:
		return st, nil
	}
	return "", fmt.Errorf("audit: unknown leak report status %q (want pending, done or dead)", s)
}

// LeakReport is one leaked token as reported, and what became of it.
type LeakReport struct {
	ID int64 `json:"id"`
	// Key identifies the report: reports with the same key are the same
	// report delivered again. The caller derives it.
	Key string `json:"key"`
	// TokenSHA256 is the lowercase hex SHA-256 of the token.
	TokenSHA256 string `json:"token_sha256"`
	// SealedToken is the raw token in the form the caller stores it in,
	// which secretscan encrypts, or "" when it is not kept. It is cleared
	// once the token resolves to a key or the report is done.
	SealedToken string `json:"-"`
	// Type, Source and URL are as reported.
	Type   string `json:"type"`
	Source string `json:"source"`
	URL    string `json:"url"`

	Status LeakReportStatus `json:"status"`
	// Outcome is what processing concluded, set once the report is done or
	// dead.
	Outcome  string `json:"outcome,omitempty"`
	Attempts int    `json:"attempts"`
	// APIKeyID and AccountID are the key the token belongs to, once it has
	// resolved.
	APIKeyID  string `json:"api_key_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	// DecisionID is the decision on the report's key_leak event.
	DecisionID string `json:"decision_id,omitempty"`

	// ReceivedAt is when the report first arrived.
	ReceivedAt time.Time `json:"received_at"`
	// QueuedAt is when the report last became pending: when it arrived, or
	// when it was requeued. Its age is counted from then.
	QueuedAt      time.Time `json:"queued_at"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastError     string    `json:"last_error,omitempty"`
}

// LeakAttempt is the outcome of one attempt at a report.
type LeakAttempt struct {
	// At is when the attempt ended.
	At time.Time
	// Attempt is the report's Attempts as claimed, which fences Retry and
	// MarkDead: a worker whose lease ran out cannot overwrite the outcome
	// of a later claim.
	Attempt int
	// Outcome is what the attempt concluded, for a done or dead report.
	Outcome string
	// APIKeyID and AccountID are the key the token belongs to, when it is
	// known. Recording a key forgets the sealed token, which is no longer
	// needed.
	APIKeyID  string
	AccountID string
	// DecisionID is the decision on the report's key_leak event.
	DecisionID string
	// Error describes a failure.
	Error string
}

// LeakReportStats counts the reports that need attention.
type LeakReportStats struct {
	Pending int64
	Dead    int64
	// OldestPending is when the oldest pending report arrived, zero when
	// none is pending.
	OldestPending time.Time
}

// LeakReportFilter selects reports to list.
type LeakReportFilter struct {
	// Status keeps reports with this status; empty keeps all.
	Status LeakReportStatus
	// Limit is the most reports returned, newest first. Default 50.
	Limit int
}

const defaultLeakReportLimit = 50

var leakReportInsertCols = []string{"report_key", "token_sha256", "sealed_token", "token_type", "source", "url",
	"status", "attempts", "received_at_us", "queued_at_us", "next_attempt_at_us", "updated_at_us"}

const leakReportCols = `id, report_key, token_sha256, sealed_token, token_type, source, url, status, outcome,
    attempts, api_key_id, account_id, decision_id, received_at_us, queued_at_us, next_attempt_at_us,
    updated_at_us, last_error`

// AddLeakReports implements LeakReports. Of each report it reads Key,
// TokenSHA256, SealedToken, Type, Source, URL and ReceivedAt (now when
// zero); the first attempt is due at ReceivedAt.
func (db *DB) AddLeakReports(ctx context.Context, reports []LeakReport) (int, error) {
	if len(reports) == 0 {
		return 0, nil
	}
	now := time.Now()
	rows := make([][]any, 0, len(reports))
	for _, r := range reports {
		if r.Key == "" || r.TokenSHA256 == "" {
			return 0, fmt.Errorf("audit: add leak reports: a report needs a key and a token hash")
		}
		received := r.ReceivedAt
		if received.IsZero() {
			received = now
		}
		at := toMicros(received)
		rows = append(rows, []any{r.Key, r.TokenSHA256, r.SealedToken, storable(r.Type), storable(r.Source), storable(r.URL),
			string(LeakReportPending), 0, at, at, at, at})
	}
	n, err := db.dialect.insertMany(ctx, db.db, "leak_reports", leakReportInsertCols, rows)
	if err != nil {
		return 0, fmt.Errorf("audit: add leak reports: %w", err)
	}
	return int(n), nil
}

// LeakReportsByKey implements LeakReports.
func (db *DB) LeakReportsByKey(ctx context.Context, keys []string) ([]LeakReport, error) {
	out := []LeakReport{}
	for start := 0; start < len(keys); start += maxParams {
		chunk := keys[start:min(start+maxParams, len(keys))]
		args := make([]any, len(chunk))
		for i, k := range chunk {
			args[i] = k
		}
		q := "SELECT " + leakReportCols + " FROM leak_reports WHERE report_key IN (" +
			strings.TrimSuffix(strings.Repeat("?, ", len(chunk)), ", ") + ")"
		rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), args...)
		if err != nil {
			return nil, fmt.Errorf("audit: leak reports by key: %w", err)
		}
		rs, err := scanLeakReports(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: leak reports by key: %w", err)
		}
		out = append(out, rs...)
	}
	return out, nil
}

// ClaimLeakReports implements LeakReports.
func (db *DB) ClaimLeakReports(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]LeakReport, error) {
	if limit <= 0 {
		return nil, nil
	}
	// As in the outbox, the lease is the next attempt time: a report whose
	// worker never reports back becomes due again when the lease ends.
	q := db.dialect.rebind(`UPDATE leak_reports
SET attempts = attempts + 1, next_attempt_at_us = ?, updated_at_us = ?
WHERE id IN (
    SELECT id FROM leak_reports
    WHERE status = 'pending' AND next_attempt_at_us <= ?
    ORDER BY next_attempt_at_us, id
    LIMIT ?` + db.dialect.skipLocked + `
)
RETURNING ` + leakReportCols)
	nowUS := toMicros(now)
	rows, err := db.db.QueryContext(ctx, q, toMicros(now.Add(lease)), nowUS, nowUS, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: claim leak reports: %w", err)
	}
	rs, err := scanLeakReports(rows)
	if err != nil {
		return nil, fmt.Errorf("audit: claim leak reports: %w", err)
	}
	// RETURNING order is unspecified.
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs, nil
}

// FinishLeakReport implements LeakReports. The sealed token goes: a done
// report never needs it again.
func (db *DB) FinishLeakReport(ctx context.Context, id int64, a LeakAttempt) error {
	return db.settleLeakReport(ctx, `UPDATE leak_reports
SET status = 'done', outcome = ?, api_key_id = ?, account_id = ?, decision_id = ?, sealed_token = '',
    updated_at_us = ?, last_error = ?
WHERE id = ? AND status <> 'done'`,
		storable(a.Outcome), storable(a.APIKeyID), storable(a.AccountID), storable(a.DecisionID),
		toMicros(a.At), truncate(a.Error), id)
}

// RetryLeakReport implements LeakReports.
func (db *DB) RetryLeakReport(ctx context.Context, id int64, a LeakAttempt, next time.Time) error {
	return db.settleLeakReport(ctx, `UPDATE leak_reports
SET next_attempt_at_us = ?, updated_at_us = ?, last_error = ?, api_key_id = ?, account_id = ?`+forgetToken(a)+`
WHERE id = ? AND status = 'pending' AND attempts = ?`,
		toMicros(next), toMicros(a.At), truncate(a.Error), storable(a.APIKeyID), storable(a.AccountID), id, a.Attempt)
}

// MarkLeakReportDead implements LeakReports. A dead report whose token has
// not resolved keeps its sealed token, so that it can be requeued once
// whatever failed is fixed; retention deletes it with the report.
func (db *DB) MarkLeakReportDead(ctx context.Context, id int64, a LeakAttempt) error {
	return db.settleLeakReport(ctx, `UPDATE leak_reports
SET status = 'dead', outcome = ?, updated_at_us = ?, last_error = ?, api_key_id = ?, account_id = ?`+forgetToken(a)+`
WHERE id = ? AND status = 'pending' AND attempts = ?`,
		storable(a.Outcome), toMicros(a.At), truncate(a.Error), storable(a.APIKeyID), storable(a.AccountID), id, a.Attempt)
}

// forgetToken clears the sealed token once the attempt knows the key: the
// raw token is needed only to resolve it.
func forgetToken(a LeakAttempt) string {
	if a.APIKeyID == "" {
		return ""
	}
	return ", sealed_token = ''"
}

func (db *DB) settleLeakReport(ctx context.Context, q string, args ...any) error {
	if _, err := db.db.ExecContext(ctx, db.dialect.rebind(q), args...); err != nil {
		return fmt.Errorf("audit: update leak report: %w", err)
	}
	return nil
}

// RequeueLeakReports makes the dead reports among ids pending again, due at
// now, with their attempts and age counted afresh, and returns how many it
// requeued. Reports that are not dead are left alone: a pending one may be
// in the middle of an attempt.
func (db *DB) RequeueLeakReports(ctx context.Context, now time.Time, ids []int64) (int, error) {
	var total int64
	for start := 0; start < len(ids); start += maxParams {
		chunk := ids[start:min(start+maxParams, len(ids))]
		nowUS := toMicros(now)
		args := []any{nowUS, nowUS, nowUS}
		for _, id := range chunk {
			args = append(args, id)
		}
		res, err := db.db.ExecContext(ctx, db.dialect.rebind(`UPDATE leak_reports
SET status = 'pending', outcome = '', attempts = 0, next_attempt_at_us = ?, queued_at_us = ?, updated_at_us = ?
WHERE status = 'dead' AND id IN (`+strings.TrimSuffix(strings.Repeat("?, ", len(chunk)), ", ")+`)`), args...)
		if err != nil {
			return int(total), fmt.Errorf("audit: requeue leak reports: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}
	return int(total), nil
}

// ListLeakReports returns reports, newest first.
func (db *DB) ListLeakReports(ctx context.Context, f LeakReportFilter) ([]LeakReport, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultLeakReportLimit
	}
	q := "SELECT " + leakReportCols + " FROM leak_reports"
	var args []any
	if f.Status != "" {
		q += " WHERE status = ?"
		args = append(args, string(f.Status))
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list leak reports: %w", err)
	}
	rs, err := scanLeakReports(rows)
	if err != nil {
		return nil, fmt.Errorf("audit: list leak reports: %w", err)
	}
	return rs, nil
}

// LeakReportStats counts the pending and dead reports.
func (db *DB) LeakReportStats(ctx context.Context) (LeakReportStats, error) {
	rows, err := db.db.QueryContext(ctx, `SELECT status, COUNT(*), MIN(received_at_us) FROM leak_reports
WHERE status IN ('pending', 'dead') GROUP BY status`)
	if err != nil {
		return LeakReportStats{}, fmt.Errorf("audit: leak report stats: %w", err)
	}
	defer rows.Close()
	var s LeakReportStats
	for rows.Next() {
		var status string
		var n, oldest int64
		if err := rows.Scan(&status, &n, &oldest); err != nil {
			return LeakReportStats{}, fmt.Errorf("audit: leak report stats: %w", err)
		}
		switch LeakReportStatus(status) {
		case LeakReportPending:
			s.Pending, s.OldestPending = n, fromMicros(oldest)
		case LeakReportDead:
			s.Dead = n
		}
	}
	if err := rows.Err(); err != nil {
		return LeakReportStats{}, fmt.Errorf("audit: leak report stats: %w", err)
	}
	return s, nil
}

func scanLeakReports(rows *sql.Rows) ([]LeakReport, error) {
	defer rows.Close()
	rs := []LeakReport{}
	for rows.Next() {
		var r LeakReport
		var received, queued, next, updated int64
		if err := rows.Scan(&r.ID, &r.Key, &r.TokenSHA256, &r.SealedToken, &r.Type, &r.Source, &r.URL, &r.Status,
			&r.Outcome, &r.Attempts, &r.APIKeyID, &r.AccountID, &r.DecisionID, &received, &queued, &next,
			&updated, &r.LastError); err != nil {
			return nil, err
		}
		r.ReceivedAt = fromMicros(received)
		r.QueuedAt = fromMicros(queued)
		r.NextAttemptAt = fromMicros(next)
		r.UpdatedAt = fromMicros(updated)
		rs = append(rs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rs, nil
}

// deleteLeakReports deletes up to pruneBatch done or dead reports last
// updated before before, oldest first. Pending ones are never deleted.
func (db *DB) deleteLeakReports(ctx context.Context, before int64) (int, error) {
	res, err := db.db.ExecContext(ctx, db.dialect.rebind(`DELETE FROM leak_reports WHERE id IN (
    SELECT id FROM leak_reports
    WHERE status IN ('done', 'dead') AND updated_at_us < ?
    ORDER BY updated_at_us
    LIMIT ?`+db.dialect.skipLocked+`
)`), before, pruneBatch)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// storable makes a string storable as Postgres text, which must be valid
// UTF-8 without NUL bytes. The values come from GitHub and the platform's
// resolver, and one refused value would refuse its whole batch every time
// it is sent again.
func storable(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.ReplaceAll(s, "\x00", "")
}

var _ LeakReports = (*DB)(nil)
