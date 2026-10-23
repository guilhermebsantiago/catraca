package audit

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Outbox is a durable queue of webhook deliveries, one per decision and
// effect. The hooks package writes to it and delivers from it; *DB
// implements it in the audit database.
type Outbox interface {
	// Enqueue adds deliveries and returns how many were new. A delivery for
	// a (decision id, effect) already in the outbox is skipped, which makes
	// enqueueing idempotent.
	Enqueue(ctx context.Context, deliveries []Delivery) (int, error)
	// Claim leases up to r.Limit pending deliveries of r.Effect that are due
	// at r.Now, oldest first, and counts an attempt for each. A claimed
	// delivery is not claimed again until the lease ends, so if its worker
	// dies it is retried. Each hook claims its own deliveries, so one whose
	// endpoint is slow never holds up another's.
	Claim(ctx context.Context, r ClaimRequest) ([]Delivery, error)
	// MarkDelivered records a successful attempt.
	MarkDelivered(ctx context.Context, id int64, a Attempt) error
	// Retry records a failed attempt and schedules the next one.
	Retry(ctx context.Context, id int64, a Attempt, next time.Time) error
	// MarkDead records a failed attempt after which the delivery is given up.
	MarkDead(ctx context.Context, id int64, a Attempt) error
	// Expire gives up the deliveries of effect that are due at a.At and were
	// queued before before (see Delivery.QueuedAt), recording a.Error as the
	// reason, and returns how many it gave up. They are past their hook's
	// max age, or wait for a hook that is not configured.
	Expire(ctx context.Context, effect string, before time.Time, a Attempt) (int, error)
	// Backlog counts the pending deliveries of every effect that has some.
	Backlog(ctx context.Context, now time.Time) ([]Backlog, error)
	// Deliveries returns the deliveries for a decision, by effect.
	Deliveries(ctx context.Context, decisionID string) ([]Delivery, error)
}

// DeliveryStatus is where a delivery is in its life.
type DeliveryStatus string

const (
	// DeliveryPending deliveries are waiting for their next attempt.
	DeliveryPending DeliveryStatus = "pending"
	// DeliveryDelivered deliveries got a 2xx response.
	DeliveryDelivered DeliveryStatus = "delivered"
	// DeliveryDead deliveries failed every attempt, or can no longer be
	// sent, and will not be retried.
	DeliveryDead DeliveryStatus = "dead"
)

// Delivery is one webhook call for one effect of one decision.
type Delivery struct {
	ID         int64  `json:"id"`
	DecisionID string `json:"decision_id"`
	Effect     string `json:"effect"`
	// Payload is the request body, fixed when the delivery is enqueued so
	// every attempt sends the same bytes.
	Payload        []byte         `json:"-"`
	Status         DeliveryStatus `json:"status"`
	Attempts       int            `json:"attempts"`
	NextAttemptAt  time.Time      `json:"next_attempt_at"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	LastStatusCode int            `json:"last_status_code,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	// RequeuedAt is when the dead delivery was last made pending again
	// (Requeue), zero if it never was.
	RequeuedAt time.Time `json:"requeued_at,omitzero"`
}

// QueuedAt is when the delivery last entered the queue: when it was
// requeued, or when it was created if it never was. A hook's max age counts
// from it, so a requeued delivery gets the whole of it again.
func (d Delivery) QueuedAt() time.Time {
	if d.RequeuedAt.After(d.CreatedAt) {
		return d.RequeuedAt
	}
	return d.CreatedAt
}

// ClaimRequest says which deliveries Claim leases.
type ClaimRequest struct {
	// Effect names the hook whose deliveries to claim.
	Effect string
	// Now is when the deliveries must be due by. Leases start then.
	Now time.Time
	// Limit is the most deliveries to claim.
	Limit int
	// Lease is how long each claimed delivery is reserved for its attempt.
	Lease time.Duration
	// QueuedAfter skips the deliveries queued before it, which are past
	// their hook's max age and left for Expire. Zero skips none.
	QueuedAfter time.Time
}

// Backlog is what waits in the outbox for one effect.
type Backlog struct {
	Effect string `json:"effect"`
	// Pending deliveries wait for an attempt: due, leased to an attempt in
	// flight, or waiting out the backoff before a retry.
	Pending int `json:"pending"`
	// Due deliveries are the pending ones whose next attempt is due: they
	// wait for a worker, not for a backoff or an attempt in flight.
	Due int `json:"due"`
	// Oldest is the earliest QueuedAt among the pending deliveries, zero
	// without any.
	Oldest time.Time `json:"oldest_pending,omitzero"`
}

// Attempt is the outcome of one delivery attempt.
type Attempt struct {
	At time.Time
	// StatusCode is the HTTP status, or 0 when there was no response.
	StatusCode int
	// Error describes a failure.
	Error string
}

// maxErrorLen bounds the stored error, which may quote a response body.
const maxErrorLen = 1024

var outboxCols = []string{"decision_id", "effect", "payload", "status", "attempts",
	"next_attempt_at_us", "created_at_us", "updated_at_us"}

const deliveryCols = `id, decision_id, effect, payload, status, attempts,
    next_attempt_at_us, created_at_us, updated_at_us, last_status_code, last_error, requeued_at_us`

// queuedAt is Delivery.QueuedAt in SQL. requeued_at_us is 0 until the first
// requeue, and later than created_at_us after it.
const queuedAt = `CASE WHEN requeued_at_us > created_at_us THEN requeued_at_us ELSE created_at_us END`

// Enqueue implements Outbox. Of each delivery it reads DecisionID, Effect,
// Payload and CreatedAt (now when zero); the first attempt is due at
// CreatedAt.
func (db *DB) Enqueue(ctx context.Context, deliveries []Delivery) (int, error) {
	if len(deliveries) == 0 {
		return 0, nil
	}
	now := time.Now()
	rows := make([][]any, 0, len(deliveries))
	for _, d := range deliveries {
		if d.DecisionID == "" || d.Effect == "" {
			return 0, fmt.Errorf("audit: enqueue: delivery needs a decision id and an effect")
		}
		created := d.CreatedAt
		if created.IsZero() {
			created = now
		}
		at := toMicros(created)
		rows = append(rows, []any{d.DecisionID, d.Effect, string(d.Payload), string(DeliveryPending), 0, at, at, at})
	}
	n, err := db.dialect.insertMany(ctx, db.db, "outbox", outboxCols, rows)
	if err != nil {
		return 0, fmt.Errorf("audit: enqueue: %w", err)
	}
	return int(n), nil
}

// Claim implements Outbox.
func (db *DB) Claim(ctx context.Context, r ClaimRequest) ([]Delivery, error) {
	if r.Limit <= 0 {
		return nil, nil
	}
	// The lease is the next attempt time: a delivery whose worker never
	// reports back becomes due again when the lease ends.
	q := db.dialect.rebind(`UPDATE outbox
SET attempts = attempts + 1, next_attempt_at_us = ?, updated_at_us = ?
WHERE id IN (
    SELECT id FROM outbox
    WHERE status = 'pending' AND effect = ? AND next_attempt_at_us <= ? AND ` + queuedAt + ` >= ?
    ORDER BY next_attempt_at_us, id
    LIMIT ?` + db.dialect.skipLocked + `
)
RETURNING ` + deliveryCols)
	nowUS := toMicros(r.Now)
	after := int64(math.MinInt64)
	if !r.QueuedAfter.IsZero() {
		after = toMicros(r.QueuedAfter)
	}
	rows, err := db.db.QueryContext(ctx, q, toMicros(r.Now.Add(r.Lease)), nowUS, r.Effect, nowUS, after, r.Limit)
	if err != nil {
		return nil, fmt.Errorf("audit: claim deliveries: %w", err)
	}
	ds, err := scanDeliveries(rows)
	if err != nil {
		return nil, fmt.Errorf("audit: claim deliveries: %w", err)
	}
	// RETURNING order is unspecified.
	sort.Slice(ds, func(i, j int) bool { return ds[i].ID < ds[j].ID })
	return ds, nil
}

// MarkDelivered implements Outbox. It applies whatever the delivery's status,
// because a success is the final word even if another attempt failed.
func (db *DB) MarkDelivered(ctx context.Context, id int64, a Attempt) error {
	return db.settle(ctx, `UPDATE outbox
SET status = 'delivered', updated_at_us = ?, last_status_code = ?, last_error = ?
WHERE id = ?`, toMicros(a.At), a.StatusCode, truncate(a.Error), id)
}

// Retry implements Outbox. It applies only to a pending delivery, so a late
// failure cannot undo a success.
func (db *DB) Retry(ctx context.Context, id int64, a Attempt, next time.Time) error {
	return db.settle(ctx, `UPDATE outbox
SET next_attempt_at_us = ?, updated_at_us = ?, last_status_code = ?, last_error = ?
WHERE id = ? AND status = 'pending'`, toMicros(next), toMicros(a.At), a.StatusCode, truncate(a.Error), id)
}

// MarkDead implements Outbox. It applies only to a pending delivery.
func (db *DB) MarkDead(ctx context.Context, id int64, a Attempt) error {
	return db.settle(ctx, `UPDATE outbox
SET status = 'dead', updated_at_us = ?, last_status_code = ?, last_error = ?
WHERE id = ? AND status = 'pending'`, toMicros(a.At), a.StatusCode, truncate(a.Error), id)
}

// expireBatch is the most deliveries one statement of Expire or Requeue
// changes, so neither holds the outbox's locks for long: on SQLite every
// write waits for it, the decision writer included.
const expireBatch = 500

// Expire implements Outbox. It keeps the error of the last attempt, if there
// was one, after the reason. A delivery leased to an attempt in flight is
// not due, so it is left to finish.
func (db *DB) Expire(ctx context.Context, effect string, before time.Time, a Attempt) (int, error) {
	q := db.dialect.rebind(`UPDATE outbox
SET status = 'dead', updated_at_us = ?,
    last_error = CASE WHEN last_error = '' THEN CAST(? AS TEXT) ELSE CAST(? AS TEXT) || '; last attempt: ' || last_error END
WHERE id IN (
    SELECT id FROM outbox
    WHERE status = 'pending' AND effect = ? AND next_attempt_at_us <= ? AND ` + queuedAt + ` < ?
    ORDER BY id
    LIMIT ?` + db.dialect.skipLocked + `
)`)
	reason, at := truncate(a.Error), toMicros(a.At)
	total := 0
	for {
		res, err := db.db.ExecContext(ctx, q, at, reason, reason, effect, at, toMicros(before), expireBatch)
		if err != nil {
			return total, fmt.Errorf("audit: expire deliveries: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("audit: expire deliveries: %w", err)
		}
		total += int(n)
		if n < expireBatch {
			return total, nil
		}
	}
}

// Backlog implements Outbox.
func (db *DB) Backlog(ctx context.Context, now time.Time) ([]Backlog, error) {
	stats, err := db.countDeliveries(ctx, now, true)
	if err != nil {
		return nil, fmt.Errorf("audit: outbox backlog: %w", err)
	}
	out := make([]Backlog, 0, len(stats))
	for _, s := range stats {
		out = append(out, s.Backlog)
	}
	return out, nil
}

// countDeliveries counts the deliveries of each effect by status, or only
// the pending ones, in effect order.
func (db *DB) countDeliveries(ctx context.Context, now time.Time, pendingOnly bool) ([]EffectStats, error) {
	q := `SELECT effect, status, COUNT(*),
    SUM(CASE WHEN next_attempt_at_us <= ? THEN 1 ELSE 0 END),
    MIN(` + queuedAt + `)
FROM outbox`
	if pendingOnly {
		q += " WHERE status = 'pending'"
	}
	q += " GROUP BY effect, status ORDER BY effect"
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), toMicros(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EffectStats{}
	for rows.Next() {
		var (
			effect string
			status DeliveryStatus
			n, due int
			oldest int64
		)
		if err := rows.Scan(&effect, &status, &n, &due, &oldest); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Effect != effect {
			out = append(out, EffectStats{Backlog: Backlog{Effect: effect}})
		}
		s := &out[len(out)-1]
		switch status {
		case DeliveryPending:
			s.Pending, s.Due, s.Oldest = n, due, fromMicros(oldest)
		case DeliveryDead:
			s.Dead = n
		case DeliveryDelivered:
			s.Delivered = n
		}
	}
	return out, rows.Err()
}

func (db *DB) settle(ctx context.Context, q string, args ...any) error {
	if _, err := db.db.ExecContext(ctx, db.dialect.rebind(q), args...); err != nil {
		return fmt.Errorf("audit: update delivery: %w", err)
	}
	return nil
}

// Deliveries implements Outbox.
func (db *DB) Deliveries(ctx context.Context, decisionID string) ([]Delivery, error) {
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(
		"SELECT "+deliveryCols+" FROM outbox WHERE decision_id = ? ORDER BY effect"), decisionID)
	if err != nil {
		return nil, fmt.Errorf("audit: deliveries: %w", err)
	}
	ds, err := scanDeliveries(rows)
	if err != nil {
		return nil, fmt.Errorf("audit: deliveries: %w", err)
	}
	return ds, nil
}

func scanDeliveries(rows *sql.Rows) ([]Delivery, error) {
	defer rows.Close()
	ds := []Delivery{}
	for rows.Next() {
		var d Delivery
		var next, created, updated, requeued int64
		if err := rows.Scan(&d.ID, &d.DecisionID, &d.Effect, &d.Payload, &d.Status, &d.Attempts,
			&next, &created, &updated, &d.LastStatusCode, &d.LastError, &requeued); err != nil {
			return nil, err
		}
		d.NextAttemptAt = fromMicros(next)
		d.CreatedAt = fromMicros(created)
		d.UpdatedAt = fromMicros(updated)
		if requeued > 0 {
			d.RequeuedAt = fromMicros(requeued)
		}
		ds = append(ds, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ds, nil
}

// truncate bounds an error message and makes it storable: Postgres text
// must be valid UTF-8 without NUL bytes, and a response body may be neither.
func truncate(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= maxErrorLen {
		return s
	}
	cut := maxErrorLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

var (
	_ Outbox = (*DB)(nil)
	_ Store  = (*DB)(nil)
)
