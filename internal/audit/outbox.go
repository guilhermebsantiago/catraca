package audit

import (
	"context"
	"database/sql"
	"fmt"
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
	// Claim leases up to limit pending deliveries due at now, oldest first,
	// and counts an attempt for each. A claimed delivery is not claimed
	// again until the lease ends, so if its worker dies it is retried.
	Claim(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]Delivery, error)
	// MarkDelivered records a successful attempt.
	MarkDelivered(ctx context.Context, id int64, a Attempt) error
	// Retry records a failed attempt and schedules the next one.
	Retry(ctx context.Context, id int64, a Attempt, next time.Time) error
	// MarkDead records a failed attempt after which the delivery is given up.
	MarkDead(ctx context.Context, id int64, a Attempt) error
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
    next_attempt_at_us, created_at_us, updated_at_us, last_status_code, last_error`

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
func (db *DB) Claim(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]Delivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	// The lease is the next attempt time: a delivery whose worker never
	// reports back becomes due again when the lease ends.
	q := db.dialect.rebind(`UPDATE outbox
SET attempts = attempts + 1, next_attempt_at_us = ?, updated_at_us = ?
WHERE id IN (
    SELECT id FROM outbox
    WHERE status = 'pending' AND next_attempt_at_us <= ?
    ORDER BY next_attempt_at_us, id
    LIMIT ?` + db.dialect.skipLocked + `
)
RETURNING ` + deliveryCols)
	nowUS := toMicros(now)
	rows, err := db.db.QueryContext(ctx, q, toMicros(now.Add(lease)), nowUS, nowUS, limit)
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
		var next, created, updated int64
		if err := rows.Scan(&d.ID, &d.DecisionID, &d.Effect, &d.Payload, &d.Status, &d.Attempts,
			&next, &created, &updated, &d.LastStatusCode, &d.LastError); err != nil {
			return nil, err
		}
		d.NextAttemptAt = fromMicros(next)
		d.CreatedAt = fromMicros(created)
		d.UpdatedAt = fromMicros(updated)
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
