package audit

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The outbox as operators see it: listing deliveries, requeueing dead ones
// once their receiver is fixed, and counting them per hook. The catraca
// outbox commands use these; the hooks package does not.

// DeliveryFilter selects deliveries. Zero fields select everything.
type DeliveryFilter struct {
	// IDs selects these deliveries.
	IDs []int64
	// Status selects the deliveries in this state.
	Status DeliveryStatus
	// Effect selects the deliveries for one hook.
	Effect string
	// Since selects the deliveries last updated at or after it. For a dead
	// delivery that is when it was given up.
	Since time.Time
}

// maxFilterIDs bounds the ids one filter may name, well under both
// databases' limits on bound parameters per statement.
const maxFilterIDs = 1000

// where returns the filter as a WHERE clause, empty when it selects
// everything, and its arguments.
func (f DeliveryFilter) where() (string, []any, error) {
	var conds []string
	var args []any
	if len(f.IDs) > maxFilterIDs {
		return "", nil, fmt.Errorf("audit: at most %d delivery ids at once, got %d", maxFilterIDs, len(f.IDs))
	}
	if len(f.IDs) > 0 {
		conds = append(conds, "id IN (?"+strings.Repeat(", ?", len(f.IDs)-1)+")")
		for _, id := range f.IDs {
			args = append(args, id)
		}
	}
	switch f.Status {
	case "":
	case DeliveryPending, DeliveryDelivered, DeliveryDead:
		conds = append(conds, "status = ?")
		args = append(args, string(f.Status))
	default:
		return "", nil, fmt.Errorf("audit: unknown delivery status %q (want pending, delivered or dead)", f.Status)
	}
	if f.Effect != "" {
		conds = append(conds, "effect = ?")
		args = append(args, f.Effect)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "updated_at_us >= ?")
		args = append(args, toMicros(f.Since))
	}
	if len(conds) == 0 {
		return "", nil, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

// ListDeliveries returns up to limit deliveries f selects: pending ones in
// the order they are due, the others most recently updated first.
func (db *DB) ListDeliveries(ctx context.Context, f DeliveryFilter, limit int) ([]Delivery, error) {
	where, args, err := f.where()
	if err != nil {
		return nil, err
	}
	order := "updated_at_us DESC, id DESC"
	if f.Status == DeliveryPending {
		order = "next_attempt_at_us, id"
	}
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(
		"SELECT "+deliveryCols+" FROM outbox"+where+" ORDER BY "+order+" LIMIT ?"), append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list deliveries: %w", err)
	}
	ds, err := scanDeliveries(rows)
	if err != nil {
		return nil, fmt.Errorf("audit: list deliveries: %w", err)
	}
	return ds, nil
}

// Requeue makes the dead deliveries f selects pending again and returns
// their ids. Each is due at now, its attempts start over from 1, and its
// hook's max age counts from now (RequeuedAt). The last status and error
// stay until the next attempt replaces them. Deliveries that are not dead
// are left alone: f.Status must be empty or dead.
//
// It changes at most a few hundred rows per statement, so requeueing a large
// backlog does not hold the outbox's locks for long; the deliveries a
// statement requeues are committed even if a later one fails.
func (db *DB) Requeue(ctx context.Context, f DeliveryFilter, now time.Time) ([]int64, error) {
	if f.Status != "" && f.Status != DeliveryDead {
		return nil, fmt.Errorf("audit: only dead deliveries can be requeued, not %s ones", f.Status)
	}
	f.Status = DeliveryDead
	where, args, err := f.where()
	if err != nil {
		return nil, err
	}
	q := db.dialect.rebind(`UPDATE outbox
SET status = 'pending', attempts = 0, next_attempt_at_us = ?, requeued_at_us = ?, updated_at_us = ?
WHERE id IN (
    SELECT id FROM outbox` + where + `
    ORDER BY id
    LIMIT ?` + db.dialect.skipLocked + `
)
RETURNING id`)
	at := toMicros(now)
	args = append([]any{at, at, at}, append(args, expireBatch)...)
	ids := []int64{}
	for {
		n, err := db.requeueBatch(ctx, q, args, &ids)
		if err != nil {
			return ids, fmt.Errorf("audit: requeue deliveries: %w", err)
		}
		if n < expireBatch {
			return ids, nil
		}
	}
}

func (db *DB) requeueBatch(ctx context.Context, q string, args []any, ids *[]int64) (int, error) {
	rows, err := db.db.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return n, err
		}
		*ids = append(*ids, id)
		n++
	}
	return n, rows.Err()
}

// EffectStats counts the deliveries for one effect.
type EffectStats struct {
	Backlog
	Dead      int `json:"dead"`
	Delivered int `json:"delivered"`
}

// OutboxStats counts the deliveries of every effect in the outbox, by
// status, in effect order. Due counts the pending deliveries due at now. It
// reads the whole outbox.
func (db *DB) OutboxStats(ctx context.Context, now time.Time) ([]EffectStats, error) {
	stats, err := db.countDeliveries(ctx, now, false)
	if err != nil {
		return nil, fmt.Errorf("audit: outbox stats: %w", err)
	}
	return stats, nil
}
