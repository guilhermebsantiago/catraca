package audit

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Retention deletes what Options.Retention expires in the background, in
// small batches, so the log, the outbox and the leak reports stop growing
// until the disk is full. Labeled decisions are kept for Options.LabeledRetention, forever by
// default, because the precision gate counts labels over all time.

const (
	// pruneFirst is when the first run starts after Open: soon, so that a
	// process restarted more often than pruneEvery still prunes, but out
	// of the way of the start itself.
	pruneFirst = time.Minute
	pruneEvery = 10 * time.Minute
	// pruneBatch is the default of Options.PruneBatch on SQLite: the most
	// rows one DELETE removes, so no statement holds locks for long. On
	// SQLite every write waits for it, the decision writer included.
	pruneBatch = 500
	// pruneBatchPostgres is the default on Postgres, where a DELETE locks
	// only the rows it deletes.
	pruneBatchPostgres = 5000
	// pruneMinPause is the least time between two batches. Without
	// Options.PrunePause the loop waits at least as long as the batch took
	// on SQLite, so a large backlog takes at most about half of the
	// database's write time; on Postgres it is the default pause.
	pruneMinPause = 10 * time.Millisecond
	// pruneTimeout bounds one DELETE.
	pruneTimeout = 30 * time.Second
)

// RetentionStats counts what the retention loop deleted since the DB was
// opened. Export them as metrics.
type RetentionStats struct {
	// Decisions were deleted with their matches and labels.
	Decisions uint64
	// Deliveries were delivered or dead webhook deliveries deleted from the
	// outbox.
	Deliveries uint64
	// LeakReports were done or dead leaked-key reports deleted.
	LeakReports uint64
	// Errors counts runs that failed. Each is logged, and the next run
	// retries.
	Errors uint64
}

type retentionCounters struct {
	decisions, deliveries, leakReports, errors atomic.Uint64
	// from is the decision time, in unix microseconds, where the search
	// for unlabeled decisions to delete starts: everything older was
	// deleted by an earlier run of this process or is labeled, and the
	// labeled ones would otherwise be read again by every batch. Only the
	// retention loop uses it.
	from int64
}

// RetentionStats returns the retention loop's counters. They stay zero
// without a retention.
func (db *DB) RetentionStats() RetentionStats {
	return RetentionStats{
		Decisions:   db.retention.decisions.Load(),
		Deliveries:  db.retention.deliveries.Load(),
		LeakReports: db.retention.leakReports.Load(),
		Errors:      db.retention.errors.Load(),
	}
}

func (db *DB) pruneLoop(ctx context.Context) {
	t := time.NewTimer(pruneFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := db.prune(ctx, time.Now()); err != nil && ctx.Err() == nil {
			db.retention.errors.Add(1)
			db.log.Error("audit: deleting expired rows failed; retrying on the next run", "err", err)
		}
		t.Reset(pruneEvery)
	}
}

// prune deletes the rows the retention settings expire at now: unlabeled
// decisions, finished deliveries and done or dead leak reports older than
// Retention, and, when LabeledRetention is set, every decision older than
// that.
func (db *DB) prune(ctx context.Context, now time.Time) error {
	var errs []error
	var decisions, deliveries int

	cutoff := toMicros(now.Add(-db.opts.Retention))
	from := db.retention.from
	err := db.inBatches(ctx, func(ctx context.Context) (int, error) {
		n, last, err := db.deleteDecisions(ctx, from, cutoff, true)
		if n > 0 {
			// Every unlabeled decision before last was in this batch.
			from = last
		}
		decisions += n
		return n, err
	})
	if err != nil {
		// Keep the progress made; the next run goes on from there.
		db.retention.from = from
		errs = append(errs, fmt.Errorf("delete unlabeled decisions: %w", err))
	} else {
		db.retention.from = cutoff
	}

	if lr := db.opts.LabeledRetention; lr > 0 {
		labeledCutoff := toMicros(now.Add(-lr))
		err := db.inBatches(ctx, func(ctx context.Context) (int, error) {
			n, _, err := db.deleteDecisions(ctx, 0, labeledCutoff, false)
			decisions += n
			return n, err
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("delete labeled decisions: %w", err))
		}
	}

	err = db.inBatches(ctx, func(ctx context.Context) (int, error) {
		n, err := db.deleteDeliveries(ctx, cutoff)
		deliveries += n
		return n, err
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("delete finished deliveries: %w", err))
	}

	var leakReports int
	err = db.inBatches(ctx, func(ctx context.Context) (int, error) {
		n, err := db.deleteLeakReports(ctx, cutoff)
		leakReports += n
		return n, err
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("delete finished leak reports: %w", err))
	}

	db.retention.decisions.Add(uint64(decisions))
	db.retention.deliveries.Add(uint64(deliveries))
	db.retention.leakReports.Add(uint64(leakReports))
	if decisions > 0 || deliveries > 0 || leakReports > 0 {
		db.log.Info("audit: deleted expired rows", "decisions", decisions, "deliveries", deliveries,
			"leak_reports", leakReports, "retention", db.opts.Retention.String())
	}
	return errors.Join(errs...)
}

// inBatches calls del until it deletes fewer than PruneBatch rows, pausing
// between batches for PrunePause or, without one, as long as the last
// batch took.
func (db *DB) inBatches(ctx context.Context, del func(context.Context) (int, error)) error {
	for {
		start := time.Now()
		sctx, cancel := context.WithTimeout(ctx, pruneTimeout)
		n, err := del(sctx)
		cancel()
		if err != nil || n < db.opts.PruneBatch {
			return err
		}
		pause := db.opts.PrunePause
		if pause == 0 {
			pause = max(time.Since(start), pruneMinPause)
		}
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// deleteDecisions deletes up to PruneBatch decisions decided in [from,
// before), oldest first, skipping labeled ones when unlabeledOnly is set.
// Matches and labels go with them through ON DELETE CASCADE. It returns how
// many it deleted and the latest decision time among them. On Postgres,
// rows another process is deleting or labeling are skipped, not waited for.
func (db *DB) deleteDecisions(ctx context.Context, from, before int64, unlabeledOnly bool) (n int, last int64, err error) {
	q := `DELETE FROM decisions WHERE id IN (
    SELECT d.id FROM decisions d
    WHERE d.decided_at_us >= ? AND d.decided_at_us < ?`
	if unlabeledOnly {
		q += `
        AND NOT EXISTS (SELECT 1 FROM labels l WHERE l.decision_id = d.id)`
	}
	q += `
    ORDER BY d.decided_at_us
    LIMIT ?` + db.dialect.skipLocked + `
)
RETURNING decided_at_us`
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), from, before, db.opts.PruneBatch)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var at int64
		if err := rows.Scan(&at); err != nil {
			return n, last, err
		}
		n++
		last = max(last, at)
	}
	return n, last, rows.Err()
}

// deleteDeliveries deletes up to PruneBatch delivered or dead deliveries
// last updated before before, oldest first. Pending ones are never deleted.
func (db *DB) deleteDeliveries(ctx context.Context, before int64) (int, error) {
	res, err := db.db.ExecContext(ctx, db.dialect.rebind(`DELETE FROM outbox WHERE id IN (
    SELECT id FROM outbox
    WHERE status IN ('delivered', 'dead') AND updated_at_us < ?
    ORDER BY updated_at_us
    LIMIT ?`+db.dialect.skipLocked+`
)`), before, db.opts.PruneBatch)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
