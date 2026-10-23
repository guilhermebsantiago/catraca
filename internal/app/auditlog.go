package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
)

// How long to wait between attempts to open an unreachable audit database:
// from the first delay, doubling to the last, each jittered to between half
// and all of it so that instances started together do not retry together.
const (
	auditRetryFirst = time.Second
	auditRetryMax   = 30 * time.Second
)

// errAuditNotOpen is what the audit log answers before its database opens.
var errAuditNotOpen = fmt.Errorf("%w: the audit database is not open yet", api.ErrAuditUnavailable)

// auditLog is the audit database as the rest of the server uses it, while it
// may still be opening. A Postgres database that cannot be reached when the
// server starts is opened in the background, retried with backoff, instead
// of stopping the server: Kubernetes would restart it with a backoff of up
// to five minutes, and keep it down that long after the database is back.
// Decisions do not need the audit log, so they are made meanwhile, as they
// are when the database fails later on. Until it opens:
//
//   - Record waits, so the engine's queue keeps the decisions made meanwhile
//     and drops, and counts, those that do not fit;
//   - the outbox waits up to its context, as a write to a database that is
//     down would, so effects are kept if it opens in time;
//   - reads and labels fail at once with api.ErrAuditUnavailable.
//
// An error that waiting cannot fix (a malformed DSN, wrong credentials, a
// schema newer than this build) is not retried: it is sent on fatal, and
// Serve stops the server with it.
type auditLog struct {
	log *slog.Logger
	// retryFirst and retryMax bound the wait between attempts.
	retryFirst, retryMax time.Duration

	// opened is closed once db is set; closed is closed when the log gives
	// up on a database that never opened.
	opened, closed chan struct{}
	db             *audit.DB

	// lastErr is the last error opening the database.
	lastErr atomic.Pointer[error]
	// dropped counts decisions dropped because the database never opened.
	dropped atomic.Uint64
	fatal   chan error

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     chan struct{}
}

func newAuditLog(log *slog.Logger) *auditLog {
	return &auditLog{
		log:        log,
		retryFirst: auditRetryFirst,
		retryMax:   auditRetryMax,
		opened:     make(chan struct{}),
		closed:     make(chan struct{}),
		fatal:      make(chan error, 1),
		done:       make(chan struct{}),
	}
}

// openAuditLog opens the audit database dsn names. SQLite is a local file,
// so it opens now, and a failure is a configuration problem returned as is.
// Postgres opens in the background; see auditLog.
func openAuditLog(ctx context.Context, dsn string, opts audit.Options, log *slog.Logger) (*auditLog, error) {
	l := newAuditLog(log)
	open := func(ctx context.Context) (*audit.DB, error) { return audit.Open(ctx, dsn, opts) }
	if !isPostgres(dsn) {
		db, err := open(ctx)
		if err != nil {
			return nil, err
		}
		l.set(db)
		close(l.done)
		return l, nil
	}
	l.start(open)
	return l, nil
}

// isPostgres reports whether dsn names Postgres, by the prefixes audit.Open
// reads.
func isPostgres(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// start opens the database in the background with open, retrying while it
// is unreachable, until it opens, fails for good or the log is closed.
func (l *auditLog) start(open func(context.Context) (*audit.DB, error)) {
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	go func() {
		defer close(l.done)
		started := time.Now()
		delay := l.retryFirst
		for attempt := 1; ; attempt++ {
			db, err := open(ctx)
			if err == nil {
				l.set(db)
				if attempt > 1 {
					l.log.Info("the audit database is open; decisions are recorded again",
						"attempts", attempt, "after", time.Since(started).Round(time.Millisecond))
				}
				return
			}
			if ctx.Err() != nil {
				return
			}
			l.lastErr.Store(&err)
			if !unreachable(err) {
				l.fatal <- fmt.Errorf("open the audit database: %w", err)
				return
			}
			wait := delay/2 + rand.N(delay/2+1)
			l.log.Error("the audit database is unreachable; deciding without the audit log until it opens",
				"attempt", attempt, "retry_in", wait.Round(time.Millisecond), "error", err)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			delay = min(2*delay, l.retryMax)
		}
	}()
}

// unreachable reports whether err, from opening the database, says it could
// not be reached for now (the network, a server starting up or out of
// connections) rather than something waiting will not fix.
func unreachable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case len(pgErr.Code) >= 2 && pgErr.Code[:2] == "08": // connection exception
			return true
		case pgErr.Code == "57P01", pgErr.Code == "57P02", pgErr.Code == "57P03": // shutting down, starting up
			return true
		case pgErr.Code == "53300": // too many connections
			return true
		}
		return false
	}
	// A deadline here is the DSN's connect_timeout: the attempts are never
	// given one otherwise.
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (l *auditLog) set(db *audit.DB) {
	l.db = db
	close(l.opened)
}

// current returns the database, or nil while it is not open.
func (l *auditLog) current() *audit.DB {
	select {
	case <-l.opened:
		return l.db
	default:
		return nil
	}
}

// wait returns the database once it is open, or an error when ctx ends or
// the log gives up first.
func (l *auditLog) wait(ctx context.Context) (*audit.DB, error) {
	select {
	case <-l.opened:
		return l.db, nil
	default:
	}
	select {
	case <-l.opened:
		return l.db, nil
	case <-l.closed:
		return nil, errAuditNotOpen
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", errAuditNotOpen, ctx.Err())
	}
}

// failed receives an error opening the database that waiting cannot fix.
func (l *auditLog) failed() <-chan error { return l.fatal }

// stopOpening stops the attempts to open the database. If it has not opened
// by then, it never will: what waits for it gives up, and what is recorded
// from then on is dropped.
func (l *auditLog) stopOpening() {
	l.stopOnce.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}
		<-l.done
		if l.current() == nil {
			close(l.closed)
		}
	})
}

// Close stops opening the database and closes it if it opened, writing
// queued decisions until ctx ends.
func (l *auditLog) Close(ctx context.Context) error {
	l.stopOpening()
	if db := l.current(); db != nil {
		return db.Close(ctx)
	}
	return nil
}

// Ping checks that the database answers; it fails while it is not open.
func (l *auditLog) Ping(ctx context.Context) error {
	db := l.current()
	if db == nil {
		if err := l.lastErr.Load(); err != nil {
			return fmt.Errorf("%w: %w", errAuditNotOpen, *err)
		}
		return errAuditNotOpen
	}
	return db.SQL().PingContext(ctx)
}

// RecorderStats returns the database's recorder counters, with the
// decisions dropped because it never opened counted as dropped.
func (l *auditLog) RecorderStats() audit.RecorderStats {
	var s audit.RecorderStats
	if db := l.current(); db != nil {
		s = db.RecorderStats()
	}
	s.Dropped += l.dropped.Load()
	return s
}

// RetentionStats returns the retention loop's counters, zero until the
// database opens.
func (l *auditLog) RetentionStats() audit.RetentionStats {
	if db := l.current(); db != nil {
		return db.RetentionStats()
	}
	return audit.RetentionStats{}
}

// Record implements engine.Recorder. It waits for the database to open, so
// the engine's bounded queue holds the decisions meanwhile.
func (l *auditLog) Record(ctx context.Context, ev event.Event, d decision.Decision) {
	db, err := l.wait(ctx)
	if err != nil {
		l.dropped.Add(1)
		return
	}
	db.Record(ctx, ev, d)
}

// The outbox, for the hooks.

func (l *auditLog) Enqueue(ctx context.Context, deliveries []audit.Delivery) (int, error) {
	db, err := l.wait(ctx)
	if err != nil {
		return 0, err
	}
	return db.Enqueue(ctx, deliveries)
}

func (l *auditLog) Claim(ctx context.Context, r audit.ClaimRequest) ([]audit.Delivery, error) {
	db, err := l.wait(ctx)
	if err != nil {
		return nil, err
	}
	return db.Claim(ctx, r)
}

func (l *auditLog) Expire(ctx context.Context, effect string, before time.Time, a audit.Attempt) (int, error) {
	db, err := l.wait(ctx)
	if err != nil {
		return 0, err
	}
	return db.Expire(ctx, effect, before, a)
}

func (l *auditLog) Backlog(ctx context.Context, now time.Time) ([]audit.Backlog, error) {
	db, err := l.wait(ctx)
	if err != nil {
		return nil, err
	}
	return db.Backlog(ctx, now)
}

func (l *auditLog) MarkDelivered(ctx context.Context, id int64, a audit.Attempt) error {
	db, err := l.wait(ctx)
	if err != nil {
		return err
	}
	return db.MarkDelivered(ctx, id, a)
}

func (l *auditLog) Retry(ctx context.Context, id int64, a audit.Attempt, next time.Time) error {
	db, err := l.wait(ctx)
	if err != nil {
		return err
	}
	return db.Retry(ctx, id, a, next)
}

func (l *auditLog) MarkDead(ctx context.Context, id int64, a audit.Attempt) error {
	db, err := l.wait(ctx)
	if err != nil {
		return err
	}
	return db.MarkDead(ctx, id, a)
}

func (l *auditLog) Deliveries(ctx context.Context, decisionID string) ([]audit.Delivery, error) {
	db, err := l.wait(ctx)
	if err != nil {
		return nil, err
	}
	return db.Deliveries(ctx, decisionID)
}

// The API's reads and labels, which fail at once while the database is not
// open rather than hold the request.

func (l *auditLog) Get(ctx context.Context, decisionID string) (audit.Entry, error) {
	db := l.current()
	if db == nil {
		return audit.Entry{}, errAuditNotOpen
	}
	return db.Get(ctx, decisionID)
}

func (l *auditLog) Label(ctx context.Context, decisionID string, lb audit.Label) error {
	db := l.current()
	if db == nil {
		return errAuditNotOpen
	}
	return db.Label(ctx, decisionID, lb)
}

func (l *auditLog) RuleStats(ctx context.Context, since time.Time) ([]precision.RuleStats, error) {
	db := l.current()
	if db == nil {
		return nil, errAuditNotOpen
	}
	return db.RuleStats(ctx, since)
}

func (l *auditLog) ReviewQueue(ctx context.Context, ruleID string, mode decision.Mode, limit int) ([]audit.ReviewItem, error) {
	db := l.current()
	if db == nil {
		return nil, errAuditNotOpen
	}
	return db.ReviewQueue(ctx, ruleID, mode, limit)
}

func (l *auditLog) Flush(ctx context.Context) error {
	db := l.current()
	if db == nil {
		return errAuditNotOpen
	}
	return db.Flush(ctx)
}
