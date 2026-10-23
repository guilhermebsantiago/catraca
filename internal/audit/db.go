package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	_ "modernc.org/sqlite"             // registers the "sqlite" database/sql driver
)

// DB is an audit database on SQLite or Postgres. It implements Store and
// Outbox. It is safe for concurrent use.
type DB struct {
	db      *sql.DB
	dialect dialect
	opts    Options
	log     *slog.Logger

	// mu guards closed and sends on queue, so Record never sends on a
	// closed channel.
	mu       sync.RWMutex
	closed   bool
	queue    chan row
	flushReq chan chan error
	done     chan struct{}

	// writeCtx is the parent of every write of the background writer.
	// Close cancels it with abandon when its context ends, which aborts the
	// write in flight and makes the writer give up on what is left.
	writeCtx context.Context
	abandon  context.CancelFunc
	// closing is set by Close: from then on each batch gets one attempt.
	closing atomic.Bool

	// stopPruning ends the retention loop and pruned is closed once it has
	// returned. Both are nil without a retention.
	stopPruning context.CancelFunc
	pruned      chan struct{}

	closeOnce sync.Once
	closeErr  error

	// pending counts decisions accepted by Record and not yet written or
	// given up on, so Get and Label know when flushing could help.
	pending         atomic.Int64
	recorded        atomic.Uint64
	dropped         atomic.Uint64
	failed          atomic.Uint64
	rejected        atomic.Uint64
	droppedSinceLog atomic.Uint64
	lastDropLog     atomic.Int64
	rejectLog       limiter

	retention retentionCounters
}

// Open opens the audit database named by dsn, creating it and applying
// migrations as needed, and starts the background writer and, with a
// retention, the background deleter. The DSN is one of:
//
//	postgres://user:pass@host:5432/catraca?sslmode=disable   (or postgresql://)
//	sqlite:/var/lib/catraca/audit.db
//	/var/lib/catraca/audit.db                                (SQLite)
//
// The SQLite path ":memory:" opens a private in-memory database.
func Open(ctx context.Context, dsn string, opts Options) (*DB, error) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return OpenPostgres(ctx, dsn, opts)
	case strings.HasPrefix(dsn, "sqlite://"):
		return OpenSQLite(ctx, strings.TrimPrefix(dsn, "sqlite://"), opts)
	case strings.HasPrefix(dsn, "sqlite:"):
		return OpenSQLite(ctx, strings.TrimPrefix(dsn, "sqlite:"), opts)
	case dsn == "":
		return nil, fmt.Errorf("audit: empty DSN")
	default:
		return OpenSQLite(ctx, dsn, opts)
	}
}

// OpenSQLite opens or creates the SQLite database at path. It uses WAL
// journaling, so readers do not wait for the writer, and immediate
// transactions with a busy timeout, so concurrent writers queue instead of
// failing.
func OpenSQLite(ctx context.Context, path string, opts Options) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: empty SQLite path")
	}
	params := "_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL&_foreign_keys=1&_txlock=immediate"
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	db, err := sql.Open("sqlite", path+sep+params)
	if err != nil {
		return nil, fmt.Errorf("audit: open sqlite: %w", err)
	}
	if path == ":memory:" || strings.HasPrefix(path, ":memory:?") {
		// Each connection to ":memory:" is its own database, and closing
		// it drops the data: keep exactly one, and never expire it.
		db.SetMaxOpenConns(1)
	} else {
		opts.Pool.withDefaults().apply(db)
	}
	return open(ctx, db, sqliteDialect, opts)
}

// OpenPostgres connects to the Postgres database at url (a postgres:// URL or
// a key=value connection string, as accepted by pgx).
func OpenPostgres(ctx context.Context, url string, opts Options) (*DB, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("audit: open postgres: %w", err)
	}
	opts.Pool.withDefaults().apply(db)
	return open(ctx, db, postgresDialect, opts)
}

func (p Pool) apply(db *sql.DB) {
	db.SetMaxOpenConns(p.MaxOpen)
	db.SetMaxIdleConns(p.MaxIdle)
	db.SetConnMaxLifetime(p.MaxLifetime)
	db.SetConnMaxIdleTime(p.MaxIdleTime)
}

func open(ctx context.Context, sqlDB *sql.DB, d dialect, opts Options) (*DB, error) {
	if err := opts.validate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	opts = opts.withDefaults()
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("audit: connect to %s: %w", d.name, err)
	}
	if err := migrate(ctx, sqlDB, d); err != nil {
		sqlDB.Close()
		return nil, err
	}
	writeCtx, abandon := context.WithCancel(context.Background())
	db := &DB{
		db:       sqlDB,
		dialect:  d,
		opts:     opts,
		log:      opts.Logger,
		queue:    make(chan row, opts.BufferSize),
		flushReq: make(chan chan error),
		done:     make(chan struct{}),
		writeCtx: writeCtx,
		abandon:  abandon,
	}
	go db.writer()
	if opts.Retention > 0 {
		ctx, stop := context.WithCancel(context.Background())
		db.stopPruning, db.pruned = stop, make(chan struct{})
		go func() {
			defer close(db.pruned)
			db.pruneLoop(ctx)
		}()
	}
	return db, nil
}

// Close stops accepting decisions, writes the ones still queued and closes
// the database. Stop anything using the DB as an Outbox first.
//
// Close writes the queue for as long as ctx allows, and at most 30 seconds
// when ctx has no deadline. When ctx ends first, Close aborts the write in
// flight and gives up on every decision still queued: they are counted as
// failed and logged as one line with their number. It then closes the
// database and returns an error wrapping ctx's. Close is safe to call more
// than once; later calls return the first one's result.
func (db *DB) Close(ctx context.Context) error {
	db.closeOnce.Do(func() { db.closeErr = db.close(ctx) })
	return db.closeErr
}

func (db *DB) close(ctx context.Context) error {
	db.mu.Lock()
	db.closed = true
	db.closing.Store(true)
	close(db.queue)
	db.mu.Unlock()
	if db.stopPruning != nil {
		db.stopPruning()
	}
	if _, ok := ctx.Deadline(); !ok {
		// A database that hangs must not hang the shutdown with it.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, drainTimeout)
		defer cancel()
	}

	var errs []error
	select {
	case <-db.done:
	case <-ctx.Done():
	}
	select {
	case <-db.done:
	default:
		db.abandon()
		// pending still counts the batch whose write was just aborted,
		// which may have committed a moment before: an upper bound.
		if n := db.pending.Load(); n > 0 {
			db.log.Error("audit: closed before every queued decision was written", "unwritten", n, "error", ctx.Err())
			errs = append(errs, fmt.Errorf("audit: close: gave up on %d queued decisions: %w", n, ctx.Err()))
		}
	}
	if db.pruned != nil {
		// Pruning checks for the stop between statements and the stop
		// aborts the statement in flight.
		select {
		case <-db.pruned:
		case <-ctx.Done():
		}
	}
	// After an abandon the writer may still be running, but its writes fail
	// at once, and sql.DB.Close does not wait for them.
	if err := db.db.Close(); err != nil {
		errs = append(errs, fmt.Errorf("audit: close: %w", err))
	}
	db.abandon()
	return errors.Join(errs...)
}

// SQL returns the underlying database handle, for health checks and ad-hoc
// queries. Do not close it; call Close.
func (db *DB) SQL() *sql.DB { return db.db }

// Backend returns "sqlite" or "postgres".
func (db *DB) Backend() string { return db.dialect.name }

// dialect holds what differs between the backends. The schema and queries
// are otherwise shared: both store times as unix microseconds and both
// support ON CONFLICT, RETURNING, partial indexes and FILTER.
type dialect struct {
	name string
	// migrations is the directory of migrationsFS holding this backend's
	// migrations.
	migrations string
	// numbered is true when placeholders are $1, $2... instead of ?.
	numbered bool
	// lockMigrations serializes migrations between processes, run inside the
	// migration transaction. SQLite needs none: an immediate transaction
	// already holds the write lock.
	lockMigrations string
	// skipLocked lets concurrent outbox workers claim different rows, and
	// concurrent retention runs delete different rows.
	skipLocked string
	// refused reports whether a write failed because the database refused
	// the values in it, rather than because it cannot take writes.
	refused func(error) bool
}

var (
	sqliteDialect = dialect{
		name:       "sqlite",
		migrations: "migrations/sqlite",
		refused:    sqliteRefused,
	}
	postgresDialect = dialect{
		name:       "postgres",
		migrations: "migrations/postgres",
		numbered:   true,
		// The key is arbitrary; it only has to be the same for every
		// Catraca process.
		lockMigrations: "SELECT pg_advisory_xact_lock(4708204391077625121)",
		skipLocked:     " FOR UPDATE SKIP LOCKED",
		refused:        postgresRefused,
	}
)

// rebind rewrites ? placeholders for the dialect. Queries in this package
// never contain a literal question mark.
func (d dialect) rebind(q string) string {
	if !d.numbered {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 16)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

// execer is satisfied by *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// maxParams keeps multi-row inserts well under both databases' limits on
// bound parameters per statement.
const maxParams = 8000

// insertMany inserts rows into table with one statement per chunk and
// returns how many rows were inserted. Conflicting rows are skipped.
func (d dialect) insertMany(ctx context.Context, ex execer, table string, cols []string, rows [][]any) (int64, error) {
	perStmt := max(1, maxParams/len(cols))
	var total int64
	for start := 0; start < len(rows); start += perStmt {
		chunk := rows[start:min(start+perStmt, len(rows))]
		var b strings.Builder
		fmt.Fprintf(&b, "INSERT INTO %s (%s) VALUES ", table, strings.Join(cols, ", "))
		args := make([]any, 0, len(chunk)*len(cols))
		n := 0
		for i, r := range chunk {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteByte('(')
			for j := range cols {
				if j > 0 {
					b.WriteString(", ")
				}
				n++
				if d.numbered {
					b.WriteString("$" + strconv.Itoa(n))
				} else {
					b.WriteByte('?')
				}
			}
			b.WriteByte(')')
			args = append(args, r...)
		}
		b.WriteString(" ON CONFLICT DO NOTHING")
		res, err := ex.ExecContext(ctx, b.String(), args...)
		if err != nil {
			return total, fmt.Errorf("insert into %s: %w", table, err)
		}
		if affected, err := res.RowsAffected(); err == nil {
			total += affected
		}
	}
	return total, nil
}

func toMicros(t time.Time) int64 { return t.UnixMicro() }

func fromMicros(us int64) time.Time { return time.UnixMicro(us).UTC() }
