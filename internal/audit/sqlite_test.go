package audit

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

func TestOpenDSN(t *testing.T) {
	dir := t.TempDir()
	for _, dsn := range []string{
		filepath.Join(dir, "plain.db"),
		"sqlite:" + filepath.Join(dir, "prefixed.db"),
		":memory:",
	} {
		db, err := Open(context.Background(), dsn, Options{})
		if err != nil {
			t.Errorf("Open(%q): %v", dsn, err)
			continue
		}
		if db.Backend() != "sqlite" {
			t.Errorf("Open(%q).Backend() = %q", dsn, db.Backend())
		}
		record(t, db, newDecision("d1", t0, []string{"a"}, nil))
		if _, err := db.Get(context.Background(), "d1"); err != nil {
			t.Errorf("Open(%q): Get: %v", dsn, err)
		}
		db.Close(context.Background())
	}
	if _, err := Open(context.Background(), "", Options{}); err == nil {
		t.Error("Open(\"\"): want an error")
	}
	if _, err := Open(context.Background(), ":memory:", Options{EventMode: "everything"}); err == nil {
		t.Error("Open with an unknown event mode: want an error")
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := OpenSQLite(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec("INSERT INTO schema_migrations (version, name, applied_at_us) VALUES (999, 'future.sql', 0)"); err != nil {
		t.Fatal(err)
	}
	db.Close(context.Background())
	_, err = OpenSQLite(context.Background(), path, Options{})
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("Open on a newer schema: err = %v, want a version error", err)
	}
}

// TestRecordDropsWhenBufferFull blocks the writer behind another connection's
// write lock and checks that Record keeps returning, dropping what does not
// fit, and that everything it accepted is written once the lock is released.
func TestRecordDropsWhenBufferFull(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	var logs bytes.Buffer
	db, err := OpenSQLite(ctx, path, Options{BufferSize: 4, BatchSize: 1,
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)

	locker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	conn, err := locker.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}

	const total = 50
	start := time.Now()
	for i := range total {
		id := fmt.Sprintf("d%d", i)
		db.Record(ctx, sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Record blocked for %v with the writer stuck", elapsed)
	}
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	s := db.RecorderStats()
	if s.Dropped < total-10 || s.Recorded+s.Dropped != total || s.Failed != 0 {
		t.Errorf("RecorderStats = %+v, want most of %d dropped and the rest recorded", s, total)
	}
	if !strings.Contains(logs.String(), "dropped decisions") || !strings.Contains(logs.String(), "buffer full") {
		t.Errorf("drops were not logged: %s", logs.String())
	}
	// One line for the burst, not one per drop.
	if n := strings.Count(logs.String(), "dropped decisions"); n != 1 {
		t.Errorf("logged drops %d times, want once", n)
	}
}

func TestRecordWithoutIDIsDropped(t *testing.T) {
	db, err := Open(context.Background(), ":memory:", Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	db.Record(context.Background(), sendEvent("x"), newDecision("", t0, nil, nil))
	if s := db.RecorderStats(); s.Dropped != 1 || s.Queued != 0 {
		t.Errorf("RecorderStats = %+v, want 1 dropped", s)
	}
}

// TestUnreachableIsNotRejected checks that a database that cannot take
// writes fails the whole batch after its retries, instead of trying each row
// and counting them as refused.
func TestUnreachableIsNotRejected(t *testing.T) {
	ctx := context.Background()
	logs := &logBuffer{}
	db, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "audit.db"), Options{FlushInterval: time.Hour, Logger: logs.logger()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	// Closing the handle under the writer makes every query and ping fail.
	db.SQL().Close()
	for i := range 4 {
		id := fmt.Sprintf("d%d", i)
		db.Record(ctx, sendEvent(id), newDecision(id, t0, nil, nil))
	}
	if err := db.Flush(ctx); err == nil {
		t.Error("Flush to a closed database: want an error")
	}
	if s := db.RecorderStats(); s.Failed != 4 || s.Rejected != 0 || s.Recorded != 0 {
		t.Errorf("RecorderStats = %+v, want 4 failed and none rejected", s)
	}
	if out := logs.String(); !strings.Contains(out, "writing decisions failed") || strings.Contains(out, "refused") {
		t.Errorf("logs = %s", out)
	}
}

// TestRefused checks which errors make the writer retry a batch row by row:
// the database refusing values, not the database being unavailable.
func TestRefused(t *testing.T) {
	for code, want := range map[string]bool{
		"22021": true,  // invalid byte sequence: a NUL byte in text
		"22P05": true,  // untranslatable character: \u0000 in jsonb
		"23505": true,  // unique violation
		"54000": true,  // program limit exceeded
		"25006": false, // read-only transaction, after a failover
		"53100": false, // disk full
		"57P01": false, // admin shutdown
		"40P01": false, // deadlock
		"":      false,
	} {
		err := fmt.Errorf("insert into decisions: %w", &pgconn.PgError{Code: code})
		if got := postgresRefused(err); got != want {
			t.Errorf("postgresRefused(%q) = %v, want %v", code, got, want)
		}
	}
	if postgresRefused(context.DeadlineExceeded) || sqliteRefused(context.DeadlineExceeded) {
		t.Error("a timeout counts as refused")
	}

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := OpenSQLite(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	insert := "INSERT INTO schema_migrations (version, name, applied_at_us) VALUES (1, 'again', 0)"
	_, err = db.SQL().ExecContext(ctx, insert)
	if err == nil || !sqliteRefused(err) {
		t.Errorf("a primary key violation: refused = false (%v)", err)
	}

	// A write lock held elsewhere is the database being unavailable.
	locker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	conn, err := locker.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	impatient, err := sql.Open("sqlite", path+"?_busy_timeout=10")
	if err != nil {
		t.Fatal(err)
	}
	defer impatient.Close()
	_, err = impatient.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = 999")
	if err == nil || sqliteRefused(err) {
		t.Errorf("a locked database: refused = true (%v)", err)
	}
}

func TestCloseWithNothingQueued(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"), Options{Retention: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// An ended context loses nothing when nothing is queued, and stops the
	// retention loop at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := db.Close(ctx); err != nil {
		t.Errorf("Close with nothing queued = %v", err)
	}
	waitWriter(t, db)
	select {
	case <-db.pruned:
	case <-time.After(5 * time.Second):
		t.Error("the retention loop did not stop")
	}
}

func TestOptionsValidation(t *testing.T) {
	day := 24 * time.Hour
	for _, tt := range []struct {
		name string
		opts Options
		want string
	}{
		{"short retention", Options{Retention: time.Hour}, "retention must be at least 24h"},
		{"negative retention", Options{Retention: -day}, "cannot be negative"},
		{"labeled without retention", Options{LabeledRetention: 30 * day}, "needs a retention"},
		{"labeled shorter", Options{Retention: 30 * day, LabeledRetention: 7 * day}, "must be at least the retention"},
		{"sample above 1", Options{SampleAllowed: 1.5}, "must be from 0 to 1"},
		{"sample negative", Options{SampleAllowed: -0.1}, "must be from 0 to 1"},
		{"sample NaN", Options{SampleAllowed: math.NaN()}, "must be from 0 to 1"},
		{"negative prune batch", Options{PruneBatch: -1}, "cannot be negative"},
		{"negative prune pause", Options{PrunePause: -time.Second}, "cannot be negative"},
	} {
		_, err := Open(context.Background(), ":memory:", tt.opts)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Open = %v, want %q", tt.name, err, tt.want)
		}
	}
	db, err := Open(context.Background(), ":memory:", Options{Retention: 30 * day, LabeledRetention: 30 * day})
	if err != nil {
		t.Fatalf("equal retentions: %v", err)
	}
	db.Close(context.Background())
}

func TestRetentionDefaults(t *testing.T) {
	db, err := Open(context.Background(), ":memory:", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	if db.opts.PruneBatch != 500 || db.opts.PrunePause != 0 {
		t.Errorf("SQLite PruneBatch, PrunePause = %d, %v; want 500 and as long as each batch took", db.opts.PruneBatch, db.opts.PrunePause)
	}
	if postgresDialect.pruneBatch != 5000 || postgresDialect.prunePause != 10*time.Millisecond {
		t.Errorf("Postgres PruneBatch, PrunePause = %d, %v; want 5000, 10ms", postgresDialect.pruneBatch, postgresDialect.prunePause)
	}
	if db.opts.SampleAllowed != 1 {
		t.Errorf("SampleAllowed = %g, want 1", db.opts.SampleAllowed)
	}
}

// TestKeepAllow checks that sampling keeps about the share asked for, the
// same ids every time, even for ids that differ only at the end, as
// decision ids made in the same millisecond do.
func TestKeepAllow(t *testing.T) {
	const n = 20000
	for _, rate := range []float64{0.01, 0.1, 0.5, 0.9} {
		kept := 0
		for i := range n {
			id := fmt.Sprintf("01JBX5Q8ZK7Y3M2N4P6R8T%04d", i)
			keep := KeepAllow(id, rate)
			if keep != KeepAllow(id, rate) {
				t.Fatalf("KeepAllow(%s, %g) changed between calls", id, rate)
			}
			if keep {
				kept++
			}
		}
		// Five standard deviations of a binomial: never by chance.
		want := rate * n
		if tol := 5 * math.Sqrt(n*rate*(1-rate)); math.Abs(float64(kept)-want) > tol {
			t.Errorf("KeepAllow at %g kept %d of %d, want %.0f ± %.0f", rate, kept, n, want, tol)
		}
	}
	// A lower rate keeps a subset of what a higher one keeps.
	for i := range 1000 {
		id := fmt.Sprintf("id-%d", i)
		if KeepAllow(id, 0.1) && !KeepAllow(id, 0.5) {
			t.Fatalf("%s is kept at 0.1 but not at 0.5", id)
		}
	}
	if !KeepAllow("anything", 1) || KeepAllow("anything", 0) {
		t.Error("KeepAllow must keep everything at 1 and nothing at 0")
	}
}

func TestPoolDefaults(t *testing.T) {
	got := Pool{}.withDefaults()
	want := Pool{MaxOpen: 10, MaxIdle: 10, MaxLifetime: 30 * time.Minute, MaxIdleTime: 5 * time.Minute}
	if got != want {
		t.Errorf("Pool{}.withDefaults() = %+v, want %+v", got, want)
	}
	if got := (Pool{MaxOpen: 4, MaxIdle: 8}).withDefaults(); got.MaxIdle != 4 {
		t.Errorf("MaxIdle above MaxOpen = %d, want 4", got.MaxIdle)
	}
	// An in-memory database is its one connection, whatever the pool says.
	db, err := Open(context.Background(), ":memory:", Options{Pool: Pool{MaxOpen: 5}})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	if got := db.SQL().Stats().MaxOpenConnections; got != 1 {
		t.Errorf(":memory: MaxOpenConnections = %d, want 1", got)
	}
}

func TestNewStoredEvent(t *testing.T) {
	ev := event.Event{
		Type:      event.Feedback,
		AccountID: "acct-1",
		Feedback:  &event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent", Recipient: "x@y.example", MessageID: "m1"},
	}
	s := NewStoredEvent(ev, EventMinimal)
	if s.FeedbackKind != event.Bounce || s.BounceType != "permanent" || s.SubjectSHA256 != "" || s.Full != nil {
		t.Errorf("feedback event = %+v", s)
	}

	signup := NewStoredEvent(event.Event{Type: event.Account, AccountID: "a", Account: &event.AccountInfo{Action: "signup"}}, EventMinimal)
	if signup.AccountAction != "signup" {
		t.Errorf("account event = %+v", signup)
	}

	var to []string
	for i := range 250 {
		to = append(to, fmt.Sprintf("user@d%d.example", i%150), "no-domain")
	}
	many := NewStoredEvent(event.Event{Type: event.Send, AccountID: "a", To: to}, EventMinimal)
	if many.Recipients != 500 || len(many.RecipientDomains) != maxRecipientDomains || many.RecipientDomains[0] != "d0.example" {
		t.Errorf("recipients = %d, domains = %d (first %q)", many.Recipients, len(many.RecipientDomains), many.RecipientDomains[0])
	}
}

func TestParseEventMode(t *testing.T) {
	for in, want := range map[string]EventMode{"": EventMinimal, "minimal": EventMinimal, "full": EventFull} {
		if got, err := ParseEventMode(in); err != nil || got != want {
			t.Errorf("ParseEventMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseEventMode("all"); err == nil {
		t.Error("ParseEventMode(all): want an error")
	}
}

func TestRebind(t *testing.T) {
	q := "SELECT a FROM t WHERE b = ? AND c IN (?, ?)"
	if got := sqliteDialect.rebind(q); got != q {
		t.Errorf("sqlite rebind = %q", got)
	}
	if got, want := postgresDialect.rebind(q), "SELECT a FROM t WHERE b = $1 AND c IN ($2, $3)"; got != want {
		t.Errorf("postgres rebind = %q, want %q", got, want)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short"); got != "short" {
		t.Errorf("truncate(short) = %q", got)
	}
	got := truncate(strings.Repeat("é", 1000) + string([]byte{0xff, 0}))
	if !utf8.ValidString(got) || strings.ContainsRune(got, 0) || len(got) > maxErrorLen+3 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncate produced %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
}

func TestLoadMigrations(t *testing.T) {
	for _, d := range []dialect{sqliteDialect, postgresDialect} {
		ms, err := loadMigrations(d.migrations)
		if err != nil {
			t.Fatalf("%s: %v", d.name, err)
		}
		if len(ms) == 0 || ms[0].version != 1 {
			t.Errorf("%s migrations = %+v", d.name, ms)
		}
	}
	// Both backends must have the same migration versions.
	s, _ := loadMigrations(sqliteDialect.migrations)
	p, _ := loadMigrations(postgresDialect.migrations)
	if len(s) != len(p) {
		t.Fatalf("sqlite has %d migrations, postgres %d", len(s), len(p))
	}
	for i := range s {
		if s[i].name != p[i].name {
			t.Errorf("migration %d: sqlite %s, postgres %s", i, s[i].name, p[i].name)
		}
	}
}
