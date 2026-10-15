package audit

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
		db.Close()
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
	db.Close()
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
	defer db.Close()

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
	defer db.Close()
	db.Record(context.Background(), sendEvent("x"), newDecision("", t0, nil, nil))
	if s := db.RecorderStats(); s.Dropped != 1 || s.Queued != 0 {
		t.Errorf("RecorderStats = %+v, want 1 dropped", s)
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
