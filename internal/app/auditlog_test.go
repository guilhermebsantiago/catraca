package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

var errRefused = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}

func testDecision(id string) (event.Event, decision.Decision) {
	return event.Event{Type: event.Send, AccountID: "acct", Time: time.Now()},
		decision.Decision{ID: id, EventID: id + "-ev", Time: time.Now().UTC(), Action: decision.Allow, RulesetVersion: "v"}
}

// startAuditLog starts an audit log whose open fails while fail says so,
// then opens a SQLite database.
func startAuditLog(t *testing.T, logs io.Writer, fail func(attempt int) error) (*auditLog, *atomic.Int32) {
	t.Helper()
	l := newAuditLog(slog.New(slog.NewTextHandler(logs, nil)))
	l.retryFirst, l.retryMax = 5*time.Millisecond, 20*time.Millisecond
	var attempts atomic.Int32
	path := filepath.Join(t.TempDir(), "audit.db")
	l.start(func(ctx context.Context) (*audit.DB, error) {
		if err := fail(int(attempts.Add(1))); err != nil {
			return nil, err
		}
		return audit.OpenSQLite(ctx, path, audit.Options{})
	})
	t.Cleanup(func() { l.Close(context.Background()) })
	return l, &attempts
}

// TestAuditLogOpensAfterRetrying checks the audit log while its database is
// unreachable and once it opens: decisions wait and are then written, reads
// fail at once, and the attempts are logged.
func TestAuditLogOpensAfterRetrying(t *testing.T) {
	logs := &lockedBuffer{}
	reachable := make(chan struct{})
	l, attempts := startAuditLog(t, logs, func(int) error {
		select {
		case <-reachable:
			return nil
		default:
			return fmt.Errorf("failed to connect: %w", errRefused)
		}
	})
	waitFor(t, "a few attempts", func() bool { return attempts.Load() >= 3 })

	if _, err := l.Get(context.Background(), "x"); !errors.Is(err, api.ErrAuditUnavailable) {
		t.Errorf("Get before the database opens = %v, want ErrAuditUnavailable", err)
	}
	if err := l.Ping(context.Background()); !errors.Is(err, errAuditNotOpen) || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("Ping before the database opens = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := l.Enqueue(ctx, nil); !errors.Is(err, api.ErrAuditUnavailable) {
		t.Errorf("Enqueue = %v, want it to give up with its context", err)
	}
	cancel()
	recorded := make(chan struct{})
	go func() {
		ev, d := testDecision("d1")
		l.Record(context.Background(), ev, d)
		close(recorded)
	}()
	select {
	case <-recorded:
		t.Fatal("Record returned before the database opened")
	case <-time.After(50 * time.Millisecond):
	}

	close(reachable)
	select {
	case <-recorded:
	case <-time.After(5 * time.Second):
		t.Fatal("Record still waits after the database opened")
	}
	if err := l.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if entry, err := l.Get(context.Background(), "d1"); err != nil || entry.Decision.ID != "d1" {
		t.Errorf("Get after the database opened: %+v, %v", entry, err)
	}
	if err := l.Ping(context.Background()); err != nil {
		t.Errorf("Ping after the database opened: %v", err)
	}
	if n := strings.Count(logs.String(), "the audit database is unreachable"); n < 3 {
		t.Errorf("logged %d failed attempts, want one per attempt:\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), "the audit database is open") {
		t.Errorf("no log line when it opened:\n%s", logs)
	}
	select {
	case err := <-l.failed():
		t.Errorf("failed() = %v for an unreachable database", err)
	default:
	}
}

// TestAuditLogStopsOnPermanentErrors checks that an error waiting cannot fix
// is not retried and reaches failed().
func TestAuditLogStopsOnPermanentErrors(t *testing.T) {
	auth := &pgconn.PgError{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"}
	l, attempts := startAuditLog(t, io.Discard, func(int) error { return auth })
	select {
	case err := <-l.failed():
		if !errors.Is(err, auth) {
			t.Errorf("failed() = %v, want the authentication error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a permanent error was not reported")
	}
	time.Sleep(30 * time.Millisecond)
	if n := attempts.Load(); n != 1 {
		t.Errorf("%d attempts, want 1: a permanent error is not retried", n)
	}
}

// TestAuditLogGivesUpOnClose checks that closing the log while its database
// is unreachable releases what waits for it and counts dropped decisions.
func TestAuditLogGivesUpOnClose(t *testing.T) {
	l, _ := startAuditLog(t, io.Discard, func(int) error { return errRefused })
	recorded := make(chan struct{})
	go func() {
		ev, d := testDecision("d1")
		l.Record(context.Background(), ev, d)
		close(recorded)
	}()
	time.Sleep(20 * time.Millisecond)
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recorded:
	case <-time.After(5 * time.Second):
		t.Fatal("Record still waits after Close")
	}
	ev, d := testDecision("d2")
	l.Record(context.Background(), ev, d)
	if got := l.RecorderStats().Dropped; got != 2 {
		t.Errorf("dropped = %d, want 2", got)
	}
	if _, err := l.Claim(context.Background(), time.Now(), 1, time.Second); !errors.Is(err, api.ErrAuditUnavailable) {
		t.Errorf("Claim after Close = %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"refused", fmt.Errorf("audit: connect to postgres: %w", errRefused), true},
		{"dns", &net.DNSError{Err: "no such host", Name: "db.internal", IsNotFound: true}, true},
		{"connect timeout", fmt.Errorf("failed to connect: %w", context.DeadlineExceeded), true},
		{"eof", fmt.Errorf("migrate: %w", io.ErrUnexpectedEOF), true},
		{"starting up", &pgconn.PgError{Code: "57P03"}, true},
		{"too many connections", &pgconn.PgError{Code: "53300"}, true},
		{"connection exception", &pgconn.PgError{Code: "08006"}, true},
		{"password", &pgconn.PgError{Code: "28P01"}, false},
		{"no database", &pgconn.PgError{Code: "3D000"}, false},
		{"syntax", &pgconn.PgError{Code: "42601"}, false},
		{"schema", errors.New("audit: database schema is at version 9, newer than this build of Catraca knows (1)"), false},
	} {
		if got := unreachable(tt.err); got != tt.want {
			t.Errorf("%s: unreachable = %t, want %t", tt.name, got, tt.want)
		}
	}
}

// heldRecorder passes decisions on to next once release is closed, so a test
// can hold them between the engine's queue and the audit log.
type heldRecorder struct {
	next    *auditLog
	release chan struct{}
}

func (r heldRecorder) Record(ctx context.Context, ev event.Event, d decision.Decision) {
	<-r.release
	r.next.Record(ctx, ev, d)
}

// TestAuditReadsSeeEarlierDecisions checks that a read sent after a
// decision is made finds it, while the engine still holds it in its queue:
// Get waits for the queue rather than answer not found.
func TestAuditReadsSeeEarlierDecisions(t *testing.T) {
	l, err := openAuditLog(context.Background(), "sqlite:"+filepath.Join(t.TempDir(), "audit.db"), audit.Options{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(context.Background()) })
	rs, err := rules.Parse([]byte("version: 1\nrules:\n  - id: wide\n    when: event.recipients > 1\n    action: flag\n    reason: wide\n"))
	if err != nil {
		t.Fatal(err)
	}
	cat := signal.NewCatalog(store.NewMemory(), signal.Options{})
	t.Cleanup(func() { cat.Close() })
	rec := heldRecorder{next: l, release: make(chan struct{})}
	eng, err := engine.New(engine.Options{Catalog: cat, Rules: rules.NewHolder(rs), Recorder: rec, Deadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	l.handedOver = eng.Sync
	t.Cleanup(func() {
		select {
		case <-rec.release:
		default:
			close(rec.release)
		}
		eng.Close(context.Background())
	})

	d, err := eng.Decide(context.Background(), event.Event{Type: event.Send, AccountID: "acct", To: []string{"a@x.example", "b@y.example"}})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		entry audit.Entry
		err   error
	}
	got := make(chan result, 1)
	go func() {
		e, err := l.Get(context.Background(), d.ID)
		got <- result{e, err}
	}()
	select {
	case r := <-got:
		t.Fatalf("Get answered before the decision reached the audit log: %+v, %v", r.entry, r.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(rec.release)
	r := <-got
	if r.err != nil || r.entry.Decision.ID != d.ID {
		t.Fatalf("Get = %+v, %v; want the decision", r.entry, r.err)
	}

	// A label and the review queue, right after the next decision.
	d, err = eng.Decide(context.Background(), event.Event{Type: event.Send, AccountID: "acct", To: []string{"a@x.example", "b@y.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Label(context.Background(), d.ID, audit.Label{RuleID: "wide", Verdict: audit.TruePositive, By: "test"}); err != nil {
		t.Errorf("Label right after the decision: %v", err)
	}
	if _, err := eng.Decide(context.Background(), event.Event{Type: event.Send, AccountID: "acct", To: []string{"a@x.example", "b@y.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, err := l.ReviewQueue(context.Background(), "wide", decision.Shadow, 10)
	if err != nil || len(items) != 2 {
		t.Errorf("review queue right after the decisions = %d items, %v; want the 2 unlabeled ones", len(items), err)
	}
}
