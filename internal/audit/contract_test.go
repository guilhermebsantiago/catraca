package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
)

// The contract suite runs every behavior of the audit database against each
// backend. SQLite always runs; Postgres runs when CATRACA_TEST_POSTGRES_URL
// is set, each test in its own schema.

func TestSQLite(t *testing.T) {
	runContract(t, func(t *testing.T) string {
		return "sqlite:" + filepath.Join(t.TempDir(), "audit.db")
	})
}

func TestPostgres(t *testing.T) {
	base := os.Getenv("CATRACA_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set CATRACA_TEST_POSTGRES_URL to run the Postgres contract tests")
	}
	runContract(t, func(t *testing.T) string { return postgresSchemaDSN(t, base) })
}

// postgresSchemaDSN creates a schema for one test, dropped when it ends, and
// returns a DSN whose search_path points at it.
func postgresSchemaDSN(t *testing.T, base string) string {
	t.Helper()
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("catraca_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	switch {
	case !strings.Contains(base, "://"):
		return base + " search_path=" + schema
	case strings.Contains(base, "?"):
		return base + "&search_path=" + schema
	default:
		return base + "?search_path=" + schema
	}
}

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func runContract(t *testing.T, newDSN func(t *testing.T) string) {
	open := func(t *testing.T, dsn string, opts Options) *DB {
		t.Helper()
		db, err := Open(context.Background(), dsn, opts)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { db.Close(context.Background()) })
		return db
	}
	fresh := func(t *testing.T) *DB { return open(t, newDSN(t), Options{}) }

	t.Run("RecordAndGet", func(t *testing.T) { testRecordAndGet(t, fresh(t)) })
	t.Run("FullEventMode", func(t *testing.T) {
		testFullEventMode(t, open(t, newDSN(t), Options{EventMode: EventFull}))
	})
	t.Run("GetNotFound", func(t *testing.T) { testGetNotFound(t, fresh(t)) })
	t.Run("LabelErrors", func(t *testing.T) { testLabelErrors(t, fresh(t)) })
	t.Run("LabelsAndRuleStats", func(t *testing.T) { testLabelsAndRuleStats(t, fresh(t)) })
	t.Run("LatestLabelWins", func(t *testing.T) { testLatestLabelWins(t, fresh(t)) })
	t.Run("ReviewQueue", func(t *testing.T) { testReviewQueue(t, fresh(t)) })
	t.Run("ConcurrentRecord", func(t *testing.T) { testConcurrentRecord(t, fresh(t)) })
	t.Run("DuplicateRecord", func(t *testing.T) { testDuplicateRecord(t, fresh(t)) })
	t.Run("Outbox", func(t *testing.T) { testOutbox(t, fresh(t)) })
	t.Run("OutboxClaimLimit", func(t *testing.T) { testOutboxClaimLimit(t, fresh(t)) })
	t.Run("OutboxConcurrentClaims", func(t *testing.T) { testOutboxConcurrentClaims(t, fresh(t)) })
	t.Run("OutboxClaimPerEffect", func(t *testing.T) { testOutboxClaimPerEffect(t, fresh(t)) })
	t.Run("OutboxExpire", func(t *testing.T) { testOutboxExpire(t, fresh(t)) })
	t.Run("OutboxBacklog", func(t *testing.T) { testOutboxBacklog(t, fresh(t)) })
	t.Run("OutboxRequeue", func(t *testing.T) { testOutboxRequeue(t, fresh(t)) })
	t.Run("MigrateOutbox", func(t *testing.T) {
		dsn := newDSN(t)
		testMigrateOutbox(t, dsn, func(opts Options) *DB { return open(t, dsn, opts) })
	})
	t.Run("LabelClient", func(t *testing.T) { testLabelClient(t, fresh(t)) })
	t.Run("MigrateLabelClient", func(t *testing.T) {
		dsn := newDSN(t)
		testMigrateLabelClient(t, dsn, func(opts Options) *DB { return open(t, dsn, opts) })
	})
	t.Run("CloseDrainsAndReopen", func(t *testing.T) {
		dsn := newDSN(t)
		testCloseDrainsAndReopen(t, dsn, func(opts Options) *DB { return open(t, dsn, opts) })
	})
	t.Run("RefusedRow", func(t *testing.T) {
		logs := &logBuffer{}
		testRefusedRow(t, open(t, newDSN(t), Options{FlushInterval: time.Hour, Logger: logs.logger()}), logs)
	})
	t.Run("CloseHonorsContext", func(t *testing.T) {
		dsn := newDSN(t)
		testCloseHonorsContext(t, dsn, func(opts Options) *DB { return open(t, dsn, opts) })
	})
	t.Run("FlushHonorsContext", func(t *testing.T) {
		dsn := newDSN(t)
		testFlushHonorsContext(t, dsn, open(t, dsn, Options{FlushInterval: time.Hour}))
	})
	t.Run("Pool", func(t *testing.T) {
		db := open(t, newDSN(t), Options{Pool: Pool{MaxOpen: 3, MaxIdle: 5}})
		if got := db.SQL().Stats().MaxOpenConnections; got != 3 {
			t.Errorf("MaxOpenConnections = %d, want 3", got)
		}
		if got := fresh(t).SQL().Stats().MaxOpenConnections; got != DefaultPoolMaxOpen {
			t.Errorf("default MaxOpenConnections = %d, want %d", got, DefaultPoolMaxOpen)
		}
	})
	t.Run("Retention", func(t *testing.T) {
		db := open(t, newDSN(t), Options{Retention: 48 * time.Hour, LabeledRetention: 7 * 24 * time.Hour})
		testRetention(t, db)
	})
	t.Run("LeakReports", func(t *testing.T) { testLeakReports(t, fresh(t)) })
	t.Run("LeakReportsConcurrentClaims", func(t *testing.T) { testLeakReportsConcurrentClaims(t, fresh(t)) })
	t.Run("LeakReportRetention", func(t *testing.T) {
		testLeakReportRetention(t, open(t, newDSN(t), Options{Retention: 48 * time.Hour}))
	})
}

// logBuffer collects log lines from the writer goroutine for a test to read.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuffer) logger() *slog.Logger { return slog.New(slog.NewTextHandler(l, nil)) }

// lockWrites makes every insert into decisions wait, from another
// connection, until the returned function is called.
func lockWrites(t *testing.T, db *DB, dsn string) (release func()) {
	t.Helper()
	ctx := context.Background()
	driver, source, lock := "pgx", dsn, []string{"BEGIN", "LOCK TABLE decisions IN EXCLUSIVE MODE"}
	if db.Backend() == "sqlite" {
		driver, source, lock = "sqlite", strings.TrimPrefix(dsn, "sqlite:"), []string{"BEGIN IMMEDIATE"}
	}
	other, err := sql.Open(driver, source)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range lock {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
				t.Errorf("ROLLBACK: %v", err)
			}
			conn.Close()
			other.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// waitWriter waits for the background writer to exit after Close, so the
// database files are no longer in use when the test ends.
func waitWriter(t *testing.T, db *DB) {
	t.Helper()
	select {
	case <-db.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the writer did not exit")
	}
}

func sendEvent(id string) event.Event {
	return event.Event{
		ID:         "ev-" + id,
		Type:       event.Send,
		Time:       t0,
		AccountID:  "acct-1",
		APIKeyID:   "key-1",
		IP:         "203.0.113.7",
		From:       "Alice <alice@sender.example>",
		To:         []string{"bob@gmail.com", "carol@gmail.com", "dave@yahoo.com"},
		Subject:    "Your invoice is overdue",
		Links:      []string{"https://bit.ly/abc"},
		Attributes: map[string]string{"plan": "free"},
	}
}

// newDecision builds a decision at at with the given enforced and shadow
// rules. A rule id ending in "!" is marked Errored.
func newDecision(id string, at time.Time, enforced, shadow []string) decision.Decision {
	d := decision.Decision{
		ID:             id,
		EventID:        "ev-" + id,
		Time:           at,
		Action:         decision.Allow,
		RulesetVersion: "v1abc",
		LatencyMicros:  420,
	}
	match := func(rule string, mode decision.Mode) decision.Match {
		errored := strings.HasSuffix(rule, "!")
		rule = strings.TrimSuffix(rule, "!")
		return decision.Match{RuleID: rule, Reason: "reason for " + rule, Action: decision.Block, Mode: mode,
			Errored: errored, Effects: []string{"notify"}}
	}
	for _, r := range enforced {
		d.Matches = append(d.Matches, match(r, decision.Enforce))
		d.Action = decision.Block
	}
	for _, r := range shadow {
		d.Shadow = append(d.Shadow, match(r, decision.Shadow))
	}
	return d
}

func record(t *testing.T, db *DB, ds ...decision.Decision) {
	t.Helper()
	for _, d := range ds {
		db.Record(context.Background(), sendEvent(d.ID), d)
	}
	if err := db.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func label(t *testing.T, db *DB, id string, l Label) {
	t.Helper()
	if err := db.Label(context.Background(), id, l); err != nil {
		t.Fatalf("Label(%s, %+v): %v", id, l, err)
	}
}

func statsByKey(t *testing.T, db *DB, since time.Time) map[string]precision.RuleStats {
	t.Helper()
	stats, err := db.RuleStats(context.Background(), since)
	if err != nil {
		t.Fatalf("RuleStats: %v", err)
	}
	out := map[string]precision.RuleStats{}
	for _, s := range stats {
		out[s.RuleID+"/"+string(s.Mode)] = s
	}
	return out
}

func testRecordAndGet(t *testing.T, db *DB) {
	ctx := context.Background()
	d := newDecision("d1", t0, []string{"leaked-key"}, []string{"burst"})
	d.Degraded = true
	d.Errors = []decision.RuleError{{RuleID: "slow", Error: "signal missing"}}
	ev := sendEvent("d1")
	db.Record(ctx, ev, d)

	// No Flush: Get writes the queued decision first.
	got, err := db.Get(ctx, "d1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Decision.Time.Equal(d.Time) {
		t.Errorf("time = %v, want %v", got.Decision.Time, d.Time)
	}
	got.Decision.Time = d.Time
	if !reflect.DeepEqual(got.Decision, d) {
		t.Errorf("decision round trip:\n got %+v\nwant %+v", got.Decision, d)
	}
	sum := sha256.Sum256([]byte(ev.Subject))
	want := StoredEvent{
		ID: "ev-d1", Type: event.Send, Time: t0, AccountID: "acct-1", APIKeyID: "key-1", IP: "203.0.113.7",
		FromDomain: "sender.example", Recipients: 3, RecipientDomains: []string{"gmail.com", "yahoo.com"},
		SubjectSHA256: hex.EncodeToString(sum[:])[:16],
	}
	if !got.Event.Time.Equal(want.Time) {
		t.Errorf("event time = %v, want %v", got.Event.Time, want.Time)
	}
	got.Event.Time = want.Time
	if !reflect.DeepEqual(got.Event, want) {
		t.Errorf("stored event:\n got %+v\nwant %+v", got.Event, want)
	}
	if got.Labels == nil || len(got.Labels) != 0 {
		t.Errorf("labels = %#v, want empty, non-nil", got.Labels)
	}
	raw, _ := json.Marshal(got.Event)
	for _, secret := range []string{"alice@", "bob@", "overdue", "bit.ly", "free"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("minimal event keeps %q: %s", secret, raw)
		}
	}
	if s := db.RecorderStats(); s.Recorded != 1 || s.Dropped != 0 || s.Failed != 0 || s.Queued != 0 {
		t.Errorf("RecorderStats = %+v", s)
	}
}

func testFullEventMode(t *testing.T, db *DB) {
	ev := sendEvent("d1")
	db.Record(context.Background(), ev, newDecision("d1", t0, nil, nil))
	got, err := db.Get(context.Background(), "d1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Event.Full == nil {
		t.Fatal("full mode: Event.Full is nil")
	}
	if got.Event.Full.Subject != ev.Subject || !reflect.DeepEqual(got.Event.Full.To, ev.To) ||
		got.Event.Full.Attributes["plan"] != "free" {
		t.Errorf("full event = %+v", got.Event.Full)
	}
	if got.Event.FromDomain != "sender.example" || got.Event.Recipients != 3 {
		t.Errorf("summary fields missing in full mode: %+v", got.Event)
	}
}

func testGetNotFound(t *testing.T, db *DB) {
	_, err := db.Get(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func testLabelErrors(t *testing.T, db *DB) {
	ctx := context.Background()
	record(t, db, newDecision("d1", t0, []string{"a"}, nil))
	tests := []struct {
		name string
		id   string
		l    Label
		want error
	}{
		{"bad verdict", "d1", Label{Verdict: "maybe", By: "ana"}, ErrInvalidLabel},
		{"no author", "d1", Label{Verdict: TruePositive}, ErrInvalidLabel},
		{"unknown decision", "d404", Label{Verdict: TruePositive, By: "ana"}, ErrNotFound},
		{"rule did not match", "d1", Label{RuleID: "b", Verdict: TruePositive, By: "ana"}, ErrRuleNotMatched},
	}
	for _, tt := range tests {
		if err := db.Label(ctx, tt.id, tt.l); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
	got, err := db.Get(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Labels) != 0 {
		t.Errorf("failed labels were stored: %+v", got.Labels)
	}
	// A decision no rule matched can be labeled; it counts for no rule.
	record(t, db, newDecision("d2", t0, nil, nil))
	label(t, db, "d2", Label{Verdict: TruePositive, By: "ana", Reason: "missed spam"})
}

func testLabelsAndRuleStats(t *testing.T, db *DB) {
	ctx := context.Background()
	since := t0.Add(-time.Hour)
	record(t, db,
		newDecision("d1", t0, []string{"a"}, []string{"b"}),
		newDecision("d2", t0.Add(time.Minute), []string{"a"}, nil),
		newDecision("d3", t0.Add(2*time.Minute), nil, []string{"b"}),
		newDecision("d4", t0.Add(3*time.Minute), []string{"a!"}, []string{"b"}),
		newDecision("old", since.Add(-time.Second), []string{"a"}, nil),
	)
	at := t0.Add(time.Hour).Truncate(time.Microsecond)
	rev := Reversal("support@platform", "customer appeal")
	rev.Time = at
	label(t, db, "d1", rev)
	label(t, db, "d2", Label{RuleID: "a", Verdict: TruePositive, By: "ana", Time: at})
	label(t, db, "d3", Label{Verdict: TruePositive, By: "ana", Time: at})

	stats := statsByKey(t, db, since)
	want := map[string]precision.RuleStats{
		"a/enforce": {RuleID: "a", Mode: decision.Enforce, Matches: 3, Errored: 1, Labeled: 2, TruePositives: 1, FalsePositives: 1},
		"b/shadow":  {RuleID: "b", Mode: decision.Shadow, Matches: 3, Labeled: 2, TruePositives: 1, FalsePositives: 1},
	}
	if !reflect.DeepEqual(stats, want) {
		t.Errorf("RuleStats:\n got %+v\nwant %+v", stats, want)
	}
	if all := statsByKey(t, db, time.Time{}); all["a/enforce"].Matches != 4 {
		t.Errorf("RuleStats(zero) a/enforce = %+v, want 4 matches", all["a/enforce"])
	}

	got, err := db.Get(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	wantLabels := []Label{{Verdict: FalsePositive, By: "support@platform", Reason: "customer appeal", Time: at}}
	if len(got.Labels) != 1 || !got.Labels[0].Time.Equal(at) {
		t.Fatalf("labels = %+v, want %+v", got.Labels, wantLabels)
	}
	got.Labels[0].Time = at
	if !reflect.DeepEqual(got.Labels, wantLabels) {
		t.Errorf("labels = %+v, want %+v", got.Labels, wantLabels)
	}
}

func testLatestLabelWins(t *testing.T, db *DB) {
	ctx := context.Background()
	record(t, db, newDecision("d1", t0, []string{"a"}, []string{"b"}))
	verdicts := func() string {
		s := statsByKey(t, db, time.Time{})
		v := func(k string) string {
			switch {
			case s[k].TruePositives == 1:
				return "TP"
			case s[k].FalsePositives == 1:
				return "FP"
			}
			return "-"
		}
		return v("a/enforce") + " " + v("b/shadow")
	}
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }

	label(t, db, "d1", Label{Verdict: TruePositive, By: "ana", Time: at(10)})
	if got := verdicts(); got != "TP TP" {
		t.Errorf("after decision TP: %s", got)
	}
	label(t, db, "d1", Label{RuleID: "a", Verdict: FalsePositive, By: "bea", Time: at(20)})
	if got := verdicts(); got != "FP TP" {
		t.Errorf("after rule a FP: %s", got)
	}
	label(t, db, "d1", Label{RuleID: "a", Verdict: TruePositive, By: "caio", Time: at(5)})
	if got := verdicts(); got != "FP TP" {
		t.Errorf("an older label replaced a newer one: %s", got)
	}
	label(t, db, "d1", Label{Verdict: FalsePositive, By: "dani", Time: at(20)})
	if got := verdicts(); got != "FP FP" {
		t.Errorf("a later label at the same time should win: %s", got)
	}
	got, err := db.Get(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	var by []string
	for _, l := range got.Labels {
		by = append(by, l.By)
	}
	if strings.Join(by, ",") != "ana,bea,caio,dani" {
		t.Errorf("labels by = %v, want every label in insertion order", by)
	}
}

func testReviewQueue(t *testing.T, db *DB) {
	ctx := context.Background()
	var ds []decision.Decision
	for i := range 6 {
		ds = append(ds, newDecision(fmt.Sprintf("d%d", i), t0.Add(time.Duration(i)*time.Minute), []string{"a"}, []string{"b"}))
	}
	record(t, db, ds...)
	label(t, db, "d5", Label{RuleID: "a", Verdict: TruePositive, By: "ana"})
	label(t, db, "d3", Label{Verdict: FalsePositive, By: "ana"})

	ids := func(items []ReviewItem) string {
		var out []string
		for _, it := range items {
			out = append(out, it.DecisionID+":"+it.RuleID)
		}
		return strings.Join(out, ",")
	}
	tests := []struct {
		rule  string
		mode  decision.Mode
		limit int
		want  string
	}{
		{"a", decision.Enforce, 10, "d4:a,d2:a,d1:a,d0:a"},
		{"a", decision.Enforce, 2, "d4:a,d2:a"},
		{"a", decision.Shadow, 10, ""},
		{"b", "", 10, "d5:b,d4:b,d2:b,d1:b,d0:b"},
		{"", decision.Shadow, 3, "d5:b,d4:b,d2:b"},
	}
	for _, tt := range tests {
		items, err := db.ReviewQueue(ctx, tt.rule, tt.mode, tt.limit)
		if err != nil {
			t.Fatalf("ReviewQueue(%q, %q, %d): %v", tt.rule, tt.mode, tt.limit, err)
		}
		if got := ids(items); got != tt.want {
			t.Errorf("ReviewQueue(%q, %q, %d) = %s, want %s", tt.rule, tt.mode, tt.limit, got, tt.want)
		}
	}

	items, err := db.ReviewQueue(ctx, "a", decision.Enforce, 1)
	if err != nil || len(items) != 1 {
		t.Fatalf("ReviewQueue = %v, %v", items, err)
	}
	it := items[0]
	if it.Mode != decision.Enforce || it.Action != decision.Block || it.Reason != "reason for a" ||
		!it.Time.Equal(t0.Add(4*time.Minute)) || it.Event.AccountID != "acct-1" || it.Event.Recipients != 3 {
		t.Errorf("review item = %+v", it)
	}
	if _, err := db.ReviewQueue(ctx, "a", "sometimes", 1); err == nil {
		t.Error("ReviewQueue with an unknown mode: want an error")
	}
	if items, err := db.ReviewQueue(ctx, "", "", 0); err != nil || len(items) != 9 {
		t.Errorf("ReviewQueue default limit = %d items, %v; want all 9", len(items), err)
	}
}

func testConcurrentRecord(t *testing.T, db *DB) {
	const workers, each = 8, 100
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				id := fmt.Sprintf("w%d-%d", w, i)
				db.Record(context.Background(), sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
			}
		}()
	}
	wg.Wait()
	if err := db.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := db.RecorderStats()
	if s.Recorded != workers*each || s.Dropped != 0 || s.Failed != 0 || s.Queued != 0 {
		t.Errorf("RecorderStats = %+v, want %d recorded", s, workers*each)
	}
	if got := statsByKey(t, db, time.Time{})["a/enforce"].Matches; got != workers*each {
		t.Errorf("matches = %d, want %d", got, workers*each)
	}
}

func testDuplicateRecord(t *testing.T, db *DB) {
	d := newDecision("d1", t0, []string{"a"}, nil)
	record(t, db, d, d)
	record(t, db, d)
	if got := statsByKey(t, db, time.Time{})["a/enforce"].Matches; got != 1 {
		t.Errorf("a decision recorded three times counts %d matches, want 1", got)
	}
}

func testOutbox(t *testing.T, db *DB) {
	ctx := context.Background()
	n, err := db.Enqueue(ctx, []Delivery{
		{DecisionID: "d1", Effect: "revoke_key", Payload: []byte(`{"effect":"revoke_key"}`), CreatedAt: t0},
		{DecisionID: "d1", Effect: "notify", Payload: []byte(`{"effect":"notify"}`), CreatedAt: t0},
	})
	if err != nil || n != 2 {
		t.Fatalf("Enqueue = %d, %v; want 2", n, err)
	}
	n, err = db.Enqueue(ctx, []Delivery{{DecisionID: "d1", Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0}})
	if err != nil || n != 0 {
		t.Fatalf("Enqueue duplicate = %d, %v; want 0", n, err)
	}
	if _, err := db.Enqueue(ctx, []Delivery{{DecisionID: "d1"}}); err == nil {
		t.Error("Enqueue without effect: want an error")
	}

	// claim claims for each hook in turn, revoke_key first.
	claim := func(at time.Time) []Delivery {
		t.Helper()
		var all []Delivery
		for _, effect := range []string{"revoke_key", "notify"} {
			ds, err := db.Claim(ctx, ClaimRequest{Effect: effect, Now: at, Limit: 10, Lease: time.Minute})
			if err != nil {
				t.Fatalf("Claim(%s): %v", effect, err)
			}
			all = append(all, ds...)
		}
		return all
	}
	ds := claim(t0)
	if len(ds) != 2 || ds[0].Effect != "revoke_key" || ds[1].Effect != "notify" {
		t.Fatalf("Claim = %+v, want revoke_key then notify", ds)
	}
	revoke, notify := ds[0], ds[1]
	if revoke.Attempts != 1 || string(revoke.Payload) != `{"effect":"revoke_key"}` || revoke.Status != DeliveryPending ||
		!revoke.CreatedAt.Equal(t0) || !revoke.NextAttemptAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("claimed = %+v", revoke)
	}
	if ds := claim(t0.Add(30 * time.Second)); len(ds) != 0 {
		t.Errorf("leased deliveries were claimed again: %+v", ds)
	}
	if err := db.MarkDelivered(ctx, revoke.ID, Attempt{At: t0.Add(time.Second), StatusCode: 200}); err != nil {
		t.Fatal(err)
	}
	ds = claim(t0.Add(61 * time.Second))
	if len(ds) != 1 || ds[0].ID != notify.ID || ds[0].Attempts != 2 {
		t.Fatalf("after the lease = %+v, want notify on attempt 2", ds)
	}
	if err := db.Retry(ctx, notify.ID, Attempt{At: t0.Add(62 * time.Second), StatusCode: 500, Error: "HTTP 500"},
		t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ds := claim(t0.Add(5 * time.Minute)); len(ds) != 0 {
		t.Errorf("claimed before the retry is due: %+v", ds)
	}
	if ds := claim(t0.Add(10 * time.Minute)); len(ds) != 1 || ds[0].Attempts != 3 {
		t.Fatalf("retry = %+v, want notify on attempt 3", ds)
	}
	if err := db.MarkDead(ctx, notify.ID, Attempt{At: t0.Add(11 * time.Minute), Error: "connection refused"}); err != nil {
		t.Fatal(err)
	}
	// A late failure report cannot revive a settled delivery.
	if err := db.Retry(ctx, notify.ID, Attempt{At: t0.Add(12 * time.Minute)}, t0.Add(13*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ds := claim(t0.Add(time.Hour)); len(ds) != 0 {
		t.Errorf("settled deliveries were claimed: %+v", ds)
	}

	all, err := db.Deliveries(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("Deliveries = %+v", all)
	}
	byEffect := map[string]Delivery{all[0].Effect: all[0], all[1].Effect: all[1]}
	if r := byEffect["revoke_key"]; r.Status != DeliveryDelivered || r.LastStatusCode != 200 || r.Attempts != 1 {
		t.Errorf("revoke_key = %+v", r)
	}
	if n := byEffect["notify"]; n.Status != DeliveryDead || n.Attempts != 3 || n.LastError != "connection refused" ||
		n.LastStatusCode != 0 || !n.UpdatedAt.Equal(t0.Add(11*time.Minute)) {
		t.Errorf("notify = %+v", n)
	}
	if none, err := db.Deliveries(ctx, "d404"); err != nil || len(none) != 0 {
		t.Errorf("Deliveries(unknown) = %v, %v", none, err)
	}

	long := strings.Repeat("é", 2000) + string([]byte{0xff, 0})
	if _, err := db.Enqueue(ctx, []Delivery{{DecisionID: "d2", Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0}}); err != nil {
		t.Fatal(err)
	}
	ds = claim(t0)
	if len(ds) != 1 {
		t.Fatalf("claim d2 = %+v", ds)
	}
	if err := db.Retry(ctx, ds[0].ID, Attempt{At: t0, StatusCode: 502, Error: long}, t0.Add(time.Minute)); err != nil {
		t.Fatalf("Retry with a long, invalid error: %v", err)
	}
}

func testOutboxClaimLimit(t *testing.T, db *DB) {
	ctx := context.Background()
	var ds []Delivery
	for i := range 5 {
		ds = append(ds, Delivery{DecisionID: fmt.Sprintf("d%d", i), Effect: "notify", Payload: []byte(`{}`),
			CreatedAt: t0.Add(time.Duration(i) * time.Second)})
	}
	if _, err := db.Enqueue(ctx, ds); err != nil {
		t.Fatal(err)
	}
	claim := func(at time.Time, limit int) []Delivery {
		t.Helper()
		got, err := db.Claim(ctx, ClaimRequest{Effect: "notify", Now: at, Limit: limit, Lease: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := claim(t0.Add(time.Hour), 3); len(got) != 3 || got[0].DecisionID != "d0" || got[2].DecisionID != "d2" {
		t.Errorf("Claim(3) = %+v, want the 3 oldest", got)
	}
	if got := claim(t0.Add(2*time.Second), 10); len(got) != 0 {
		t.Errorf("Claim before d3 is due = %+v", got)
	}
	if got := claim(t0, 0); len(got) != 0 {
		t.Errorf("Claim(0) = %+v", got)
	}
}

// testOutboxClaimPerEffect checks that each hook claims only its own
// deliveries, however many older ones another hook has waiting, and that
// deliveries past their max age are left for Expire.
func testOutboxClaimPerEffect(t *testing.T, db *DB) {
	ctx := context.Background()
	var ds []Delivery
	for i := range 5 {
		ds = append(ds, Delivery{DecisionID: fmt.Sprintf("slow%d", i), Effect: "notify", Payload: []byte(`{}`),
			CreatedAt: t0.Add(time.Duration(i) * time.Second)})
	}
	ds = append(ds, Delivery{DecisionID: "fast", Effect: "revoke_key", Payload: []byte(`{}`), CreatedAt: t0.Add(time.Minute)})
	if _, err := db.Enqueue(ctx, ds); err != nil {
		t.Fatal(err)
	}
	claim := func(r ClaimRequest) []string {
		t.Helper()
		r.Lease = time.Minute
		got, err := db.Claim(ctx, r)
		if err != nil {
			t.Fatalf("Claim(%+v): %v", r, err)
		}
		var ids []string
		for _, d := range got {
			if d.Effect != r.Effect {
				t.Errorf("Claim(%s) returned a delivery for %s", r.Effect, d.Effect)
			}
			ids = append(ids, d.DecisionID)
		}
		return ids
	}
	now := t0.Add(time.Hour)
	if got := claim(ClaimRequest{Effect: "revoke_key", Now: now, Limit: 1}); !reflect.DeepEqual(got, []string{"fast"}) {
		t.Errorf("Claim(revoke_key) = %v, want fast, ahead of the older notify deliveries", got)
	}
	if got := claim(ClaimRequest{Effect: "notify", Now: now, Limit: 10, QueuedAfter: t0.Add(3 * time.Second)}); !reflect.DeepEqual(got, []string{"slow3", "slow4"}) {
		t.Errorf("Claim(notify, queued after 3s) = %v, want slow3 and slow4", got)
	}
	if got := claim(ClaimRequest{Effect: "suspend_account", Now: now, Limit: 10}); len(got) != 0 {
		t.Errorf("Claim(an effect without deliveries) = %v", got)
	}
}

// testOutboxExpire checks that Expire gives up the due deliveries of one
// effect queued before the cutoff, keeps the error of their last attempt,
// leaves attempts in flight alone and works through more rows than one
// statement changes.
func testOutboxExpire(t *testing.T, db *DB) {
	ctx := context.Background()
	enqueue := func(id, effect string, at time.Time) {
		t.Helper()
		if _, err := db.Enqueue(ctx, []Delivery{{DecisionID: id, Effect: effect, Payload: []byte(`{}`), CreatedAt: at}}); err != nil {
			t.Fatal(err)
		}
	}
	get := func(id string) Delivery {
		t.Helper()
		ds, err := db.Deliveries(ctx, id)
		if err != nil || len(ds) != 1 {
			t.Fatalf("Deliveries(%s) = %v, %v", id, ds, err)
		}
		return ds[0]
	}
	claim := func(at time.Time, limit int, lease time.Duration) []Delivery {
		t.Helper()
		ds, err := db.Claim(ctx, ClaimRequest{Effect: "notify", Now: at, Limit: limit, Lease: lease})
		if err != nil {
			t.Fatal(err)
		}
		return ds
	}

	// failed was attempted once and waits for its retry; inflight is being
	// attempted when Expire runs.
	enqueue("inflight", "notify", t0.Add(-2*time.Second))
	enqueue("failed", "notify", t0.Add(-time.Second))
	if ds := claim(t0, 2, time.Minute); len(ds) != 2 {
		t.Fatalf("claimed %+v", ds)
	}
	if err := db.Retry(ctx, get("failed").ID, Attempt{At: t0, StatusCode: 503, Error: "HTTP 503"}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(2 * time.Hour)
	if ds := claim(at, 1, time.Hour); len(ds) != 1 || ds[0].DecisionID != "inflight" {
		t.Fatalf("claimed %+v, want inflight", ds)
	}
	enqueue("never", "notify", t0)
	enqueue("recent", "notify", t0.Add(90*time.Minute))
	enqueue("other", "revoke_key", t0)
	enqueue("done", "notify", t0)
	if err := db.MarkDelivered(ctx, get("done").ID, Attempt{At: t0, StatusCode: 200}); err != nil {
		t.Fatal(err)
	}

	n, err := db.Expire(ctx, "notify", t0.Add(time.Hour), Attempt{At: at, Error: "older than max_age 1h"})
	if err != nil || n != 2 {
		t.Fatalf("Expire = %d, %v; want failed and never", n, err)
	}
	if d := get("never"); d.Status != DeliveryDead || d.LastError != "older than max_age 1h" || d.LastStatusCode != 0 || !d.UpdatedAt.Equal(at) {
		t.Errorf("never = %+v", d)
	}
	if d := get("failed"); d.Status != DeliveryDead || d.LastError != "older than max_age 1h; last attempt: HTTP 503" || d.LastStatusCode != 503 {
		t.Errorf("failed = %+v, want the reason and the last attempt's error", d)
	}
	for id, want := range map[string]DeliveryStatus{"inflight": DeliveryPending, "recent": DeliveryPending,
		"other": DeliveryPending, "done": DeliveryDelivered} {
		if d := get(id); d.Status != want {
			t.Errorf("%s = %s, want %s", id, d.Status, want)
		}
	}

	// More than one statement's worth.
	var bulk []Delivery
	for i := range expireBatch*2 + 1 {
		bulk = append(bulk, Delivery{DecisionID: fmt.Sprintf("bulk%04d", i), Effect: "bulk", Payload: []byte(`{}`), CreatedAt: t0})
	}
	if _, err := db.Enqueue(ctx, bulk); err != nil {
		t.Fatal(err)
	}
	if n, err := db.Expire(ctx, "bulk", t0.Add(time.Second), Attempt{At: at, Error: "no hook"}); err != nil || n != len(bulk) {
		t.Errorf("Expire(bulk) = %d, %v; want %d", n, err, len(bulk))
	}
}

// testOutboxBacklog checks the pending counts per effect, which delivered
// and dead deliveries are not part of.
func testOutboxBacklog(t *testing.T, db *DB) {
	ctx := context.Background()
	if bl, err := db.Backlog(ctx, t0); err != nil || len(bl) != 0 {
		t.Fatalf("Backlog of an empty outbox = %+v, %v", bl, err)
	}
	var ds []Delivery
	for i, effect := range []string{"notify", "notify", "notify", "notify", "notify", "revoke_key"} {
		ds = append(ds, Delivery{DecisionID: fmt.Sprintf("d%d", i), Effect: effect, Payload: []byte(`{}`),
			CreatedAt: t0.Add(time.Duration(i) * time.Minute)})
	}
	if _, err := db.Enqueue(ctx, ds); err != nil {
		t.Fatal(err)
	}
	// d0 is delivered, d1 dead and d2 waits out a backoff; d3 and d4 are due.
	claimed, err := db.Claim(ctx, ClaimRequest{Effect: "notify", Now: t0.Add(time.Hour), Limit: 3, Lease: time.Minute})
	if err != nil || len(claimed) != 3 {
		t.Fatalf("Claim = %+v, %v", claimed, err)
	}
	at := t0.Add(time.Hour)
	if err := errors.Join(
		db.MarkDelivered(ctx, claimed[0].ID, Attempt{At: at, StatusCode: 200}),
		db.MarkDead(ctx, claimed[1].ID, Attempt{At: at, StatusCode: 500}),
		db.Retry(ctx, claimed[2].ID, Attempt{At: at, StatusCode: 500}, at.Add(time.Hour)),
	); err != nil {
		t.Fatal(err)
	}

	bl, err := db.Backlog(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	want := []Backlog{
		{Effect: "notify", Pending: 3, Due: 2, Oldest: t0.Add(2 * time.Minute)},
		{Effect: "revoke_key", Pending: 1, Due: 1, Oldest: t0.Add(5 * time.Minute)},
	}
	if !reflect.DeepEqual(bl, want) {
		t.Errorf("Backlog:\n got %+v\nwant %+v", bl, want)
	}
	stats, err := db.OutboxStats(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	wantStats := []EffectStats{{Backlog: want[0], Dead: 1, Delivered: 1}, {Backlog: want[1]}}
	if !reflect.DeepEqual(stats, wantStats) {
		t.Errorf("OutboxStats:\n got %+v\nwant %+v", stats, wantStats)
	}
}

// testOutboxRequeue checks listing deliveries and requeueing dead ones,
// which starts their attempts and their max age over.
func testOutboxRequeue(t *testing.T, db *DB) {
	ctx := context.Background()
	ds := []Delivery{
		{DecisionID: "dead1", Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0},
		{DecisionID: "dead2", Effect: "revoke_key", Payload: []byte(`{}`), CreatedAt: t0},
		{DecisionID: "dead3", Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0},
		{DecisionID: "delivered", Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0},
		{DecisionID: "pending", Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0.Add(time.Minute)},
	}
	if _, err := db.Enqueue(ctx, ds); err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, d := range ds {
		got, err := db.Deliveries(ctx, d.DecisionID)
		if err != nil || len(got) != 1 {
			t.Fatalf("Deliveries(%s) = %v, %v", d.DecisionID, got, err)
		}
		ids[d.DecisionID] = got[0].ID
	}
	for i, id := range []string{"dead1", "dead2", "dead3"} {
		if err := db.MarkDead(ctx, ids[id], Attempt{At: t0.Add(time.Duration(i+1) * time.Hour), StatusCode: 503, Error: "HTTP 503"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.MarkDelivered(ctx, ids["delivered"], Attempt{At: t0, StatusCode: 200}); err != nil {
		t.Fatal(err)
	}

	list := func(f DeliveryFilter, limit int) string {
		t.Helper()
		got, err := db.ListDeliveries(ctx, f, limit)
		if err != nil {
			t.Fatalf("ListDeliveries(%+v): %v", f, err)
		}
		var out []string
		for _, d := range got {
			out = append(out, d.DecisionID)
		}
		return strings.Join(out, ",")
	}
	for _, tt := range []struct {
		f     DeliveryFilter
		limit int
		want  string
	}{
		{DeliveryFilter{Status: DeliveryDead}, 10, "dead3,dead2,dead1"},
		{DeliveryFilter{Status: DeliveryDead}, 2, "dead3,dead2"},
		{DeliveryFilter{Status: DeliveryDead, Effect: "notify"}, 10, "dead3,dead1"},
		{DeliveryFilter{Status: DeliveryDead, Since: t0.Add(2 * time.Hour)}, 10, "dead3,dead2"},
		{DeliveryFilter{Status: DeliveryPending}, 10, "pending"},
		{DeliveryFilter{IDs: []int64{ids["dead1"], ids["pending"]}}, 10, "dead1,pending"},
		{DeliveryFilter{}, 10, "dead3,dead2,dead1,pending,delivered"},
	} {
		if got := list(tt.f, tt.limit); got != tt.want {
			t.Errorf("ListDeliveries(%+v, %d) = %s, want %s", tt.f, tt.limit, got, tt.want)
		}
	}
	if _, err := db.ListDeliveries(ctx, DeliveryFilter{Status: "lost"}, 10); err == nil {
		t.Error("ListDeliveries with an unknown status: want an error")
	}

	// Only the dead one of these is requeued; the rest are not dead or do
	// not exist.
	at := t0.Add(5 * time.Hour)
	got, err := db.Requeue(ctx, DeliveryFilter{IDs: []int64{ids["dead1"], ids["delivered"], ids["pending"], 999999}}, at)
	if err != nil || !reflect.DeepEqual(got, []int64{ids["dead1"]}) {
		t.Fatalf("Requeue(ids) = %v, %v; want dead1 alone", got, err)
	}
	d, err := db.Deliveries(ctx, "dead1")
	if err != nil {
		t.Fatal(err)
	}
	if r := d[0]; r.Status != DeliveryPending || r.Attempts != 0 || !r.NextAttemptAt.Equal(at) || !r.RequeuedAt.Equal(at) ||
		!r.QueuedAt().Equal(at) || !r.CreatedAt.Equal(t0) || r.LastError != "HTTP 503" {
		t.Errorf("requeued = %+v", r)
	}
	// Its max age starts over: a claim that skips deliveries queued before
	// an hour ago takes it.
	claimed, err := db.Claim(ctx, ClaimRequest{Effect: "notify", Now: at, Limit: 10, Lease: time.Minute, QueuedAfter: at.Add(-time.Hour)})
	if err != nil || len(claimed) != 1 || claimed[0].DecisionID != "dead1" || claimed[0].Attempts != 1 {
		t.Errorf("Claim after the requeue = %+v, %v; want dead1 on attempt 1", claimed, err)
	}

	if got, err := db.Requeue(ctx, DeliveryFilter{Effect: "notify", Since: t0.Add(2 * time.Hour)}, at); err != nil || !reflect.DeepEqual(got, []int64{ids["dead3"]}) {
		t.Errorf("Requeue(notify since 2h) = %v, %v; want dead3", got, err)
	}
	if _, err := db.Requeue(ctx, DeliveryFilter{Status: DeliveryPending}, at); err == nil {
		t.Error("Requeue of pending deliveries: want an error")
	}
	if got, err := db.Requeue(ctx, DeliveryFilter{}, at); err != nil || !reflect.DeepEqual(got, []int64{ids["dead2"]}) {
		t.Errorf("Requeue(every dead one) = %v, %v; want dead2", got, err)
	}
	if got, err := db.Requeue(ctx, DeliveryFilter{}, at); err != nil || len(got) != 0 {
		t.Errorf("Requeue with nothing dead = %v, %v", got, err)
	}

	// More than one statement's worth.
	var bulk []Delivery
	for i := range expireBatch + 7 {
		bulk = append(bulk, Delivery{DecisionID: fmt.Sprintf("bulk%04d", i), Effect: "bulk", Payload: []byte(`{}`), CreatedAt: t0})
	}
	if _, err := db.Enqueue(ctx, bulk); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Expire(ctx, "bulk", t0.Add(time.Second), Attempt{At: at, Error: "no hook"}); err != nil {
		t.Fatal(err)
	}
	if got, err := db.Requeue(ctx, DeliveryFilter{Effect: "bulk"}, at); err != nil || len(got) != len(bulk) {
		t.Errorf("Requeue(bulk) = %d ids, %v; want %d", len(got), err, len(bulk))
	}
}

// testMigrateOutbox upgrades a database at schema version 2 that has a
// delivery in its outbox: the delivery keeps working, never requeued.
func testMigrateOutbox(t *testing.T, dsn string, open func(Options) *DB) {
	ctx := context.Background()
	driver, source, d := "pgx", dsn, postgresDialect
	if strings.HasPrefix(dsn, "sqlite:") {
		driver, source, d = "sqlite", strings.TrimPrefix(dsn, "sqlite:"), sqliteDialect
	}
	raw, err := sql.Open(driver, source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	ms, err := loadMigrations(d.migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations (
    version       BIGINT PRIMARY KEY,
    name          TEXT NOT NULL,
    applied_at_us BIGINT NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.version > 2 {
			break
		}
		if _, err := raw.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if _, err := raw.ExecContext(ctx, fmt.Sprintf("INSERT INTO schema_migrations (version, name, applied_at_us) VALUES (%d, '%s', 0)", m.version, m.name)); err != nil {
			t.Fatal(err)
		}
	}
	us := toMicros(t0)
	if _, err := raw.ExecContext(ctx, fmt.Sprintf(`INSERT INTO outbox (decision_id, effect, payload, status, attempts, next_attempt_at_us, created_at_us, updated_at_us)
VALUES ('old', 'notify', '{}', 'pending', 0, %d, %d, %d)`, us, us, us)); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db := open(Options{})
	got, err := db.Deliveries(ctx, "old")
	if err != nil || len(got) != 1 {
		t.Fatalf("Deliveries after the upgrade = %+v, %v", got, err)
	}
	if !got[0].RequeuedAt.IsZero() || !got[0].QueuedAt().Equal(t0) {
		t.Errorf("an old delivery = %+v, want it never requeued, queued when created", got[0])
	}
	claimed, err := db.Claim(ctx, ClaimRequest{Effect: "notify", Now: t0, Limit: 1, Lease: time.Minute, QueuedAfter: t0.Add(-time.Hour)})
	if err != nil || len(claimed) != 1 {
		t.Errorf("Claim after the upgrade = %+v, %v", claimed, err)
	}
	index := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'outbox_effect_due'"
	if db.Backend() == "postgres" {
		index = "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'outbox_effect_due'"
	}
	var n int
	if err := db.SQL().QueryRowContext(ctx, index).Scan(&n); err != nil || n != 1 {
		t.Errorf("the outbox_effect_due index: %d, %v", n, err)
	}
}

// testLabelClient checks that a label keeps the API token it was given
// with, apart from its by.
func testLabelClient(t *testing.T, db *DB) {
	record(t, db, newDecision("d1", t0, []string{"a"}, nil))
	label(t, db, "d1", Label{Verdict: TruePositive, By: "ana", Client: "ops", Time: t0})
	label(t, db, "d1", Label{Verdict: FalsePositive, By: "appeals", Time: t0.Add(time.Minute)})
	got, err := db.Get(context.Background(), "d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Labels) != 2 || got.Labels[0].Client != "ops" || got.Labels[0].By != "ana" || got.Labels[1].Client != "" {
		t.Errorf("labels = %+v, want the first given by ana with ops, the second without a client", got.Labels)
	}
}

// testMigrateLabelClient upgrades a database at schema version 4 that has
// a label: the label keeps its by and gets an empty client, and labels
// given after the upgrade keep theirs.
func testMigrateLabelClient(t *testing.T, dsn string, open func(Options) *DB) {
	ctx := context.Background()
	driver, source, d := "pgx", dsn, postgresDialect
	if strings.HasPrefix(dsn, "sqlite:") {
		driver, source, d = "sqlite", strings.TrimPrefix(dsn, "sqlite:"), sqliteDialect
	}
	raw, err := sql.Open(driver, source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	ms, err := loadMigrations(d.migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations (
    version       BIGINT PRIMARY KEY,
    name          TEXT NOT NULL,
    applied_at_us BIGINT NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.version > 4 {
			break
		}
		if _, err := raw.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if _, err := raw.ExecContext(ctx, fmt.Sprintf("INSERT INTO schema_migrations (version, name, applied_at_us) VALUES (%d, '%s', 0)", m.version, m.name)); err != nil {
			t.Fatal(err)
		}
	}
	us := toMicros(t0)
	for _, q := range []string{
		fmt.Sprintf(`INSERT INTO decisions (id, event_id, decided_at_us, action, event_type, account_id, api_key_id, ruleset_version, degraded, decision_json, event_json)
VALUES ('old', 'e', %d, 'allow', 'send', 'acct', '', 'v1', FALSE, '{}', '{}')`, us),
		fmt.Sprintf(`INSERT INTO labels (decision_id, rule_id, verdict, labeled_by, reason, labeled_at_us, created_at_us)
VALUES ('old', '', 'true_positive', 'ana', '', %d, %d)`, us, us),
	} {
		if _, err := raw.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	db := open(Options{})
	label(t, db, "old", Label{Verdict: FalsePositive, By: "bea", Client: "ops", Time: t0.Add(time.Minute)})
	rows, err := db.SQL().QueryContext(ctx, "SELECT labeled_by, client FROM labels WHERE decision_id = 'old' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var by, client string
		if err := rows.Scan(&by, &client); err != nil {
			t.Fatal(err)
		}
		got = append(got, by+"/"+client)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "ana/,bea/ops" {
		t.Errorf("labels after the upgrade = %v, want ana/ (no client) and bea/ops", got)
	}
}

func testCloseDrainsAndReopen(t *testing.T, dsn string, open func(Options) *DB) {
	ctx := context.Background()
	db := open(Options{FlushInterval: time.Hour, Logger: slog.New(slog.DiscardHandler)})
	for i := range 20 {
		id := fmt.Sprintf("d%d", i)
		db.Record(ctx, sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
	}
	if err := db.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := db.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
	db.Record(ctx, sendEvent("late"), newDecision("late", t0, nil, nil))
	if s := db.RecorderStats(); s.Recorded != 20 || s.Dropped != 1 {
		t.Errorf("RecorderStats after Close = %+v, want 20 recorded and 1 dropped", s)
	}
	if err := db.Flush(ctx); err != nil {
		t.Errorf("Flush after Close: %v", err)
	}

	// Reopening runs the migrations again, which must be a no-op.
	db2 := open(Options{})
	if got := statsByKey(t, db2, time.Time{})["a/enforce"].Matches; got != 20 {
		t.Errorf("after reopen: %d matches, want 20", got)
	}
	var versions int
	if err := db2.SQL().QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations(db2.dialect.migrations)
	if err != nil {
		t.Fatal(err)
	}
	if versions != len(ms) {
		t.Errorf("schema_migrations has %d rows, want %d", versions, len(ms))
	}
}

// testRefusedRow checks that a decision the database cannot store costs
// only itself: the rest of its batch is written, and it is counted and
// logged with its id.
func testRefusedRow(t *testing.T, db *DB, logs *logBuffer) {
	ctx := context.Background()
	if db.Backend() == "sqlite" {
		// SQLite stores a NUL byte, so a trigger refuses the row instead.
		if _, err := db.SQL().ExecContext(ctx, `CREATE TRIGGER refuse_poison BEFORE INSERT ON decisions
WHEN NEW.account_id LIKE 'poison%' BEGIN SELECT RAISE(ABORT, 'poison row'); END`); err != nil {
			t.Fatal(err)
		}
	}
	// Postgres text and jsonb cannot hold a NUL byte, so either poison row
	// makes the whole multi-row insert fail.
	poison := func(id string) {
		ev := sendEvent(id)
		ev.AccountID = "poison\x00" + id
		db.Record(ctx, ev, newDecision(id, t0, []string{"a"}, nil))
	}
	good := func(id string) {
		db.Record(ctx, sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
	}
	good("first")
	poison("poison-1")
	good("middle")
	poison("poison-2")
	good("last")
	if err := db.Flush(ctx); err == nil || !strings.Contains(err.Error(), "refused 2 of 5") {
		t.Errorf("Flush = %v, want the 2 refused decisions reported", err)
	}

	for _, id := range []string{"first", "middle", "last"} {
		if _, err := db.Get(ctx, id); err != nil {
			t.Errorf("Get(%s) after a refused row in its batch: %v", id, err)
		}
	}
	for _, id := range []string{"poison-1", "poison-2"} {
		if _, err := db.Get(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%s) = %v, want ErrNotFound", id, err)
		}
	}
	if s := db.RecorderStats(); s.Recorded != 3 || s.Failed != 2 || s.Rejected != 2 || s.Queued != 0 {
		t.Errorf("RecorderStats = %+v, want 3 recorded, 2 failed and rejected", s)
	}
	if got := statsByKey(t, db, time.Time{})["a/enforce"].Matches; got != 3 {
		t.Errorf("matches = %d, want 3", got)
	}
	// One line for the first refused row; the second, in the same second,
	// is only counted.
	out := logs.String()
	if n := strings.Count(out, "the database refused a decision"); n != 1 {
		t.Errorf("logged %d refused rows, want 1 (rate-limited):\n%s", n, out)
	}
	if !strings.Contains(out, "decision_id=poison-1") {
		t.Errorf("the refused decision's id was not logged:\n%s", out)
	}
	if strings.Contains(out, "writing decisions failed") {
		t.Errorf("a refused row was reported as a write failure:\n%s", out)
	}

	// The next batch is written as one again.
	record(t, db, newDecision("after", t0, []string{"a"}, nil))
	if s := db.RecorderStats(); s.Recorded != 4 || s.Rejected != 2 {
		t.Errorf("RecorderStats = %+v, want 4 recorded", s)
	}
}

func testCloseHonorsContext(t *testing.T, dsn string, open func(Options) *DB) {
	logs := &logBuffer{}
	db := open(Options{FlushInterval: time.Hour, Logger: logs.logger()})
	release := lockWrites(t, db, dsn)
	ctx := context.Background()
	for i := range 5 {
		id := fmt.Sprintf("d%d", i)
		db.Record(ctx, sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
	}

	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := db.Close(cctx)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Close took %v with a 300ms deadline", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "gave up on 5 queued decisions") {
		t.Errorf("Close = %v, want the 5 queued decisions given up on a deadline", err)
	}
	if again := db.Close(ctx); again == nil || again.Error() != err.Error() {
		t.Errorf("second Close = %v, want the first one's error", again)
	}
	waitWriter(t, db)
	if s := db.RecorderStats(); s.Recorded != 0 || s.Failed != 5 || s.Queued != 0 {
		t.Errorf("RecorderStats = %+v, want 5 failed", s)
	}
	if out := logs.String(); !strings.Contains(out, "closed before every queued decision was written") ||
		!strings.Contains(out, "unwritten=5") {
		t.Errorf("the decisions given up were not logged:\n%s", out)
	}

	release()
	db2 := open(Options{})
	if _, err := db2.Get(ctx, "d0"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a decision given up on was written: %v", err)
	}
}

func testFlushHonorsContext(t *testing.T, dsn string, db *DB) {
	ctx := context.Background()
	release := lockWrites(t, db, dsn)
	for i := range 3 {
		id := fmt.Sprintf("d%d", i)
		db.Record(ctx, sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
	}
	fctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := db.Flush(fctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Flush with writes blocked = %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Flush took %v with a 200ms deadline", elapsed)
	}
	// Nothing is lost: once the database is free, the same decisions are
	// written.
	release()
	if err := db.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for i := range 3 {
		if _, err := db.Get(ctx, fmt.Sprintf("d%d", i)); err != nil {
			t.Errorf("Get(d%d): %v", i, err)
		}
	}
	if s := db.RecorderStats(); s.Recorded != 3 || s.Failed != 0 {
		t.Errorf("RecorderStats = %+v, want 3 recorded", s)
	}
}

// testRetention runs retention by hand on a DB that keeps unlabeled
// decisions for 48h and labeled ones for 7 days.
func testRetention(t *testing.T, db *DB) {
	ctx := context.Background()
	// The background loop uses the real clock; this test sets its own.
	db.stopPruning()
	<-db.pruned

	// More old decisions than one batch deletes, with labeled ones among
	// them, which every batch must step over.
	const old = pruneBatch*2 + 100
	var ds []decision.Decision
	for i := range old {
		ds = append(ds, newDecision(fmt.Sprintf("old%04d", i), t0.Add(time.Duration(i)*time.Second), []string{"a"}, nil))
	}
	ds = append(ds, newDecision("recent", t0.Add(4*24*time.Hour), []string{"a"}, nil))
	record(t, db, ds...)
	for _, id := range []string{"old0000", fmt.Sprintf("old%04d", pruneBatch+3)} {
		label(t, db, id, Label{Verdict: TruePositive, By: "ana", Time: t0.Add(time.Hour)})
	}

	deliver := func(id string, status DeliveryStatus, at time.Time) {
		t.Helper()
		if _, err := db.Enqueue(ctx, []Delivery{{DecisionID: id, Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0}}); err != nil {
			t.Fatal(err)
		}
		ds, err := db.Deliveries(ctx, id)
		if err != nil || len(ds) != 1 {
			t.Fatalf("Deliveries(%s) = %v, %v", id, ds, err)
		}
		var mark error
		switch status {
		case DeliveryDelivered:
			mark = db.MarkDelivered(ctx, ds[0].ID, Attempt{At: at, StatusCode: 200})
		case DeliveryDead:
			mark = db.MarkDead(ctx, ds[0].ID, Attempt{At: at, Error: "HTTP 500"})
		}
		if mark != nil {
			t.Fatal(mark)
		}
	}
	deliver("delivered-old", DeliveryDelivered, t0)
	deliver("dead-old", DeliveryDead, t0)
	deliver("pending-old", DeliveryPending, t0)
	deliver("delivered-recent", DeliveryDelivered, t0.Add(4*24*time.Hour))

	count := func(q string) int {
		t.Helper()
		var n int
		if err := db.SQL().QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	deliveries := func() string {
		t.Helper()
		var out []string
		for _, id := range []string{"delivered-old", "dead-old", "pending-old", "delivered-recent"} {
			ds, err := db.Deliveries(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if len(ds) == 1 {
				out = append(out, id)
			}
		}
		return strings.Join(out, ",")
	}

	// Five days in: unlabeled decisions from day 0 are past 48h, labeled
	// ones are within 7 days.
	if err := db.prune(ctx, t0.Add(5*24*time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if got := count("SELECT COUNT(*) FROM decisions"); got != 3 {
		t.Errorf("after the first run: %d decisions, want the 2 labeled and the recent one", got)
	}
	for _, id := range []string{"old0000", fmt.Sprintf("old%04d", pruneBatch+3), "recent"} {
		if _, err := db.Get(ctx, id); err != nil {
			t.Errorf("Get(%s): %v", id, err)
		}
	}
	if got := statsByKey(t, db, time.Time{})["a/enforce"]; got.Matches != 3 || got.Labeled != 2 || got.TruePositives != 2 {
		t.Errorf("RuleStats after the first run = %+v, want 3 matches, the 2 labeled ones kept", got)
	}
	if got := deliveries(); got != "pending-old,delivered-recent" {
		t.Errorf("deliveries left = %s, want the pending one and the recent one", got)
	}
	if s := db.RetentionStats(); s.Decisions != old-2 || s.Deliveries != 2 || s.Errors != 0 {
		t.Errorf("RetentionStats = %+v, want %d decisions and 2 deliveries", s, old-2)
	}

	// Eight days in: the recent decision is past 48h, and the labeled ones
	// past 7 days go with their labels.
	if err := db.prune(ctx, t0.Add(8*24*time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if got := count("SELECT COUNT(*) FROM decisions"); got != 0 {
		t.Errorf("after the second run: %d decisions, want 0", got)
	}
	if got := count("SELECT COUNT(*) FROM labels") + count("SELECT COUNT(*) FROM matches"); got != 0 {
		t.Errorf("after the second run: %d labels and matches left, want 0", got)
	}
	if got := deliveries(); got != "pending-old" {
		t.Errorf("deliveries left = %s, want only the pending one", got)
	}
	if s := db.RetentionStats(); s.Decisions != old+1 || s.Deliveries != 3 {
		t.Errorf("RetentionStats = %+v, want %d decisions and 3 deliveries", s, old+1)
	}
}

func testOutboxConcurrentClaims(t *testing.T, db *DB) {
	ctx := context.Background()
	const total = 60
	var ds []Delivery
	for i := range total {
		ds = append(ds, Delivery{DecisionID: fmt.Sprintf("d%d", i), Effect: "notify", Payload: []byte(`{}`), CreatedAt: t0})
	}
	if _, err := db.Enqueue(ctx, ds); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[int64]int{}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for {
				got, err := db.Claim(ctx, ClaimRequest{Effect: "notify", Now: t0, Limit: 4, Lease: time.Hour})
				if err != nil {
					t.Errorf("Claim: %v", err)
					return
				}
				if len(got) == 0 {
					return
				}
				mu.Lock()
				for _, d := range got {
					seen[d.ID]++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != total {
		t.Errorf("claimed %d distinct deliveries, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("delivery %d was claimed %d times", id, n)
		}
	}
}

// leakReport is a report of a token named after key, received at at.
func leakReport(key string, at time.Time) LeakReport {
	return LeakReport{Key: key, TokenSHA256: "sha-" + key, SealedToken: "sealed-" + key, Type: "acme_api_key",
		Source: "commit", URL: "https://github.com/octo/repo/blob/main/" + key, ReceivedAt: at}
}

// leakReportsByKey returns the stored reports by key.
func leakReportsByKey(t *testing.T, db *DB, keys ...string) map[string]LeakReport {
	t.Helper()
	rs, err := db.LeakReportsByKey(context.Background(), keys)
	if err != nil {
		t.Fatalf("LeakReportsByKey: %v", err)
	}
	out := map[string]LeakReport{}
	for _, r := range rs {
		out[r.Key] = r
	}
	return out
}

func testLeakReports(t *testing.T, db *DB) {
	ctx := context.Background()
	n, err := db.AddLeakReports(ctx, []LeakReport{leakReport("r1", t0), leakReport("r2", t0.Add(time.Second)), leakReport("r1", t0)})
	if err != nil || n != 2 {
		t.Fatalf("AddLeakReports = %d, %v; want 2, the repeated report once", n, err)
	}
	if n, err := db.AddLeakReports(ctx, []LeakReport{leakReport("r2", t0.Add(time.Hour))}); err != nil || n != 0 {
		t.Fatalf("AddLeakReports of a stored report = %d, %v; want 0", n, err)
	}
	if _, err := db.AddLeakReports(ctx, []LeakReport{{Key: "r3"}}); err == nil {
		t.Error("AddLeakReports without a token hash: want an error")
	}
	stored := leakReportsByKey(t, db, "r1", "r2", "unknown")
	if len(stored) != 2 {
		t.Fatalf("LeakReportsByKey = %+v, want r1 and r2", stored)
	}
	if r := stored["r1"]; r.TokenSHA256 != "sha-r1" || r.SealedToken != "sealed-r1" || r.Type != "acme_api_key" ||
		r.Source != "commit" || r.URL != "https://github.com/octo/repo/blob/main/r1" || r.Status != LeakReportPending ||
		r.Attempts != 0 || !r.ReceivedAt.Equal(t0) || !r.QueuedAt.Equal(t0) || !r.NextAttemptAt.Equal(t0) {
		t.Errorf("r1 = %+v", r)
	}
	if !stored["r2"].ReceivedAt.Equal(t0.Add(time.Second)) {
		t.Errorf("r2 = %+v, want the first delivery's time", stored["r2"])
	}
	if s, err := db.LeakReportStats(ctx); err != nil || s.Pending != 2 || s.Dead != 0 || !s.OldestPending.Equal(t0) {
		t.Errorf("LeakReportStats = %+v, %v; want 2 pending since t0", s, err)
	}

	claim := func(at time.Time) []LeakReport {
		t.Helper()
		rs, err := db.ClaimLeakReports(ctx, at, 10, time.Minute)
		if err != nil {
			t.Fatalf("ClaimLeakReports: %v", err)
		}
		return rs
	}
	rs := claim(t0.Add(time.Second))
	if len(rs) != 2 || rs[0].Key != "r1" || rs[1].Key != "r2" {
		t.Fatalf("claim = %+v, want r1 then r2", rs)
	}
	r1, r2 := rs[0], rs[1]
	if r1.Attempts != 1 || r1.SealedToken != "sealed-r1" || !r1.NextAttemptAt.Equal(t0.Add(time.Second+time.Minute)) {
		t.Errorf("claimed r1 = %+v", r1)
	}
	if rs := claim(t0.Add(30 * time.Second)); len(rs) != 0 {
		t.Errorf("leased reports were claimed again: %+v", rs)
	}

	// r1's token resolved but its decision failed: the key is kept and the
	// sealed token goes. r2's token did not resolve: it keeps its token.
	if err := db.RetryLeakReport(ctx, r1.ID, LeakAttempt{At: t0.Add(2 * time.Second), Attempt: 1, APIKeyID: "key_1",
		AccountID: "acct_1", Error: "engine down"}, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.RetryLeakReport(ctx, r2.ID, LeakAttempt{At: t0.Add(2 * time.Second), Attempt: 1, Error: "resolver down"},
		t0.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored = leakReportsByKey(t, db, "r1", "r2")
	if r := stored["r1"]; r.APIKeyID != "key_1" || r.AccountID != "acct_1" || r.SealedToken != "" || r.LastError != "engine down" ||
		r.Status != LeakReportPending || !r.NextAttemptAt.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("r1 after a retry with its key = %+v", r)
	}
	if r := stored["r2"]; r.APIKeyID != "" || r.SealedToken != "sealed-r2" || r.LastError != "resolver down" {
		t.Errorf("r2 after a retry without a key = %+v", r)
	}

	rs = claim(t0.Add(2 * time.Minute))
	if len(rs) != 2 || rs[0].Attempts != 2 || rs[1].Attempts != 2 || rs[0].APIKeyID != "key_1" {
		t.Fatalf("claim after the retries = %+v, want both on attempt 2, r1 with its key", rs)
	}
	// A worker whose lease ran out reports its first attempt late: the
	// second claim is the one that counts.
	if err := db.RetryLeakReport(ctx, r2.ID, LeakAttempt{At: t0.Add(3 * time.Minute), Attempt: 1, Error: "late"}, t0); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkLeakReportDead(ctx, r2.ID, LeakAttempt{At: t0.Add(3 * time.Minute), Attempt: 1, Error: "late"}); err != nil {
		t.Fatal(err)
	}
	if r := leakReportsByKey(t, db, "r2")["r2"]; r.Status != LeakReportPending || r.LastError != "resolver down" ||
		!r.NextAttemptAt.Equal(t0.Add(3*time.Minute)) {
		t.Errorf("r2 after a stale attempt reported = %+v, want it untouched", r)
	}

	if err := db.FinishLeakReport(ctx, r1.ID, LeakAttempt{At: t0.Add(150 * time.Second), Attempt: 2, Outcome: "leaked",
		APIKeyID: "key_1", AccountID: "acct_1", DecisionID: "dec_1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkLeakReportDead(ctx, r2.ID, LeakAttempt{At: t0.Add(150 * time.Second), Attempt: 2, Outcome: "resolve_failed",
		Error: "resolver down"}); err != nil {
		t.Fatal(err)
	}
	// Settled reports are not claimed, and a late failure cannot reopen a
	// done one.
	if rs := claim(t0.Add(time.Hour)); len(rs) != 0 {
		t.Errorf("settled reports were claimed: %+v", rs)
	}
	if err := db.RetryLeakReport(ctx, r1.ID, LeakAttempt{At: t0.Add(time.Hour), Attempt: 2, Error: "late"}, t0); err != nil {
		t.Fatal(err)
	}
	stored = leakReportsByKey(t, db, "r1", "r2")
	if r := stored["r1"]; r.Status != LeakReportDone || r.Outcome != "leaked" || r.DecisionID != "dec_1" || r.APIKeyID != "key_1" ||
		r.LastError != "" || r.Attempts != 2 || !r.UpdatedAt.Equal(t0.Add(150*time.Second)) {
		t.Errorf("r1 done = %+v", r)
	}
	if r := stored["r2"]; r.Status != LeakReportDead || r.Outcome != "resolve_failed" || r.SealedToken != "sealed-r2" || r.Attempts != 2 {
		t.Errorf("r2 dead = %+v, want it to keep its token for a retry", r)
	}
	if s, err := db.LeakReportStats(ctx); err != nil || s.Pending != 0 || s.Dead != 1 || !s.OldestPending.IsZero() {
		t.Errorf("LeakReportStats = %+v, %v; want 1 dead", s, err)
	}

	list := func(f LeakReportFilter) []string {
		t.Helper()
		rs, err := db.ListLeakReports(ctx, f)
		if err != nil {
			t.Fatalf("ListLeakReports: %v", err)
		}
		var keys []string
		for _, r := range rs {
			keys = append(keys, r.Key)
		}
		return keys
	}
	if got := list(LeakReportFilter{}); fmt.Sprint(got) != "[r2 r1]" {
		t.Errorf("list = %v, want newest first", got)
	}
	if got := list(LeakReportFilter{Status: LeakReportDead}); fmt.Sprint(got) != "[r2]" {
		t.Errorf("list dead = %v", got)
	}
	if got := list(LeakReportFilter{Limit: 1}); fmt.Sprint(got) != "[r2]" {
		t.Errorf("list limit 1 = %v", got)
	}

	// Requeueing takes dead reports only, and counts their attempts and age
	// afresh.
	requeued := t0.Add(2 * time.Hour)
	if n, err := db.RequeueLeakReports(ctx, requeued, []int64{r1.ID, r2.ID, 404}); err != nil || n != 1 {
		t.Fatalf("RequeueLeakReports = %d, %v; want 1", n, err)
	}
	if r := leakReportsByKey(t, db, "r2")["r2"]; r.Status != LeakReportPending || r.Attempts != 0 || r.Outcome != "" ||
		!r.QueuedAt.Equal(requeued) || !r.NextAttemptAt.Equal(requeued) || !r.ReceivedAt.Equal(t0.Add(time.Second)) ||
		r.SealedToken != "sealed-r2" {
		t.Errorf("r2 requeued = %+v", r)
	}
	if r := leakReportsByKey(t, db, "r1")["r1"]; r.Status != LeakReportDone {
		t.Errorf("r1 after a requeue = %+v, want it still done", r)
	}
	rs = claim(requeued)
	if len(rs) != 1 || rs[0].Key != "r2" || rs[0].Attempts != 1 {
		t.Fatalf("claim after the requeue = %+v", rs)
	}
	if err := db.FinishLeakReport(ctx, rs[0].ID, LeakAttempt{At: requeued, Attempt: 1, Outcome: "not_found"}); err != nil {
		t.Fatal(err)
	}
	if r := leakReportsByKey(t, db, "r2")["r2"]; r.Status != LeakReportDone || r.Outcome != "not_found" || r.SealedToken != "" {
		t.Errorf("r2 done = %+v, want its token gone", r)
	}

	// Values Postgres text cannot hold are made storable, so that one of
	// them cannot refuse its batch every time GitHub sends it.
	odd := leakReport("odd", t0)
	odd.URL, odd.Type = "https://github.com/\x00octo", "type\xff"
	if n, err := db.AddLeakReports(ctx, []LeakReport{odd}); err != nil || n != 1 {
		t.Fatalf("AddLeakReports with NUL and invalid UTF-8 = %d, %v", n, err)
	}
	rs = claim(requeued)
	if len(rs) != 1 || rs[0].URL != "https://github.com/octo" {
		t.Fatalf("claim odd = %+v", rs)
	}
	long := strings.Repeat("é", 2000) + string([]byte{0xff, 0})
	if err := db.RetryLeakReport(ctx, rs[0].ID, LeakAttempt{At: requeued, Attempt: 1, APIKeyID: "key\x00", Error: long},
		requeued.Add(time.Minute)); err != nil {
		t.Fatalf("Retry with a long, invalid error: %v", err)
	}
}

func testLeakReportsConcurrentClaims(t *testing.T, db *DB) {
	ctx := context.Background()
	const total = 60
	var rs []LeakReport
	for i := range total {
		rs = append(rs, leakReport(fmt.Sprintf("r%d", i), t0))
	}
	if _, err := db.AddLeakReports(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[int64]int{}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for {
				got, err := db.ClaimLeakReports(ctx, t0, 4, time.Hour)
				if err != nil {
					t.Errorf("ClaimLeakReports: %v", err)
					return
				}
				if len(got) == 0 {
					return
				}
				mu.Lock()
				for _, r := range got {
					seen[r.ID]++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != total {
		t.Errorf("claimed %d distinct reports, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("report %d was claimed %d times", id, n)
		}
	}
}

// testLeakReportRetention runs retention by hand on a DB that keeps
// finished rows for 48h.
func testLeakReportRetention(t *testing.T, db *DB) {
	ctx := context.Background()
	// The background loop uses the real clock; this test sets its own.
	db.stopPruning()
	<-db.pruned

	settle := func(key string, status LeakReportStatus, at time.Time) {
		t.Helper()
		if _, err := db.AddLeakReports(ctx, []LeakReport{leakReport(key, t0)}); err != nil {
			t.Fatal(err)
		}
		if status == LeakReportPending {
			return
		}
		rs, err := db.ClaimLeakReports(ctx, t0, 1, time.Minute)
		if err != nil || len(rs) != 1 || rs[0].Key != key {
			t.Fatalf("claim %s = %+v, %v", key, rs, err)
		}
		a := LeakAttempt{At: at, Attempt: 1, Outcome: "not_found"}
		if status == LeakReportDone {
			err = db.FinishLeakReport(ctx, rs[0].ID, a)
		} else {
			err = db.MarkLeakReportDead(ctx, rs[0].ID, a)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	settle("done-old", LeakReportDone, t0)
	settle("dead-old", LeakReportDead, t0)
	settle("done-recent", LeakReportDone, t0.Add(4*24*time.Hour))
	settle("pending-old", LeakReportPending, t0)

	if err := db.prune(ctx, t0.Add(5*24*time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	left := leakReportsByKey(t, db, "done-old", "dead-old", "done-recent", "pending-old")
	if _, ok := left["done-recent"]; !ok || len(left) != 2 || left["pending-old"].Status != LeakReportPending {
		t.Errorf("reports left = %v, want the recent one and the pending one", left)
	}
	if s := db.RetentionStats(); s.LeakReports != 2 || s.Errors != 0 {
		t.Errorf("RetentionStats = %+v, want 2 leak reports", s)
	}
}
