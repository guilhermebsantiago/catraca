package audit

import (
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
		t.Cleanup(func() { db.Close() })
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
	t.Run("CloseDrainsAndReopen", func(t *testing.T) {
		dsn := newDSN(t)
		testCloseDrainsAndReopen(t, dsn, func(opts Options) *DB { return open(t, dsn, opts) })
	})
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

	claim := func(at time.Time) []Delivery {
		t.Helper()
		ds, err := db.Claim(ctx, at, 10, time.Minute)
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		return ds
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
	got, err := db.Claim(ctx, t0.Add(time.Hour), 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].DecisionID != "d0" || got[2].DecisionID != "d2" {
		t.Errorf("Claim(3) = %+v, want the 3 oldest", got)
	}
	if got, _ := db.Claim(ctx, t0.Add(2*time.Second), 10, time.Minute); len(got) != 0 {
		t.Errorf("Claim before d3 is due = %+v", got)
	}
	if got, _ := db.Claim(ctx, t0, 0, time.Minute); len(got) != 0 {
		t.Errorf("Claim(0) = %+v", got)
	}
}

func testCloseDrainsAndReopen(t *testing.T, dsn string, open func(Options) *DB) {
	ctx := context.Background()
	db := open(Options{FlushInterval: time.Hour, Logger: slog.New(slog.DiscardHandler)})
	for i := range 20 {
		id := fmt.Sprintf("d%d", i)
		db.Record(ctx, sendEvent(id), newDecision(id, t0, []string{"a"}, nil))
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := db.Close(); err != nil {
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
	if versions != 1 {
		t.Errorf("schema_migrations has %d rows, want 1", versions)
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
				got, err := db.Claim(ctx, t0, 4, time.Hour)
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
