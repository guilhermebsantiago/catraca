package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/signature"
)

const secret = "whsec_test_0123456789"

var quiet = slog.New(slog.DiscardHandler)

// clock is a manual clock for scheduling, so retries need no sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// receiver is a webhook endpoint that records requests and answers with the
// next status in its script (the last one repeats).
type receiver struct {
	t        *testing.T
	mu       sync.Mutex
	statuses []int
	headers  http.Header
	requests []recorded
	srv      *httptest.Server
}

type recorded struct {
	header http.Header
	body   []byte
}

func newReceiver(t *testing.T, statuses ...int) *receiver {
	r := &receiver{t: t, statuses: statuses, headers: http.Header{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		r.mu.Lock()
		r.requests = append(r.requests, recorded{req.Header.Clone(), body})
		status := http.StatusOK
		if len(r.statuses) > 0 {
			status = r.statuses[0]
			if len(r.statuses) > 1 {
				r.statuses = r.statuses[1:]
			}
		}
		for k, v := range r.headers {
			w.Header()[k] = v
		}
		r.mu.Unlock()
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.Method)
		}
		w.WriteHeader(status)
		if status >= 300 {
			io.WriteString(w, "receiver says no")
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) got() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.requests...)
}

func openOutbox(t *testing.T) *audit.DB {
	t.Helper()
	db, err := audit.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "audit.db"), audit.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(context.Background()) })
	return db
}

func newTestDispatcher(t *testing.T, outbox audit.Outbox, cfg Config) (*Dispatcher, *clock) {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = quiet
	}
	d, err := New(outbox, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := &clock{t: time.Now().UTC().Truncate(time.Second)}
	d.now = c.Now
	return d, c
}

func sendEvent() event.Event {
	return event.Event{ID: "ev-1", Type: event.Send, AccountID: "acct-1", APIKeyID: "key-1",
		From: "a@sender.example", To: []string{"b@gmail.com"}, Subject: "hi"}
}

// leakDecision is an enforced block whose rules ask for revoke_key and
// notify; a shadow rule asks for suspend_account, which must not fire.
func leakDecision(id string) decision.Decision {
	return decision.Decision{
		ID:      id,
		EventID: "ev-1",
		Time:    time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Action:  decision.Block,
		Matches: []decision.Match{
			{RuleID: "leaked-key-send", Reason: "API key was found in public", Action: decision.Block,
				Mode: decision.Enforce, Effects: []string{"revoke_key", "notify"}},
			{RuleID: "key-many-ips", Reason: "Key used from many IPs", Action: decision.Hold,
				Mode: decision.Enforce, Effects: []string{"revoke_key"}},
		},
		Shadow: []decision.Match{
			{RuleID: "new-account-burst", Reason: "burst", Action: decision.Block,
				Mode: decision.Shadow, Effects: []string{"suspend_account"}},
		},
	}
}

func deliveries(t *testing.T, db *audit.DB, decisionID string) map[string]audit.Delivery {
	t.Helper()
	ds, err := db.Deliveries(context.Background(), decisionID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]audit.Delivery{}
	for _, d := range ds {
		out[d.Effect] = d
	}
	return out
}

// deliverDue does what a pass of Run does, without its goroutines: for each
// hook it claims what is due, up to the hook's concurrency, attempts it and
// waits for the attempts. It returns how many it attempted.
func deliverDue(t *testing.T, d *Dispatcher) int {
	t.Helper()
	n := 0
	for _, name := range d.names {
		h := d.hooks[name]
		ds, err := d.claim(context.Background(), h, h.Concurrency)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		var wg sync.WaitGroup
		for _, del := range ds {
			wg.Go(func() { d.deliver(context.Background(), h, del) })
		}
		wg.Wait()
		n += len(ds)
	}
	return n
}

// eventually polls cond until it holds, failing the test after timeout.
// The timeout only bounds a failing test: the machine may be slow, so it is
// generous, and nothing waits for it to pass.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDeliverSuccess(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusNoContent)
	d, clk := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: rcv.srv.URL + "/revoke", Secret: secret, Headers: map[string]string{
			"Authorization": "Bearer platform-token", signature.Header: "forged"}},
		{Name: "suspend_account", URL: rcv.srv.URL + "/suspend", Secret: secret},
	}})

	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	if n := deliverDue(t, d); n != 1 {
		t.Fatalf("delivered %d, want 1 (notify has no hook, suspend_account is shadow)", n)
	}
	reqs := rcv.got()
	if len(reqs) != 1 {
		t.Fatalf("receiver got %d requests, want 1", len(reqs))
	}
	req := reqs[0]
	if got, want := req.header.Get(signature.Header), signature.Sign(secret, clk.Now(), req.body); got != want {
		t.Errorf("signature header = %q, want %q", got, want)
	}
	for k, want := range map[string]string{
		IdempotencyKeyHeader: "d1:revoke_key",
		AttemptHeader:        "1",
		"Content-Type":       "application/json",
		"Authorization":      "Bearer platform-token",
	} {
		if got := req.header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	var p Payload
	if err := json.Unmarshal(req.body, &p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	want := Payload{
		Effect: "revoke_key", DecisionID: "d1", EventID: "ev-1", EventType: event.Send,
		AccountID: "acct-1", APIKeyID: "key-1", Action: decision.Block,
		RuleIDs: []string{"leaked-key-send", "key-many-ips"},
		Reasons: []string{"API key was found in public", "Key used from many IPs"},
		Time:    time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	}
	if p.Time.Equal(want.Time) {
		p.Time = want.Time
	}
	if pj, wj := mustJSON(t, p), mustJSON(t, want); pj != wj {
		t.Errorf("payload:\n got %s\nwant %s", pj, wj)
	}
	for _, leak := range []string{"b@gmail.com", "hi\""} {
		if strings.Contains(string(req.body), leak) {
			t.Errorf("payload leaks %q: %s", leak, req.body)
		}
	}

	all := deliveries(t, db, "d1")
	if len(all) != 1 || all["revoke_key"].Status != audit.DeliveryDelivered || all["revoke_key"].LastStatusCode != 204 {
		t.Errorf("outbox = %+v", all)
	}
	if s := d.Stats(); s != (Stats{Enqueued: 1, Delivered: 1}) {
		t.Errorf("Stats = %+v", s)
	}
	if n := deliverDue(t, d); n != 0 {
		t.Errorf("a delivered delivery was attempted again")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRetriesThenSucceeds(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 500, 502, 200)
	d, clk := newTestDispatcher(t, db, Config{
		Hooks:      []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret}},
		MinBackoff: time.Second, MaxBackoff: time.Minute,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))

	if n := deliverDue(t, d); n != 1 {
		t.Fatalf("first round claimed %d", n)
	}
	if n := deliverDue(t, d); n != 0 {
		t.Fatalf("retried before the backoff elapsed")
	}
	pending := deliveries(t, db, "d1")["revoke_key"]
	if pending.Status != audit.DeliveryPending || pending.LastStatusCode != 500 ||
		!strings.Contains(pending.LastError, "HTTP 500: receiver says no") {
		t.Errorf("after a failure: %+v", pending)
	}
	if wait := pending.NextAttemptAt.Sub(clk.Now()); wait < 500*time.Millisecond || wait > time.Second {
		t.Errorf("first backoff = %v, want within [0.5s, 1s]", wait)
	}
	for range 2 {
		clk.Advance(time.Minute)
		if n := deliverDue(t, d); n != 1 {
			t.Fatalf("retry claimed %d", n)
		}
	}

	reqs := rcv.got()
	if len(reqs) != 3 {
		t.Fatalf("receiver got %d requests, want 3", len(reqs))
	}
	for i, r := range reqs {
		if got := r.header.Get(AttemptHeader); got != strconv.Itoa(i+1) {
			t.Errorf("request %d: attempt header %q", i, got)
		}
		if got := r.header.Get(IdempotencyKeyHeader); got != "d1:revoke_key" {
			t.Errorf("request %d: idempotency key %q", i, got)
		}
		if string(r.body) != string(reqs[0].body) {
			t.Errorf("request %d: body changed between attempts", i)
		}
	}
	final := deliveries(t, db, "d1")["revoke_key"]
	if final.Status != audit.DeliveryDelivered || final.Attempts != 3 {
		t.Errorf("final = %+v", final)
	}
	if s := d.Stats(); s.Delivered != 1 || s.Retried != 2 || s.Dead != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

func TestDeadLetter(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusServiceUnavailable)
	d, clk := newTestDispatcher(t, db, Config{
		Hooks:       []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret}},
		MaxAttempts: 3, MinBackoff: time.Second, MaxBackoff: time.Second,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	for range 5 {
		deliverDue(t, d)
		clk.Advance(time.Hour)
	}
	if n := len(rcv.got()); n != 3 {
		t.Errorf("receiver got %d requests, want MaxAttempts = 3", n)
	}
	dead := deliveries(t, db, "d1")["revoke_key"]
	if dead.Status != audit.DeliveryDead || dead.Attempts != 3 || dead.LastStatusCode != 503 ||
		!strings.Contains(dead.LastError, "HTTP 503") {
		t.Errorf("dead letter = %+v", dead)
	}
	if s := d.Stats(); s.Dead != 1 || s.Retried != 2 || s.Delivered != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

func TestNetworkErrorIsRetried(t *testing.T) {
	db := openOutbox(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there now
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: url, Secret: secret}}})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	got := deliveries(t, db, "d1")["revoke_key"]
	if got.Status != audit.DeliveryPending || got.LastStatusCode != 0 || got.LastError == "" {
		t.Errorf("after a network error: %+v", got)
	}
}

func TestTimeoutIsRetried(t *testing.T) {
	db := openOutbox(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: srv.URL, Secret: secret, Timeout: 50 * time.Millisecond}}})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	got := deliveries(t, db, "d1")["revoke_key"]
	if got.Status != audit.DeliveryPending || !strings.Contains(got.LastError, "deadline") {
		t.Errorf("after a timeout: %+v", got)
	}
}

func TestRedirectIsAFailure(t *testing.T) {
	db := openOutbox(t)
	srv := httptest.NewServer(http.RedirectHandler("https://elsewhere.example/", http.StatusFound))
	defer srv.Close()
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: srv.URL, Secret: secret}}})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	if got := deliveries(t, db, "d1")["revoke_key"]; got.Status != audit.DeliveryPending || got.LastStatusCode != 302 {
		t.Errorf("after a redirect: %+v", got)
	}
}

func TestRetryAfterIsHonored(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusTooManyRequests)
	rcv.headers.Set("Retry-After", "120")
	d, clk := newTestDispatcher(t, db, Config{
		Hooks:      []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret}},
		MinBackoff: time.Second, MaxBackoff: time.Hour,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	got := deliveries(t, db, "d1")["revoke_key"]
	if wait := got.NextAttemptAt.Sub(clk.Now()); wait != 120*time.Second {
		t.Errorf("next attempt in %v, want the server's 120s", wait)
	}
}

func TestDispatchIsIdempotent(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 200)
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret},
		{Name: "notify", URL: rcv.srv.URL, Secret: secret},
	}})
	for range 3 {
		d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	}
	for deliverDue(t, d) > 0 {
	}
	keys := map[string]int{}
	for _, r := range rcv.got() {
		keys[r.header.Get(IdempotencyKeyHeader)]++
	}
	if len(keys) != 2 || keys["d1:revoke_key"] != 1 || keys["d1:notify"] != 1 {
		t.Errorf("idempotency keys received = %v, want each effect once", keys)
	}
	if s := d.Stats(); s.Enqueued != 2 || s.Delivered != 2 {
		t.Errorf("Stats = %+v", s)
	}
}

func TestDispatchWithoutEffectsWritesNothing(t *testing.T) {
	db := openOutbox(t)
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}}})
	dec := leakDecision("d1")
	dec.Matches = nil
	d.Dispatch(context.Background(), sendEvent(), dec)
	if all := deliveries(t, db, "d1"); len(all) != 0 {
		t.Errorf("outbox = %+v, want nothing for shadow-only effects", all)
	}
}

func TestDispatchSkipsErroredMatches(t *testing.T) {
	db := openOutbox(t)
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: "https://hooks.example/revoke", Secret: secret},
		{Name: "notify", URL: "https://hooks.example/notify", Secret: secret},
	}})
	dec := leakDecision("d1")
	dec.Matches[0].Errored = true // leaked-key-send failed closed: no effects
	d.Dispatch(context.Background(), sendEvent(), dec)

	all := deliveries(t, db, "d1")
	if len(all) != 1 {
		t.Fatalf("outbox = %+v, want only revoke_key from key-many-ips", all)
	}
	var p Payload
	if err := json.Unmarshal(all["revoke_key"].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.RuleIDs) != 1 || p.RuleIDs[0] != "key-many-ips" {
		t.Errorf("rule_ids = %v, want [key-many-ips]", p.RuleIDs)
	}
}

func TestDispatchSurvivesCanceledContext(t *testing.T) {
	db := openOutbox(t)
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.Dispatch(ctx, sendEvent(), leakDecision("d1"))
	// Dispatch may return before the write ends; the write goes on.
	d.writing.Wait()
	if all := deliveries(t, db, "d1"); len(all) != 1 {
		t.Errorf("outbox = %+v, want the delivery enqueued despite the canceled request", all)
	}
	if s := d.Stats(); s.Enqueued != 1 || s.EnqueueErrors != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

// blockingOutbox holds every Enqueue until release is closed, after telling
// entered.
type blockingOutbox struct {
	audit.Outbox
	entered chan struct{}
	release chan struct{}
}

func newBlockingOutbox(o audit.Outbox) *blockingOutbox {
	return &blockingOutbox{Outbox: o, entered: make(chan struct{}, 16), release: make(chan struct{})}
}

func (b *blockingOutbox) Enqueue(ctx context.Context, ds []audit.Delivery) (int, error) {
	b.entered <- struct{}{}
	<-b.release
	return b.Outbox.Enqueue(ctx, ds)
}

// TestDispatchReturnsWhenTheCallerStopsWaiting checks the dispatch budget:
// Dispatch returns when its context is done, even with the outbox write
// still running, and the write goes on to store the deliveries.
func TestDispatchReturnsWhenTheCallerStopsWaiting(t *testing.T) {
	db := openOutbox(t)
	slow := newBlockingOutbox(db)
	d, _ := newTestDispatcher(t, slow, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret},
		{Name: "notify", URL: "https://hooks.example/", Secret: secret},
	}})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-slow.entered
		cancel()
	}()
	d.Dispatch(ctx, sendEvent(), leakDecision("d1"))
	if s := d.Stats(); s.Deferred != 2 || s.Enqueued != 0 {
		t.Errorf("Stats when Dispatch returned = %+v, want 2 deferred, none enqueued yet", s)
	}
	close(slow.release)
	d.writing.Wait()
	if s := d.Stats(); s.Deferred != 2 || s.Enqueued != 2 || s.EnqueueErrors != 0 {
		t.Errorf("Stats after the write = %+v, want 2 deferred and enqueued", s)
	}
	if all := deliveries(t, db, "d1"); len(all) != 2 {
		t.Errorf("outbox = %+v, want both deliveries written after Dispatch returned", all)
	}
}

// TestDispatchGivesUpWhenWritesPileUp checks that once MaxWrites writes are
// in flight, Dispatch loses new effects at once, counted and logged, instead
// of piling up more.
func TestDispatchGivesUpWhenWritesPileUp(t *testing.T) {
	db := openOutbox(t)
	slow := newBlockingOutbox(db)
	logs := &logBuffer{}
	d, _ := newTestDispatcher(t, slow, Config{
		Hooks:     []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}},
		MaxWrites: 1,
		Logger:    logs.logger(),
	})
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	d.Dispatch(gone, sendEvent(), leakDecision("d1"))
	d.Dispatch(gone, sendEvent(), leakDecision("d2"))
	if s := d.Stats(); s.Deferred != 1 || s.EnqueueErrors != 1 {
		t.Errorf("Stats = %+v, want d1 deferred and d2 lost", s)
	}
	out := logs.String()
	for _, want := range []string{"the outbox is not keeping up", "decision_id=d2", "effects=[revoke_key]", "api_key_id=key-1", "lost_since_last_line=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
	close(slow.release)
	d.writing.Wait()
	if s := d.Stats(); s.Enqueued != 1 {
		t.Errorf("Stats = %+v, want d1 enqueued", s)
	}
}

type failingOutbox struct{ audit.Outbox }

func (failingOutbox) Enqueue(context.Context, []audit.Delivery) (int, error) {
	return 0, errors.New("disk full")
}

func TestDispatchCountsEnqueueErrors(t *testing.T) {
	logs := &logBuffer{}
	d, _ := newTestDispatcher(t, failingOutbox{}, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret},
		{Name: "notify", URL: "https://hooks.example/", Secret: secret},
	}, Logger: logs.logger()})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	if s := d.Stats(); s.EnqueueErrors != 2 || s.Enqueued != 0 || s.Deferred != 0 {
		t.Errorf("Stats = %+v", s)
	}
	// The log is the only trace of a lost effect: it says what to carry out.
	out := logs.String()
	for _, want := range []string{"effects lost", "decision_id=d1", "effects=\"[revoke_key notify]\"", "account_id=acct-1", "api_key_id=key-1", "disk full"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
}

// logBuffer collects log lines from any goroutine.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
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

// TestUnconfiguredEffect checks that a delivery for an effect no hook
// carries out here waits, since an instance with the hook may deliver it,
// shows in the backlog, and is given up once it is older than MaxAge.
func TestUnconfiguredEffect(t *testing.T) {
	db := openOutbox(t)
	old, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}}})
	old.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))

	current, clk := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "notify", URL: "https://hooks.example/", Secret: secret}}})
	if n := deliverDue(t, current); n != 0 {
		t.Errorf("attempted %d deliveries for an effect without a hook", n)
	}
	current.refresh(context.Background())
	if got := deliveries(t, db, "d1")["revoke_key"]; got.Status != audit.DeliveryPending {
		t.Errorf("delivery for an effect without a hook = %+v, want it pending", got)
	}
	want := []audit.Backlog{
		{Effect: "notify"},
		{Effect: "revoke_key", Pending: 1, Due: 1, Oldest: deliveries(t, db, "d1")["revoke_key"].CreatedAt},
	}
	if got := current.Backlog(); !reflect.DeepEqual(got, want) {
		t.Errorf("Backlog:\n got %+v\nwant %+v", got, want)
	}

	clk.Advance(DefaultMaxAge + time.Minute)
	current.refresh(context.Background())
	got := deliveries(t, db, "d1")["revoke_key"]
	if got.Status != audit.DeliveryDead || !strings.Contains(got.LastError, `no hook carries out effect "revoke_key"`) {
		t.Errorf("delivery for an effect without a hook, a day later = %+v", got)
	}
	if s := current.Stats(); s.Expired != 1 || s.Dead != 1 {
		t.Errorf("Stats = %+v", s)
	}
	if got := current.Backlog(); !reflect.DeepEqual(got, []audit.Backlog{{Effect: "notify"}}) {
		t.Errorf("Backlog after it expired = %+v", got)
	}
}

// TestMaxAge checks that a delivery that waited longer than its hook's
// max age is never attempted, and is given up by the backlog refresh.
func TestMaxAge(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 200)
	d, clk := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret, MaxAge: time.Hour},
		{Name: "notify", URL: rcv.srv.URL, Secret: secret},
	}})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	clk.Advance(2 * time.Hour)
	if n := deliverDue(t, d); n != 1 {
		t.Fatalf("attempted %d, want only notify, whose max age is a day", n)
	}
	if got := deliveries(t, db, "d1")["revoke_key"]; got.Status != audit.DeliveryPending || got.Attempts != 0 {
		t.Errorf("an expired delivery was claimed: %+v", got)
	}
	d.refresh(context.Background())
	got := deliveries(t, db, "d1")["revoke_key"]
	if got.Status != audit.DeliveryDead || !strings.Contains(got.LastError, "not delivered within max_age (1h0m0s)") {
		t.Errorf("after the refresh = %+v", got)
	}
	if s := d.Stats(); s.Expired != 1 || s.Dead != 1 || s.Delivered != 1 {
		t.Errorf("Stats = %+v", s)
	}
	if n := len(rcv.got()); n != 1 {
		t.Errorf("receiver got %d requests, want notify's alone", n)
	}
}

// TestRetryPastMaxAgeIsDead checks that a failure whose retry would come
// after the max age ends the delivery at once.
func TestRetryPastMaxAgeIsDead(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusBadGateway)
	d, _ := newTestDispatcher(t, db, Config{
		Hooks:      []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret, MaxAge: 10 * time.Second}},
		MinBackoff: time.Minute,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	got := deliveries(t, db, "d1")["revoke_key"]
	if got.Status != audit.DeliveryDead || got.Attempts != 1 || got.LastStatusCode != 502 ||
		!strings.Contains(got.LastError, "HTTP 502") || !strings.Contains(got.LastError, "past max_age (10s)") {
		t.Errorf("delivery = %+v", got)
	}
	if s := d.Stats(); s.Dead != 1 || s.Retried != 0 || s.Expired != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

func TestMaxAttemptsPerHook(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusServiceUnavailable)
	d, _ := newTestDispatcher(t, db, Config{
		Hooks: []Hook{
			{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret, MaxAttempts: 1},
			{Name: "notify", URL: rcv.srv.URL, Secret: secret},
		},
		MaxAttempts: 5,
	})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	deliverDue(t, d)
	all := deliveries(t, db, "d1")
	if all["revoke_key"].Status != audit.DeliveryDead || all["notify"].Status != audit.DeliveryPending {
		t.Errorf("after one failure each: revoke_key %s, notify %s; want dead and pending", all["revoke_key"].Status, all["notify"].Status)
	}
}

func TestConcurrencyBatches(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, 200)
	d, _ := newTestDispatcher(t, db, Config{
		Hooks:       []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret}},
		Concurrency: 3,
	})
	for _, id := range []string{"d1", "d2", "d3", "d4", "d5", "d6", "d7"} {
		d.Dispatch(context.Background(), sendEvent(), leakDecision(id))
	}
	var rounds []int
	for {
		n := deliverDue(t, d)
		if n == 0 {
			break
		}
		rounds = append(rounds, n)
	}
	if len(rounds) != 3 || rounds[0] != 3 || rounds[1] != 3 || rounds[2] != 1 {
		t.Errorf("rounds = %v, want [3 3 1]", rounds)
	}
	if n := len(rcv.got()); n != 7 {
		t.Errorf("receiver got %d requests, want 7", n)
	}
}

func TestRunDeliversAndStops(t *testing.T) {
	db := openOutbox(t)
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := signature.Verify(secret, r.Header.Get(signature.Header), body, 0); err != nil {
			t.Errorf("Verify: %v", err)
		}
		got <- r.Header.Get(IdempotencyKeyHeader)
	}))
	defer srv.Close()
	d, err := New(db, Config{Hooks: []Hook{{Name: "revoke_key", URL: srv.URL, Secret: secret}},
		PollInterval: time.Hour, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	// The poll interval is an hour: only Dispatch's wake-up can deliver in
	// time.
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	select {
	case key := <-got:
		if key != "d1:revoke_key" {
			t.Errorf("idempotency key = %q", key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not deliver after Dispatch")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestBackoff(t *testing.T) {
	d, _ := newTestDispatcher(t, openOutbox(t), Config{MinBackoff: time.Second, MaxBackoff: 30 * time.Second})
	tests := []struct {
		attempt  int
		lo, hi   time.Duration
		retryAft time.Duration
	}{
		{1, 500 * time.Millisecond, time.Second, 0},
		{2, time.Second, 2 * time.Second, 0},
		{3, 2 * time.Second, 4 * time.Second, 0},
		{5, 8 * time.Second, 16 * time.Second, 0},
		{6, 15 * time.Second, 30 * time.Second, 0},
		{40, 15 * time.Second, 30 * time.Second, 0},
		{1000, 15 * time.Second, 30 * time.Second, 0},
		{1, 20 * time.Second, 20 * time.Second, 20 * time.Second},
		{1, 30 * time.Second, 30 * time.Second, time.Hour},
	}
	for _, tt := range tests {
		for range 50 {
			if got := d.backoff(tt.attempt, tt.retryAft); got < tt.lo || got > tt.hi {
				t.Errorf("backoff(%d, %v) = %v, want within [%v, %v]", tt.attempt, tt.retryAft, got, tt.lo, tt.hi)
				break
			}
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tests := map[string]time.Duration{
		"":                              0,
		"30":                            30 * time.Second,
		"-5":                            0,
		"soon":                          0,
		"Sun, 01 Mar 2026 12:01:00 GMT": time.Minute,
		"Sun, 01 Mar 2026 11:00:00 GMT": 0,
	}
	for in, want := range tests {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestDeliverDuringRotation checks that a hook with previous secrets signs
// each request with the new secret and every previous one, so a receiver
// that knows any of them accepts it, and that a delivery queued before the
// rotation is signed with the secrets of the attempt.
func TestDeliverDuringRotation(t *testing.T) {
	const next, older = "whsec_next_0123456789", "whsec_older_012345678"
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusServiceUnavailable, http.StatusNoContent)
	before, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: rcv.srv.URL, Secret: secret}}})
	before.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	if n := deliverDue(t, before); n != 1 {
		t.Fatalf("attempted %d before the rotation, want 1", n)
	}

	d, clk := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: rcv.srv.URL, Secret: next, PreviousSecrets: []string{secret, older}},
	}})
	clk.Advance(time.Hour)
	if n := deliverDue(t, d); n != 1 {
		t.Fatalf("attempted %d after the rotation, want the retry", n)
	}
	if del := deliveries(t, db, "d1")["revoke_key"]; del.Status != audit.DeliveryDelivered {
		t.Fatalf("delivery %+v, want it delivered", del)
	}
	reqs := rcv.got()
	if len(reqs) != 2 {
		t.Fatalf("receiver got %d requests, want 2", len(reqs))
	}
	if err := signature.Verify(secret, reqs[0].header.Get(signature.Header), reqs[0].body, time.Hour); err != nil {
		t.Errorf("the attempt before the rotation: %v", err)
	}
	req := reqs[1]
	header := req.header.Get(signature.Header)
	if want := signature.SignAll([]string{next, secret, older}, clk.Now(), req.body); header != want {
		t.Errorf("signature header = %q, want %q", header, want)
	}
	for _, s := range []string{next, secret, older} {
		if err := signature.Verify(s, header, req.body, time.Hour); err != nil {
			t.Errorf("a receiver with %s refuses the request: %v", s, err)
		}
	}
}

func TestNewValidates(t *testing.T) {
	db := openOutbox(t)
	ok := Hook{Name: "revoke_key", URL: "https://hooks.example/revoke", Secret: secret}
	tests := map[string][]Hook{
		"no name":              {{URL: ok.URL, Secret: secret}},
		"relative url":         {{Name: "a", URL: "/revoke", Secret: secret}},
		"ftp url":              {{Name: "a", URL: "ftp://hooks.example/", Secret: secret}},
		"no secret":            {{Name: "a", URL: ok.URL}},
		"bad timeout":          {{Name: "a", URL: ok.URL, Secret: secret, Timeout: -time.Second}},
		"duplicate":            {ok, ok},
		"malformed url":        {{Name: "a", URL: "http://[::1", Secret: secret}},
		"negative concurrency": {{Name: "a", URL: ok.URL, Secret: secret, Concurrency: -1}},
		"negative attempts":    {{Name: "a", URL: ok.URL, Secret: secret, MaxAttempts: -1}},
		"negative max age":     {{Name: "a", URL: ok.URL, Secret: secret, MaxAge: -time.Hour}},
		"above the workers":    {{Name: "a", URL: ok.URL, Secret: secret, Concurrency: DefaultWorkers + 1}},
		"empty previous":       {{Name: "a", URL: ok.URL, Secret: secret, PreviousSecrets: []string{"old-secret-0123456789", ""}}},
	}
	for name, hooks := range tests {
		if _, err := New(db, Config{Hooks: hooks}); err == nil {
			t.Errorf("%s: New succeeded, want an error", name)
		}
	}
	if _, err := New(nil, Config{}); err == nil {
		t.Error("nil outbox: want an error")
	}
	d, err := New(db, Config{Hooks: []Hook{ok}})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Configured("revoke_key") || d.Configured("notify") {
		t.Error("Configured reports the wrong hooks")
	}
	h := d.hooks["revoke_key"]
	if h.Timeout != DefaultTimeout || h.Concurrency != DefaultConcurrency || h.MaxAttempts != DefaultMaxAttempts || h.MaxAge != DefaultMaxAge {
		t.Errorf("hook defaults = %+v", h)
	}
	d, err = New(db, Config{Hooks: []Hook{ok}, Workers: 2, MaxAttempts: 3, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if h := d.hooks["revoke_key"]; h.Concurrency != 2 || h.MaxAttempts != 3 || h.MaxAge != time.Hour {
		t.Errorf("hook with the dispatcher's defaults = %+v, want the concurrency capped at the 2 workers", h)
	}
}

// TestSlowHookDoesNotHoldUpOthers runs the dispatcher with one hook whose
// endpoint hangs and one that answers: the second delivers everything while
// the first holds its own concurrency, and no more, of the workers.
func TestSlowHookDoesNotHoldUpOthers(t *testing.T) {
	db := openOutbox(t)
	var (
		mu             sync.Mutex
		hung, maxHung  int
		fastGot        int
		releaseSlow    = make(chan struct{})
		releaseOnClose sync.Once
	)
	release := func() { releaseOnClose.Do(func() { close(releaseSlow) }) }
	t.Cleanup(release)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hung++
		maxHung = max(maxHung, hung)
		mu.Unlock()
		select {
		case <-releaseSlow:
		case <-r.Context().Done():
		}
		mu.Lock()
		hung--
		mu.Unlock()
	}))
	t.Cleanup(slow.Close)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fastGot++
		mu.Unlock()
	}))
	t.Cleanup(fast.Close)

	d, err := New(db, Config{
		Hooks: []Hook{
			{Name: "revoke_key", URL: slow.URL, Secret: secret, Concurrency: 2, Timeout: time.Minute},
			{Name: "notify", URL: fast.URL, Secret: secret, Concurrency: 2},
		},
		Workers:      3,
		PollInterval: time.Hour,
		Logger:       quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	const decisions = 6
	for i := range decisions {
		d.Dispatch(context.Background(), sendEvent(), leakDecision(fmt.Sprintf("d%d", i)))
	}
	eventually(t, 20*time.Second, "the fast hook to get every delivery while the slow one hangs", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return fastGot == decisions
	})
	// The slow hook fills its concurrency, once the fast one leaves it
	// workers, and never goes past it.
	eventually(t, 20*time.Second, "the slow hook to hang on 2 attempts", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return hung == 2
	})
	mu.Lock()
	if maxHung != 2 {
		t.Errorf("the slow hook had %d attempts in flight at most, want its concurrency, 2", maxHung)
	}
	mu.Unlock()

	release()
	eventually(t, 20*time.Second, "every delivery", func() bool { return d.Stats().Delivered == 2*decisions })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not stop")
	}
	if s := d.Stats(); s.Retried != 0 || s.Dead != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

// memOutbox is an outbox with an endless supply of due deliveries for any
// effect, which records the claims made on it.
type memOutbox struct {
	mu     sync.Mutex
	nextID int64
	claims []string
}

func (m *memOutbox) Enqueue(_ context.Context, ds []audit.Delivery) (int, error) { return len(ds), nil }

func (m *memOutbox) Claim(_ context.Context, r audit.ClaimRequest) ([]audit.Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claims = append(m.claims, fmt.Sprintf("%s:%d", r.Effect, r.Limit))
	ds := make([]audit.Delivery, r.Limit)
	for i := range ds {
		m.nextID++
		ds[i] = audit.Delivery{ID: m.nextID, DecisionID: fmt.Sprint(m.nextID), Effect: r.Effect, Payload: []byte(`{}`),
			Attempts: 1, CreatedAt: r.Now}
	}
	return ds, nil
}

func (m *memOutbox) took() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := strings.Join(m.claims, " ")
	m.claims = nil
	return out
}

func (*memOutbox) MarkDelivered(context.Context, int64, audit.Attempt) error    { return nil }
func (*memOutbox) Retry(context.Context, int64, audit.Attempt, time.Time) error { return nil }
func (*memOutbox) MarkDead(context.Context, int64, audit.Attempt) error         { return nil }
func (*memOutbox) Deliveries(context.Context, string) ([]audit.Delivery, error) { return nil, nil }
func (*memOutbox) Backlog(context.Context, time.Time) ([]audit.Backlog, error)  { return nil, nil }
func (*memOutbox) Expire(context.Context, string, time.Time, audit.Attempt) (int, error) {
	return 0, nil
}

// TestWorkersAreShared drives the scheduler by hand: a hook never takes
// more than its concurrency, the hooks share the workers, and a worker that
// comes free goes to the least busy hook.
func TestWorkersAreShared(t *testing.T) {
	// Each send on a hook's channel lets one of its requests answer;
	// closing it lets them all.
	answer := map[string]chan struct{}{"revoke_key": make(chan struct{}), "notify": make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-answer[strings.TrimPrefix(r.URL.Path, "/")]
	}))
	t.Cleanup(srv.Close)
	outbox := &memOutbox{}
	d, _ := newTestDispatcher(t, outbox, Config{
		Hooks: []Hook{
			{Name: "revoke_key", URL: srv.URL + "/revoke_key", Secret: secret, Concurrency: 3, Timeout: time.Minute},
			{Name: "notify", URL: srv.URL + "/notify", Secret: secret, Concurrency: 3, Timeout: time.Minute},
		},
		Workers: 3,
	})
	ctx := context.Background()
	var schedulers []*scheduler
	t.Cleanup(func() {
		for _, ch := range answer {
			close(ch)
		}
		for _, s := range schedulers {
			s.attempts.Wait()
		}
	})
	s := d.newScheduler()
	schedulers = append(schedulers, s)
	busy := func() string {
		return fmt.Sprintf("revoke_key=%d notify=%d free=%d", s.lanes[0].busy, s.lanes[1].busy, s.free)
	}

	s.fill(ctx)
	if got := outbox.took(); got != "revoke_key:3" {
		t.Errorf("first claims = %q, want revoke_key to take every worker, its concurrency", got)
	}
	s.wantAll()
	s.fill(ctx)
	if got := outbox.took(); got != "" {
		t.Errorf("claimed %q with no worker free", got)
	}

	// One revoke_key attempt ends. Its worker goes to notify, the least busy
	// hook, though revoke_key has deliveries due and the rotation would let
	// it go first.
	answer["revoke_key"] <- struct{}{}
	if l := <-s.finished; l.hook.Name != "revoke_key" {
		t.Fatalf("%s finished, want revoke_key", l.hook.Name)
	}
	s.lanes[0].busy--
	s.free++
	s.next = 0
	s.wantAll()
	s.fill(ctx)
	if got := outbox.took(); got != "notify:1" {
		t.Errorf("claims for the freed worker = %q, want notify:1", got)
	}
	if got := busy(); got != "revoke_key=2 notify=1 free=0" {
		t.Errorf("after the freed worker: %s", got)
	}

	// With more workers than both concurrencies, each hook stops at its own.
	d.cfg.Workers = 10
	s = d.newScheduler()
	schedulers = append(schedulers, s)
	s.fill(ctx)
	if got := outbox.took(); got != "revoke_key:3 notify:3" {
		t.Errorf("claims with 10 workers = %q, want each hook's concurrency", got)
	}
	if got := busy(); got != "revoke_key=3 notify=3 free=4" {
		t.Errorf("with 10 workers: %s", got)
	}
}

// TestRunWaitsForWrites checks that Run, when it stops, waits for the
// outbox writes Dispatch left running, so a shutdown does not close the
// audit database under them.
func TestRunWaitsForWrites(t *testing.T) {
	db := openOutbox(t)
	slow := newBlockingOutbox(db)
	d, err := New(slow, Config{Hooks: []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}},
		PollInterval: time.Hour, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	gone, stop := context.WithCancel(context.Background())
	stop()
	d.Dispatch(gone, sendEvent(), leakDecision("d1"))
	<-slow.entered
	cancel()
	select {
	case <-done:
		t.Fatal("Run returned with an outbox write in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(slow.release)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not stop once the write ended")
	}
	if s := d.Stats(); s.Enqueued != 1 {
		t.Errorf("Stats when Run returned = %+v, want the write done", s)
	}
}
