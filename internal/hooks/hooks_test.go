package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
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
	t.Cleanup(func() { db.Close() })
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

func deliverDue(t *testing.T, d *Dispatcher) int {
	t.Helper()
	n, err := d.deliverDue(context.Background())
	if err != nil {
		t.Fatalf("deliverDue: %v", err)
	}
	return n
}

func TestDeliverSuccess(t *testing.T) {
	db := openOutbox(t)
	rcv := newReceiver(t, http.StatusNoContent)
	d, clk := newTestDispatcher(t, db, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: rcv.srv.URL + "/revoke", Secret: secret, Headers: map[string]string{
			"Authorization": "Bearer platform-token", SignatureHeader: "forged"}},
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
	if err := verify(secret, req.header.Get(SignatureHeader), req.body, time.Minute, clk.Now()); err != nil {
		t.Errorf("signature does not verify: %v (header %q)", err, req.header.Get(SignatureHeader))
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

func TestDispatchSurvivesCanceledContext(t *testing.T) {
	db := openOutbox(t)
	d, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.Dispatch(ctx, sendEvent(), leakDecision("d1"))
	if all := deliveries(t, db, "d1"); len(all) != 1 {
		t.Errorf("outbox = %+v, want the delivery enqueued despite the canceled request", all)
	}
}

type failingOutbox struct{ audit.Outbox }

func (failingOutbox) Enqueue(context.Context, []audit.Delivery) (int, error) {
	return 0, errors.New("disk full")
}

func TestDispatchCountsEnqueueErrors(t *testing.T) {
	d, _ := newTestDispatcher(t, failingOutbox{}, Config{Hooks: []Hook{
		{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret},
		{Name: "notify", URL: "https://hooks.example/", Secret: secret},
	}})
	d.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))
	if s := d.Stats(); s.EnqueueErrors != 2 || s.Enqueued != 0 {
		t.Errorf("Stats = %+v", s)
	}
}

func TestRemovedHookGoesDead(t *testing.T) {
	db := openOutbox(t)
	old, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "revoke_key", URL: "https://hooks.example/", Secret: secret}}})
	old.Dispatch(context.Background(), sendEvent(), leakDecision("d1"))

	current, _ := newTestDispatcher(t, db, Config{Hooks: []Hook{{Name: "notify", URL: "https://hooks.example/", Secret: secret}}})
	deliverDue(t, current)
	got := deliveries(t, db, "d1")["revoke_key"]
	if got.Status != audit.DeliveryDead || !strings.Contains(got.LastError, "no hook configured") {
		t.Errorf("delivery for a removed hook = %+v", got)
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
		if err := Verify(secret, r.Header.Get(SignatureHeader), body, 0); err != nil {
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

func TestNewValidates(t *testing.T) {
	db := openOutbox(t)
	ok := Hook{Name: "revoke_key", URL: "https://hooks.example/revoke", Secret: secret}
	tests := map[string][]Hook{
		"no name":       {{URL: ok.URL, Secret: secret}},
		"relative url":  {{Name: "a", URL: "/revoke", Secret: secret}},
		"ftp url":       {{Name: "a", URL: "ftp://hooks.example/", Secret: secret}},
		"no secret":     {{Name: "a", URL: ok.URL}},
		"bad timeout":   {{Name: "a", URL: ok.URL, Secret: secret, Timeout: -time.Second}},
		"duplicate":     {ok, ok},
		"malformed url": {{Name: "a", URL: "http://[::1", Secret: secret}},
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
	if d.lease != defaultHookTimeout+30*time.Second {
		t.Errorf("lease = %v", d.lease)
	}
}
