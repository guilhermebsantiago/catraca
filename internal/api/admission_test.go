package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// value reads a counter or gauge.
func value(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatal(err)
	}
	if out.Counter != nil {
		return out.GetCounter().GetValue()
	}
	return out.GetGauge().GetValue()
}

func newTestLimiter(maxInflight int, wait time.Duration, adaptive bool) *limiter {
	return newLimiter(maxInflight, wait, adaptive, prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_limit"}))
}

func (l *limiter) state() (limit float64, inflight, queued int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit, l.inflight, len(l.queue)
}

// waitQueued polls until n requests wait for a slot.
func waitQueued(t *testing.T, l *limiter, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, _, q := l.state(); q == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d requests never queued", n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLimiterAdmitsUpToItsLimit(t *testing.T) {
	l := newTestLimiter(2, 0, false)
	ctx := context.Background()
	a, okA := l.acquire(ctx)
	_, okB := l.acquire(ctx)
	if !okA || !okB {
		t.Fatal("the first two requests were not admitted")
	}
	if _, ok := l.acquire(ctx); ok {
		t.Fatal("a third request was admitted with two slots")
	}
	l.release(a, outcomeNone)
	if _, ok := l.acquire(ctx); !ok {
		t.Fatal("a freed slot was not reused")
	}
}

func TestLimiterWaitsForASlot(t *testing.T) {
	l := newTestLimiter(1, time.Hour, false)
	first, _ := l.acquire(context.Background())
	got := make(chan bool)
	go func() {
		_, ok := l.acquire(context.Background())
		got <- ok
	}()
	waitQueued(t, l, 1)
	l.release(first, outcomeNone)
	if !<-got {
		t.Fatal("the waiting request did not get the freed slot")
	}
	if _, inflight, queued := l.state(); inflight != 1 || queued != 0 {
		t.Errorf("inflight %d, queued %d; want 1, 0", inflight, queued)
	}
}

func TestLimiterServesWaitersInOrder(t *testing.T) {
	l := newTestLimiter(1, time.Hour, false)
	held, _ := l.acquire(context.Background())
	order := make(chan int, 2)
	for i := range 2 {
		go func() {
			t, _ := l.acquire(context.Background())
			order <- i
			l.release(t, outcomeNone)
		}()
		waitQueued(t, l, i+1)
	}
	l.release(held, outcomeNone)
	if a, b := <-order, <-order; a != 0 || b != 1 {
		t.Errorf("served %d then %d, want arrival order", a, b)
	}
}

func TestLimiterShedsWhenTheWaitEnds(t *testing.T) {
	l := newTestLimiter(1, time.Hour, false)
	waited := make(chan time.Time)
	l.after = func(time.Duration) <-chan time.Time { return waited }
	l.acquire(context.Background())

	got := make(chan bool)
	go func() {
		_, ok := l.acquire(context.Background())
		got <- ok
	}()
	waitQueued(t, l, 1)
	close(waited)
	if <-got {
		t.Fatal("a request was admitted after its wait ended with no slot free")
	}
	if _, _, queued := l.state(); queued != 0 {
		t.Errorf("%d requests still queued after their wait ended", queued)
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.after = time.After
	go func() {
		_, ok := l.acquire(ctx)
		got <- ok
	}()
	waitQueued(t, l, 1)
	cancel()
	if <-got {
		t.Fatal("a request was admitted after its caller left")
	}
}

func TestAdaptiveLimitDecreasesOncePerRound(t *testing.T) {
	l := newTestLimiter(100, 0, true)
	var burst []ticket
	for range 10 {
		tk, _ := l.acquire(context.Background())
		burst = append(burst, tk)
	}
	// One stall makes the whole burst slow; it is one signal.
	for _, tk := range burst {
		l.release(tk, outcomeSlow)
	}
	if limit, _, _ := l.state(); limit != 80 {
		t.Fatalf("limit = %v after one slow round, want 80", limit)
	}
	tk, _ := l.acquire(context.Background())
	l.release(tk, outcomeSlow)
	if limit, _, _ := l.state(); limit != 64 {
		t.Fatalf("limit = %v after a second slow round, want 64", limit)
	}
	for range 100 {
		tk, _ := l.acquire(context.Background())
		l.release(tk, outcomeSlow)
	}
	if limit, _, _ := l.state(); limit != minLimit {
		t.Fatalf("limit = %v, want the floor %d", limit, minLimit)
	}
	if got := value(t, l.gauge); got != minLimit {
		t.Errorf("limit gauge = %v, want %d", got, minLimit)
	}
}

func TestAdaptiveLimitGrowsOnlyWhileBusy(t *testing.T) {
	l := newTestLimiter(8, 0, true)
	tk, _ := l.acquire(context.Background())
	l.release(tk, outcomeSlow) // 6.4
	tk, _ = l.acquire(context.Background())
	l.release(tk, outcomeSlow) // 5.12
	start, _, _ := l.state()

	// One decision in flight of five slots: not busy, so no growth.
	for range 20 {
		tk, _ := l.acquire(context.Background())
		l.release(tk, outcomeOK)
	}
	if limit, _, _ := l.state(); limit != start {
		t.Fatalf("limit grew from %v to %v with the slots mostly idle", start, limit)
	}

	// hold runs rounds of n decisions in flight together.
	hold := func(n int) {
		for range 200 {
			var held []ticket
			for range n {
				tk, _ := l.acquire(context.Background())
				held = append(held, tk)
			}
			for _, tk := range held {
				l.release(tk, outcomeOK)
			}
		}
	}
	// Three in flight: busy, so each fast decision adds 1/limit, until the
	// limit is twice what is in flight.
	hold(3)
	if limit, _, _ := l.state(); limit < 6 || limit >= 6.5 {
		t.Errorf("limit = %v with three in flight, want it to stop near 6", limit)
	}
	hold(4)
	if limit, _, _ := l.state(); limit != 8 {
		t.Errorf("limit = %v with four in flight, want back at the ceiling of 8", limit)
	}

	// Degraded decisions made fast say nothing about capacity.
	tk, _ = l.acquire(context.Background())
	l.release(tk, outcomeNone)
	if limit, _, _ := l.state(); limit != 8 {
		t.Errorf("limit = %v after a decision without the store", limit)
	}
}

func TestStaticLimitDoesNotMove(t *testing.T) {
	l := newTestLimiter(4, 0, false)
	for range 10 {
		tk, _ := l.acquire(context.Background())
		l.release(tk, outcomeSlow)
	}
	if limit, _, _ := l.state(); limit != 4 {
		t.Errorf("static limit = %v, want 4", limit)
	}
}

// shedDecider decides through decide, blocking while hold is open, and
// answers DecideWithoutStore through without.
type shedDecider struct {
	mu       sync.Mutex
	started  chan struct{}
	hold     chan struct{}
	d        decision.Decision
	without  func(event.Event) (decision.Decision, error)
	withouts int
}

func newShedDecider() *shedDecider {
	return &shedDecider{
		started: make(chan struct{}, 16),
		d:       decision.Decision{ID: "full", Action: decision.Allow},
		without: func(event.Event) (decision.Decision, error) {
			return decision.Decision{ID: "shed", Action: decision.Allow, Degraded: true}, nil
		},
	}
}

func (f *shedDecider) Decide(context.Context, event.Event) (decision.Decision, error) {
	f.started <- struct{}{}
	f.mu.Lock()
	hold, d := f.hold, f.d
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	return d, nil
}

func (f *shedDecider) DecideWithoutStore(_ context.Context, ev event.Event) (decision.Decision, error) {
	f.mu.Lock()
	f.withouts++
	without := f.without
	f.mu.Unlock()
	return without(ev)
}

// occupy starts a decision that holds its slot until the returned function
// is called.
func occupy(t *testing.T, s http.Handler, f *shedDecider) (release func()) {
	t.Helper()
	f.mu.Lock()
	f.hold = make(chan struct{})
	hold := f.hold
	f.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	}()
	<-f.started
	return func() {
		close(hold)
		<-done
		f.mu.Lock()
		f.hold = nil
		f.mu.Unlock()
	}
}

func newAdmissionServer(t *testing.T, d Decider, logs io.Writer, mod ...func(*Options)) *Server {
	t.Helper()
	var log *slog.Logger
	if logs != nil {
		log = slog.New(slog.NewJSONHandler(logs, nil))
	}
	return newTestServer(t, d, log, append([]func(*Options){func(o *Options) {
		o.Admission = Admission{MaxInflight: 1}
		o.Registerer = prometheus.NewRegistry()
	}}, mod...)...)
}

func TestShedDecisionIsMadeWithoutTheStore(t *testing.T) {
	f := newShedDecider()
	var logs bytes.Buffer
	s := newAdmissionServer(t, f, &lockedBuffer{b: &logs})
	release := occupy(t, s, f)

	for _, path := range []string{"/v1/decide", "/v1/events"} {
		rec := serve(s, "POST", path, `{"type":"send","account_id":"a"}`)
		if rec.Code/100 != 2 || !strings.Contains(rec.Body.String(), `"id":"shed"`) || !strings.Contains(rec.Body.String(), `"degraded":true`) {
			t.Errorf("shed %s: %d %s, want the decision made without the store", path, rec.Code, rec.Body)
		}
	}
	release()
	if rec := serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`); !strings.Contains(rec.Body.String(), `"id":"full"`) {
		t.Errorf("after the slot freed: %s, want a full decision", rec.Body)
	}

	for _, route := range []string{routeDecide, routeEvents} {
		if got := value(t, s.admission.shed.WithLabelValues(route)); got != 1 {
			t.Errorf("shed{%s} = %v, want 1", route, got)
		}
		if got := value(t, s.admission.inflight.WithLabelValues(route)); got != 0 {
			t.Errorf("inflight{%s} = %v after every request ended", route, got)
		}
	}
	if !strings.Contains(logs.String(), `"shed":true`) {
		t.Errorf("access log does not mark the shed request:\n%s", logs.String())
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func TestShedFeedbackAndKeyLeakAskForARetry(t *testing.T) {
	f := newShedDecider()
	f.without = func(ev event.Event) (decision.Decision, error) {
		if ev.Type == event.KeyLeak {
			return decision.Decision{}, fmt.Errorf("engine: mark key k leaked: %w", engine.ErrWithoutStore)
		}
		return decision.Decision{ID: "shed", Degraded: true}, nil
	}
	s := newAdmissionServer(t, f, nil)
	release := occupy(t, s, f)
	defer release()

	rec := serve(s, "POST", "/v1/events", `{"type":"feedback","account_id":"a","feedback":{"kind":"bounce"}}`)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), `"code":"overloaded"`) {
		t.Errorf("shed feedback event: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	f.mu.Lock()
	withouts := f.withouts
	f.mu.Unlock()
	if withouts != 0 {
		t.Error("a shed feedback event was decided: its decision would not count it")
	}
	rec = serve(s, "POST", "/v1/events", `{"type":"key_leak","api_key_id":"k"}`)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), `"code":"overloaded"`) {
		t.Errorf("shed key_leak: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}

func TestBreakerOpenAnswersRetry(t *testing.T) {
	var logs bytes.Buffer
	s := newTestServer(t, deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		return decision.Decision{}, fmt.Errorf("engine: mark key k leaked: %w", engine.ErrBreakerOpen)
	}), slog.New(slog.NewJSONHandler(&logs, nil)))
	rec := serve(s, "POST", "/v1/events", `{"type":"key_leak","api_key_id":"k"}`)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), `"code":"unavailable"`) {
		t.Errorf("key_leak with the breaker open: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if strings.Contains(logs.String(), "decide failed") {
		t.Errorf("an open breaker was logged for each request:\n%s", logs.String())
	}
}

// TestDecisionLatencyAdaptsTheLimit checks the handler's side of the
// adaptive limit: a decision that takes half the deadline lowers it.
func TestDecisionLatencyAdaptsTheLimit(t *testing.T) {
	f := newShedDecider()
	f.d.LatencyMicros = 9_999
	s := newAdmissionServer(t, f, nil, func(o *Options) {
		o.Admission = Admission{MaxInflight: 10, Deadline: 20 * time.Millisecond}
	})
	serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	if got := value(t, s.admission.limit.WithLabelValues("decisions")); got != 10 {
		t.Errorf("decision limit = %v after a decision under half the deadline, want 10", got)
	}
	f.d.LatencyMicros = 10_000
	serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	if got := value(t, s.admission.limit.WithLabelValues("decisions")); got != 8 {
		t.Errorf("decision limit = %v after a decision took half the deadline, want 8", got)
	}
	f.d.LatencyMicros, f.d.Degraded = 9_999, true
	serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	if got := value(t, s.admission.limit.WithLabelValues("decisions")); got != 8 {
		t.Errorf("decision limit = %v after a fast degraded decision, want it unchanged", got)
	}
	if got := value(t, s.admission.limit.WithLabelValues("feedback")); got != 10 {
		t.Errorf("feedback limit = %v, want the static 10", got)
	}
}

func TestStaticAdmission(t *testing.T) {
	f := newShedDecider()
	f.d.LatencyMicros = 20_000
	s := newAdmissionServer(t, f, nil, func(o *Options) {
		o.Admission = Admission{MaxInflight: 10, Static: true, Deadline: 20 * time.Millisecond}
	})
	serve(s, "POST", "/v1/decide", `{"type":"send","account_id":"a"}`)
	if got := value(t, s.admission.limit.WithLabelValues("decisions")); got != 10 {
		t.Errorf("static decision limit = %v, want 10", got)
	}
}

// blockingHandler holds each request until release is closed, after
// reading its whole body.
type blockingHandler struct {
	started chan int
	release chan struct{}
}

func (h *blockingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.started <- len(body)
	<-h.release
	w.WriteHeader(http.StatusOK)
}

func TestFeedbackIsAdmittedApart(t *testing.T) {
	f := newShedDecider()
	fb := &blockingHandler{started: make(chan int, 4), release: make(chan struct{})}
	s := newAdmissionServer(t, f, nil, func(o *Options) { o.GenericFeedback = fb })
	release := occupy(t, s, f)
	defer release()

	// The decision slot is taken; feedback has its own.
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- serve(s, "POST", "/v1/feedback", `{"a":1}`) }()
	if n := <-fb.started; n != len(`{"a":1}`) {
		t.Errorf("the handler read %d bytes of the body", n)
	}

	rec := serve(s, "POST", "/v1/feedback", `{"a":2}`)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" || strings.TrimSpace(rec.Body.String()) != `{"error":"too many feedback requests in flight; retry later"}` {
		t.Errorf("feedback over the limit: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if got := value(t, s.admission.shed.WithLabelValues(routeFeedback)); got != 1 {
		t.Errorf("shed{%s} = %v, want 1", routeFeedback, got)
	}
	close(fb.release)
	if rec := <-done; rec.Code != 200 {
		t.Errorf("admitted feedback: %d", rec.Code)
	}
}

// TestFeedbackBodyIsReadBeforeTheSlot checks that the slot is taken after
// the body arrives, and that a body larger than what is read ahead still
// reaches the handler whole.
func TestFeedbackBodyIsReadBeforeTheSlot(t *testing.T) {
	fb := &blockingHandler{started: make(chan int, 1), release: make(chan struct{})}
	close(fb.release)
	s := newAdmissionServer(t, newShedDecider(), nil, func(o *Options) { o.GenericFeedback = fb })

	pr, pw := io.Pipe()
	req := httptest.NewRequest("POST", "/v1/feedback", pr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeHTTP(httptest.NewRecorder(), req)
	}()
	if _, err := pw.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	// The body is still arriving: no slot is held yet.
	if got := value(t, s.admission.inflight.WithLabelValues(routeFeedback)); got != 0 {
		t.Errorf("inflight = %v while the body arrives, want 0", got)
	}
	big := bytes.Repeat([]byte("x"), feedbackPrefetch+1000)
	if _, err := pw.Write(big); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	<-done
	if n := <-fb.started; n != 1+len(big) {
		t.Errorf("the handler read %d bytes, want %d", n, 1+len(big))
	}
}

func TestSecretScanningIsNotLimited(t *testing.T) {
	f := newShedDecider()
	gh := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	s := newAdmissionServer(t, f, nil, func(o *Options) { o.GitHubSecretScanning = gh })
	release := occupy(t, s, f)
	defer release()
	if rec := serve(s, "POST", "/v1/secret-scanning/github", "[]"); rec.Code != http.StatusAccepted {
		t.Errorf("secret scanning with the decision slots full: %d", rec.Code)
	}
}

func TestNewRejectsNegativeAdmission(t *testing.T) {
	for _, a := range []Admission{{MaxInflight: -1}, {Wait: -time.Millisecond}, {Deadline: -time.Millisecond}} {
		opts := Options{Decider: deciderFunc(nil), Rules: noRules{}, Audit: fakeAudit{}, Tokens: []Token{{Name: "a", Value: "x"}}, Admission: a}
		if _, err := New(opts); err == nil {
			t.Errorf("New accepted %+v", a)
		}
	}
}
