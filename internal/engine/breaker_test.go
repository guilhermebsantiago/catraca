package engine

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// storeCatalog is a catalog whose store can be broken. Like the real one, it
// answers a call with a done context from what it knows, without reaching
// the store, and remembers keys marked leaked even when the store fails.
type storeCatalog struct {
	mu      sync.Mutex
	err     error // returned by calls that reach the store
	hang    bool  // calls that reach the store wait for their context
	reached int   // calls that reached the store
	skipped int   // calls made with a done context
	leaked  map[string]bool
}

func (c *storeCatalog) call(ctx context.Context) error {
	c.mu.Lock()
	if ctx.Err() != nil {
		c.skipped++
		c.mu.Unlock()
		return ctx.Err()
	}
	c.reached++
	err, hang := c.err, c.hang
	c.mu.Unlock()
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (c *storeCatalog) Observe(ctx context.Context, ev event.Event) (signal.Set, error) {
	set := signal.Set{Event: map[string]any{"type": string(ev.Type), "api_key_id": ev.APIKeyID}}
	if err := c.call(ctx); err != nil {
		c.mu.Lock()
		if c.leaked[ev.APIKeyID] {
			set.Key = map[string]any{"leaked": true}
		}
		c.mu.Unlock()
		return set, err
	}
	set.Account = map[string]any{"sends_1m": int64(1), "age_hours": 5000.0}
	set.Key = map[string]any{"leaked": false}
	return set, nil
}

func (c *storeCatalog) MarkLeaked(ctx context.Context, apiKeyID string) error {
	c.mu.Lock()
	if c.leaked == nil {
		c.leaked = map[string]bool{}
	}
	c.leaked[apiKeyID] = true
	c.mu.Unlock()
	return c.call(ctx)
}

func (c *storeCatalog) Close() error { return nil }

func (c *storeCatalog) set(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *storeCatalog) counts() (reached, skipped int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reached, c.skipped
}

// manualClock moves only when the test says so.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type breakerHarness struct {
	eng   *Engine
	cat   *storeCatalog
	clock *manualClock
	reg   *prometheus.Registry
	logs  *bytes.Buffer
}

func newBreakerHarness(t *testing.T, opts BreakerOptions) *breakerHarness {
	t.Helper()
	rs, err := rules.Parse([]byte(testRuleset))
	if err != nil {
		t.Fatal(err)
	}
	h := &breakerHarness{
		cat:   &storeCatalog{},
		clock: &manualClock{t: t0},
		reg:   prometheus.NewRegistry(),
		logs:  &bytes.Buffer{},
	}
	h.eng, err = New(Options{
		Catalog:    h.cat,
		Rules:      rules.NewHolder(rs),
		Breaker:    opts,
		Now:        h.clock.Now,
		Registerer: h.reg,
		Logger:     slog.New(slog.NewTextHandler(&lockedWriter{w: h.logs}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// lockedWriter lets the test read the log while the engine writes it.
type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (h *breakerHarness) send(t *testing.T) decision.Decision {
	t.Helper()
	d, err := h.eng.Decide(context.Background(), sendEvent())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (h *breakerHarness) state(t *testing.T) string {
	t.Helper()
	var on []string
	for _, m := range family(t, h.reg, "catraca_store_breaker_state").GetMetric() {
		if m.GetGauge().GetValue() == 1 {
			on = append(on, m.GetLabel()[0].GetValue())
		}
	}
	if len(on) != 1 {
		t.Fatalf("breaker state gauge is 1 for %v, want exactly one state", on)
	}
	return on[0]
}

func (h *breakerHarness) transitions(t *testing.T, from, to string) float64 {
	t.Helper()
	return counter(t, h.reg, "catraca_store_breaker_transitions_total", map[string]string{"from": from, "to": to})
}

func (h *breakerHarness) shortCircuited(t *testing.T) float64 {
	t.Helper()
	return counter(t, h.reg, "catraca_short_circuited_decisions_total", nil)
}

// open fails the store until the breaker opens: the default number of
// failures, over the default window.
func (h *breakerHarness) open(t *testing.T) {
	t.Helper()
	h.cat.set(errors.New("redis: connection refused"))
	h.send(t)
	h.clock.Advance(DefaultBreakerWindow)
	for range DefaultBreakerFailures - 1 {
		h.send(t)
	}
	if got := h.state(t); got != "open" {
		t.Fatalf("breaker is %s after %d failures over %s, want open", got, DefaultBreakerFailures, DefaultBreakerWindow)
	}
}

func TestBreakerOpensAfterFailuresInARow(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{})
	if got := h.state(t); got != "closed" {
		t.Fatalf("a new breaker is %s, want closed", got)
	}
	h.cat.set(errors.New("redis: connection refused"))
	h.send(t)
	h.clock.Advance(DefaultBreakerWindow)
	for i := range DefaultBreakerFailures - 2 {
		if d := h.send(t); !d.Degraded {
			t.Fatalf("decision %d is not degraded", i)
		}
	}
	if got := h.state(t); got != "closed" {
		t.Fatalf("breaker is %s after %d failures, want closed until %d", got, DefaultBreakerFailures-1, DefaultBreakerFailures)
	}
	h.send(t)
	if got := h.state(t); got != "open" {
		t.Fatalf("breaker is %s after %d failures, want open", got, DefaultBreakerFailures)
	}

	reached, _ := h.cat.counts()
	d := h.send(t)
	if again, skipped := h.cat.counts(); again != reached || skipped != 1 {
		t.Errorf("an open breaker let a call reach the store (reached %d, then %d; skipped %d)", reached, again, skipped)
	}
	// The same decision as a store failure: leaked fails closed and
	// blocks the key, as errored; the rules that fail open are skipped.
	if !d.Degraded || d.Action != decision.Block || !slices.Equal(ruleIDs(d.Matches), []string{"leaked"}) || !d.Matches[0].Errored {
		t.Errorf("short-circuited decision = %+v, want the degraded decision of a store failure", d)
	}
	// Nothing was counted, so feedback decided this way must be sent again:
	// the feedback endpoints answer 503 for an uncounted decision.
	if !d.Uncounted {
		t.Error("a short-circuited decision is not marked uncounted")
	}
	if got := h.shortCircuited(t); got != 1 {
		t.Errorf("short-circuited decisions = %v, want 1", got)
	}
	if got := counter(t, h.reg, "catraca_degraded_decisions_total", nil); got != float64(DefaultBreakerFailures+1) {
		t.Errorf("degraded decisions = %v, want every decision", got)
	}
	if got := h.transitions(t, "closed", "open"); got != 1 {
		t.Errorf("closed->open transitions = %v, want 1", got)
	}
	if log := h.logs.String(); !strings.Contains(log, "store breaker opened") || !strings.Contains(log, "connection refused") {
		t.Errorf("log = %q, want a line saying the breaker opened, with the error", log)
	}
}

func TestBreakerCountsFailuresInARowOnly(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{Failures: 3})
	fail := errors.New("redis: connection refused")
	// A second between decisions, so every run outlasts the window.
	for _, err := range []error{fail, fail, nil, fail, fail, nil, fail, fail} {
		h.cat.set(err)
		h.send(t)
		h.clock.Advance(time.Second)
	}
	if got := h.state(t); got != "closed" {
		t.Fatalf("breaker is %s, want closed: a success ends a run of failures", got)
	}
	h.send(t)
	if got := h.state(t); got != "open" {
		t.Fatalf("breaker is %s after 3 failures in a row, want open", got)
	}
}

// TestBreakerWaitsForTheWindow checks that a burst of failures, however
// many, opens the breaker only once it has lasted the window: an overload
// makes calls miss the deadline in bursts too, and the adaptive limit ends
// those within a few rounds.
func TestBreakerWaitsForTheWindow(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{})
	h.cat.set(errors.New("context deadline exceeded"))
	for range 10 * DefaultBreakerFailures {
		h.send(t)
	}
	h.clock.Advance(DefaultBreakerWindow - time.Millisecond)
	h.send(t)
	if got := h.state(t); got != "closed" {
		t.Fatalf("breaker is %s before the window ended, want closed", got)
	}
	h.clock.Advance(time.Millisecond)
	h.send(t)
	if got := h.state(t); got != "open" {
		t.Fatalf("breaker is %s once the failures lasted the window, want open", got)
	}

	// A success starts the window over.
	h = newBreakerHarness(t, BreakerOptions{})
	h.cat.set(errors.New("context deadline exceeded"))
	h.send(t)
	h.clock.Advance(DefaultBreakerWindow / 2)
	h.cat.set(nil)
	h.send(t)
	h.cat.set(errors.New("context deadline exceeded"))
	for range DefaultBreakerFailures {
		h.send(t)
	}
	h.clock.Advance(DefaultBreakerWindow / 2)
	h.send(t)
	if got := h.state(t); got != "closed" {
		t.Fatalf("breaker is %s, want closed: a success in the window starts it over", got)
	}
}

func TestBreakerCountsDeadlineMisses(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{Failures: 2})
	h.eng.deadline = time.Millisecond
	h.cat.hang = true
	h.send(t)
	h.clock.Advance(DefaultBreakerWindow)
	h.send(t)
	if got := h.state(t); got != "open" {
		t.Fatalf("breaker is %s after two deadline misses, want open", got)
	}
}

func TestBreakerIgnoresCallsTheCallerCanceled(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{Failures: 2})
	// Only the caller ends these calls.
	h.eng.deadline = time.Minute
	h.cat.hang = true
	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			if _, err := h.eng.Decide(ctx, sendEvent()); err != nil {
				t.Error(err)
			}
		}()
		// Cancel once the call is waiting on the store.
		for {
			if reached, _ := h.cat.counts(); reached > 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		<-done
		h.cat.mu.Lock()
		h.cat.reached = 0
		h.cat.mu.Unlock()
	}
	if got := h.state(t); got != "closed" {
		t.Errorf("breaker is %s, want closed: callers that hang up say nothing about the store", got)
	}
}

func TestBreakerHalfOpenCloses(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{Probes: 3})
	h.open(t)
	h.cat.set(nil)

	h.clock.Advance(DefaultBreakerCooldown - time.Millisecond)
	if d := h.send(t); !d.Degraded {
		t.Fatal("a decision during the cooldown reached the store")
	}
	h.clock.Advance(time.Millisecond)
	for i := range 3 {
		if d := h.send(t); d.Degraded {
			t.Fatalf("probe %d is degraded with the store back", i)
		}
		want := "half_open"
		if i == 2 {
			want = "closed"
		}
		if got := h.state(t); got != want {
			t.Fatalf("after probe %d the breaker is %s, want %s", i, got, want)
		}
	}
	if d := h.send(t); d.Degraded {
		t.Error("decision after the breaker closed is degraded")
	}
	for _, tr := range [][2]string{{"open", "half_open"}, {"half_open", "closed"}} {
		if got := h.transitions(t, tr[0], tr[1]); got != 1 {
			t.Errorf("%s->%s transitions = %v, want 1", tr[0], tr[1], got)
		}
	}
	log := h.logs.String()
	for _, want := range []string{"store breaker half-open", "store breaker closed"} {
		if !strings.Contains(log, want) {
			t.Errorf("log has no %q line:\n%s", want, log)
		}
	}
}

func TestBreakerHalfOpenReopensOnAFailedProbe(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{})
	h.open(t)
	h.clock.Advance(DefaultBreakerCooldown)

	reached, _ := h.cat.counts()
	h.send(t) // the first probe, against a store that still fails
	if got := h.state(t); got != "open" {
		t.Fatalf("breaker is %s after a failed probe, want open", got)
	}
	if again, _ := h.cat.counts(); again != reached+1 {
		t.Errorf("the probe did not reach the store")
	}
	// A new cooldown starts with the failed probe.
	h.clock.Advance(DefaultBreakerCooldown - time.Millisecond)
	h.send(t)
	if again, _ := h.cat.counts(); again != reached+1 {
		t.Errorf("a call reached the store before the new cooldown ended")
	}
	if got := h.transitions(t, "half_open", "open"); got != 1 {
		t.Errorf("half_open->open transitions = %v, want 1", got)
	}
	if !strings.Contains(h.logs.String(), "store breaker opened again") {
		t.Errorf("log has no line for the failed probe:\n%s", h.logs.String())
	}
}

// TestBreakerLetsProbesThroughOnly drives the breaker directly, so the
// probes can be in flight together.
func TestBreakerLetsProbesThroughOnly(t *testing.T) {
	clock := &manualClock{t: t0}
	b, err := newBreaker(BreakerOptions{Failures: 1, Probes: 2}, clock.Now, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		c, _ := b.begin()
		b.end(c, callFailed, errors.New("down"))
		clock.Advance(DefaultBreakerWindow)
	}
	if got := breakerState(b.state.Load()); got != breakerOpen {
		t.Fatalf("breaker is %s, want open", got)
	}
	clock.Advance(DefaultBreakerCooldown)

	p1, ok1 := b.begin()
	p2, ok2 := b.begin()
	if !ok1 || !ok2 || !p1.probe || !p2.probe {
		t.Fatalf("half-open breaker did not let two probes through")
	}
	if _, ok := b.begin(); ok {
		t.Fatal("a third call went through with two probes in flight")
	}
	// A probe whose caller gave up frees its place.
	b.end(p1, callIgnored, context.Canceled)
	p3, ok := b.begin()
	if !ok {
		t.Fatal("no probe took the place of the one whose caller gave up")
	}
	b.end(p2, callOK, nil)
	if got := breakerState(b.state.Load()); got != breakerHalfOpen {
		t.Fatalf("breaker is %s after one of two probes succeeded", got)
	}
	b.end(p3, callOK, nil)
	if got := breakerState(b.state.Load()); got != breakerClosed {
		t.Fatalf("breaker is %s after both probes succeeded, want closed", got)
	}
}

// TestBreakerIgnoresCallsFromAnEarlierState checks that a call admitted
// before a transition does not count after it: a late success must not
// close a breaker that opened meanwhile, nor a late failure count toward
// the next run.
func TestBreakerIgnoresCallsFromAnEarlierState(t *testing.T) {
	clock := &manualClock{t: t0}
	b, err := newBreaker(BreakerOptions{Failures: 2, Probes: 1}, clock.Now, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	early, _ := b.begin()
	for range 2 {
		c, _ := b.begin()
		b.end(c, callFailed, errors.New("down"))
		clock.Advance(DefaultBreakerWindow)
	}
	b.end(early, callOK, nil)
	if got := breakerState(b.state.Load()); got != breakerOpen {
		t.Fatalf("breaker is %s, want open: the late success is from before it opened", got)
	}
	clock.Advance(DefaultBreakerCooldown)
	p, _ := b.begin()
	b.end(p, callOK, nil)
	b.end(early, callFailed, errors.New("down"))
	if b.failures.Load() != 0 {
		t.Errorf("a failure from before the breaker opened counted after it closed")
	}
}

func TestBreakerKeyLeakFailsAtOnceWhileOpen(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{})
	h.open(t)

	reached, _ := h.cat.counts()
	_, err := h.eng.Decide(context.Background(), event.Event{Type: event.KeyLeak, APIKeyID: "key_9"})
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("error = %v, want ErrBreakerOpen so the caller sends the event again", err)
	}
	if again, _ := h.cat.counts(); again != reached {
		t.Error("the leak write reached the store with the breaker open")
	}
	// The catalog was still told, so it blocks the key from memory.
	ev := sendEvent()
	ev.APIKeyID = "key_9"
	d, err := h.eng.Decide(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != decision.Block || len(d.Matches) != 1 || d.Matches[0].Errored {
		t.Errorf("send with the leaked key = %+v, want blocked by leaked, not errored", d)
	}
}

func TestDecideWithoutStore(t *testing.T) {
	h := newBreakerHarness(t, BreakerOptions{Failures: 1})

	d, err := h.eng.DecideWithoutStore(context.Background(), sendEvent())
	if err != nil {
		t.Fatal(err)
	}
	if reached, skipped := h.cat.counts(); reached != 0 || skipped != 1 {
		t.Errorf("calls reached %d, skipped %d; want the store skipped", reached, skipped)
	}
	if !d.Degraded || d.Action != decision.Block || len(d.Matches) != 1 || !d.Matches[0].Errored {
		t.Errorf("decision = %+v, want the degraded decision of a store failure", d)
	}

	_, err = h.eng.DecideWithoutStore(context.Background(), event.Event{Type: event.KeyLeak, APIKeyID: "key_9"})
	if !errors.Is(err, ErrWithoutStore) {
		t.Errorf("key_leak error = %v, want ErrWithoutStore", err)
	}
	if _, err := h.eng.DecideWithoutStore(context.Background(), event.Event{Type: event.Send}); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("invalid event error = %v, want ErrInvalidEvent", err)
	}

	// Skipping the store is not a store failure.
	if got := h.state(t); got != "closed" {
		t.Errorf("breaker is %s after decisions without the store, want closed", got)
	}
	if got := h.shortCircuited(t); got != 0 {
		t.Errorf("short-circuited decisions = %v, want 0: none met an open breaker", got)
	}
}

// TestDecideWithoutStoreLeavesTheStoreAlone runs the real catalog on each
// store: a decision without the store must not count its event, and a key
// marked leaked without the store stays blocked in this process.
func TestDecideWithoutStoreLeavesTheStoreAlone(t *testing.T) {
	rs, err := rules.Parse([]byte(testRuleset))
	if err != nil {
		t.Fatal(err)
	}
	for _, be := range storeBackends {
		t.Run(be.name, func(t *testing.T) {
			if be.skip != nil {
				if why := be.skip(); why != "" {
					t.Skip(why)
				}
			}
			cat := &spyCatalog{Catalog: signal.NewCatalog(be.new(t), signal.Options{})}
			t.Cleanup(func() { cat.Close() })
			eng, err := New(Options{Catalog: cat, Rules: rules.NewHolder(rs), Deadline: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			ev := sendEvent()
			ev.AccountID = "acct_shed"
			ev.APIKeyID = "key_shed"
			for range 3 {
				d, err := eng.DecideWithoutStore(ctx, ev)
				if err != nil {
					t.Fatal(err)
				}
				if !d.Uncounted {
					t.Fatalf("decision without the store = %+v, want uncounted", d)
				}
			}
			if d, err := eng.Decide(ctx, ev); err != nil || d.Degraded {
				t.Fatalf("Decide = %+v, %v", d, err)
			}
			if got := cat.lastSet().Account["sends_1m"]; got != int64(1) {
				t.Errorf("sends_1m = %v, want 1: decisions without the store must not count", got)
			}

			if _, err := eng.DecideWithoutStore(ctx, event.Event{Type: event.KeyLeak, APIKeyID: "key_shed"}); !errors.Is(err, ErrWithoutStore) {
				t.Fatalf("key_leak error = %v, want ErrWithoutStore", err)
			}
			d, err := eng.DecideWithoutStore(ctx, ev)
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != decision.Block || len(d.Matches) != 1 || d.Matches[0].Errored {
				t.Errorf("decision = %+v, want the key blocked from memory", d)
			}
		})
	}
}

func TestNewRejectsNegativeBreakerOptions(t *testing.T) {
	rs, err := rules.Parse([]byte(testRuleset))
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []BreakerOptions{{Failures: -1}, {Window: -time.Second}, {Cooldown: -time.Second}, {Probes: -1}} {
		if _, err := New(Options{Catalog: &storeCatalog{}, Rules: rules.NewHolder(rs), Breaker: opts}); err == nil {
			t.Errorf("New accepted %+v", opts)
		}
	}
}
