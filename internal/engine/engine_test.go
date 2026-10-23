package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// fakeCatalog returns fixed signals and records what it was asked.
type fakeCatalog struct {
	mu       sync.Mutex
	set      signal.Set
	err      error
	hang     bool // Observe waits for its context to end
	markErr  error
	markHang bool // MarkLeaked waits for its context to end
	calls    []string
	observed []event.Event
	deadline time.Time
	// markDeadline is the deadline of MarkLeaked's context.
	markDeadline time.Time
}

func (c *fakeCatalog) Observe(ctx context.Context, ev event.Event) (signal.Set, error) {
	c.mu.Lock()
	c.calls = append(c.calls, "observe")
	c.observed = append(c.observed, ev)
	c.deadline, _ = ctx.Deadline()
	set, err, hang := c.set, c.err, c.hang
	c.mu.Unlock()
	if hang {
		<-ctx.Done()
		return signal.Set{Event: set.Event}, ctx.Err()
	}
	return set, err
}

func (c *fakeCatalog) MarkLeaked(ctx context.Context, apiKeyID string) error {
	c.mu.Lock()
	c.calls = append(c.calls, "mark:"+apiKeyID)
	c.markDeadline, _ = ctx.Deadline()
	err, hang := c.markErr, c.markHang
	c.mu.Unlock()
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (c *fakeCatalog) Close() error { return nil }

func (c *fakeCatalog) callLog() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// fakeClock advances by step on every reading.
type fakeClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.t
	c.t = c.t.Add(c.step)
	return t
}

type recorded struct {
	ctx context.Context
	ev  event.Event
	d   decision.Decision
}

// chanRecorder sends every record to a channel.
type chanRecorder struct {
	ch    chan recorded
	block chan struct{} // when set, Record waits for it to close
}

func (r *chanRecorder) Record(ctx context.Context, ev event.Event, d decision.Decision) {
	if r.block != nil {
		<-r.block
	}
	r.ch <- recorded{ctx, ev, d}
}

type fakeDispatcher struct {
	mu    sync.Mutex
	calls []recorded
}

func (f *fakeDispatcher) Dispatch(ctx context.Context, ev event.Event, d decision.Decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recorded{ctx, ev, d})
}

const testRuleset = `version: 1
rules:
  - id: leaked
    when: event.type == "send" && event.api_key_id != "" && key.leaked
    action: block
    mode: enforce
    on_error: closed
    effects: [revoke_key]
    reason: leaked key
  - id: burst
    when: event.type == "send" && account.sends_1m > 100
    action: throttle
    retry_after: 30s
    mode: enforce
    on_error: open
    reason: burst
  - id: big-burst
    when: event.type == "send" && account.sends_1m > 1000
    action: throttle
    retry_after: 5m
    mode: enforce
    on_error: open
    reason: big burst
  - id: young
    when: event.type == "send" && account.age_hours < 24
    action: hold
    effects: [notify]
    reason: young account
  - id: leak-report
    when: event.type == "key_leak" && key.leaked
    action: flag
    mode: enforce
    on_error: open
    effects: [revoke_key]
    reason: key reported leaked
`

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// deadlineSlack is how much later than the configured deadline a context's
// deadline may fall in the deadline tests. The test reads the clock before
// Decide and Decide sets the deadline a little later: on a loaded machine,
// or a system whose wall clock ticks every few milliseconds, that gap runs
// past 10ms. A missing deadline still fails, and so would one of seconds.
const deadlineSlack = 500 * time.Millisecond

func healthySignals() signal.Set {
	return signal.Set{
		Event:   map[string]any{"type": "send", "api_key_id": "key_1"},
		Account: map[string]any{"sends_1m": int64(3), "age_hours": 5000.0},
		Key:     map[string]any{"leaked": false},
	}
}

func sendEvent() event.Event {
	return event.Event{Type: event.Send, AccountID: "acct_1", APIKeyID: "key_1", From: "a@example.com", To: []string{"b@example.org"}}
}

type harness struct {
	eng      *Engine
	cat      *fakeCatalog
	clock    *fakeClock
	holder   *rules.Holder
	reg      *prometheus.Registry
	recorder *chanRecorder
	disp     *fakeDispatcher
}

func newHarness(t *testing.T, opts Options) *harness {
	t.Helper()
	rs, err := rules.Parse([]byte(testRuleset))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		cat:    &fakeCatalog{set: healthySignals()},
		clock:  &fakeClock{t: t0, step: 250 * time.Microsecond},
		holder: rules.NewHolder(rs),
		reg:    prometheus.NewRegistry(),
		disp:   &fakeDispatcher{},
	}
	if opts.Catalog == nil {
		opts.Catalog = h.cat
	}
	if opts.Rules == nil {
		opts.Rules = h.holder
	}
	if opts.Now == nil {
		opts.Now = h.clock.Now
	}
	if opts.Registerer == nil {
		opts.Registerer = h.reg
	}
	if opts.Dispatcher == nil {
		opts.Dispatcher = h.disp
	}
	if r, ok := opts.Recorder.(*chanRecorder); ok {
		h.recorder = r
	}
	h.eng, err = New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Unblock a blocked recorder so Close can drain the queue.
		if h.recorder != nil && h.recorder.block != nil {
			select {
			case <-h.recorder.block:
			default:
				close(h.recorder.block)
			}
		}
		_ = h.eng.Close(context.Background())
	})
	return h
}

func (h *harness) decide(t *testing.T, ev event.Event) decision.Decision {
	t.Helper()
	d, err := h.eng.Decide(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ruleIDs(ms []decision.Match) []string {
	var ids []string
	for _, m := range ms {
		ids = append(ids, m.RuleID)
	}
	return ids
}

func TestDecideAllowsHealthyTraffic(t *testing.T) {
	h := newHarness(t, Options{})
	d := h.decide(t, sendEvent())

	if d.Action != decision.Allow || len(d.Matches) != 0 || len(d.Shadow) != 0 || len(d.Errors) != 0 || d.Degraded {
		t.Errorf("decision = %+v, want a clean allow", d)
	}
	if len(d.ID) != 26 || len(d.EventID) != 26 || d.ID == d.EventID {
		t.Errorf("ids = %q / %q, want two distinct ULIDs", d.ID, d.EventID)
	}
	if d.RulesetVersion != h.holder.Current().Version() {
		t.Errorf("ruleset version = %q", d.RulesetVersion)
	}
	if !d.Time.Equal(t0) {
		t.Errorf("time = %s, want the clock's %s", d.Time, t0)
	}
	if d.LatencyMicros != 250 {
		t.Errorf("latency = %dµs, want 250µs from the fake clock", d.LatencyMicros)
	}
	if d.RetryAfter != 0 {
		t.Errorf("retry_after = %s", d.RetryAfter)
	}
}

func TestDecideNormalizesWithoutTouchingTheCaller(t *testing.T) {
	h := newHarness(t, Options{})
	ev := event.Event{
		ID: "evt_from_platform", Type: event.Feedback, AccountID: "acct_1",
		From: "  Alice@Example.COM ", To: []string{"Bob@Example.ORG"},
		Feedback: &event.FeedbackInfo{Kind: event.Bounce, Recipient: "Bob@Example.ORG"},
	}
	d := h.decide(t, ev)

	if d.EventID != "evt_from_platform" {
		t.Errorf("event id = %q, want the platform's id kept", d.EventID)
	}
	seen := h.cat.observed[0]
	if seen.ID != "evt_from_platform" || seen.From != "alice@example.com" || seen.To[0] != "bob@example.org" ||
		seen.Feedback.Recipient != "bob@example.org" || !seen.Time.Equal(t0) {
		t.Errorf("observed event = %+v, want it normalized with the clock's time", seen)
	}
	if ev.To[0] != "Bob@Example.ORG" || ev.Feedback.Recipient != "Bob@Example.ORG" {
		t.Error("Decide rewrote the caller's event")
	}
}

func TestDecideRejectsInvalidEvents(t *testing.T) {
	h := newHarness(t, Options{})
	wide := sendEvent()
	wide.To = make([]string, event.MaxRecipients+1)
	for i := range wide.To {
		wide.To[i] = fmt.Sprintf("u@d%d.example", i)
	}
	for _, ev := range []event.Event{
		{},
		{Type: "teleport", AccountID: "a"},
		{Type: event.Send},
		{Type: event.Feedback, AccountID: "a"},
		{Type: event.KeyLeak},
		{Type: event.Send, AccountID: "acct\x00"},
		wide,
		{Type: event.Send, AccountID: "a", Time: time.Unix(0, 0)},
	} {
		_, err := h.eng.Decide(context.Background(), ev)
		if !errors.Is(err, ErrInvalidEvent) || !errors.Is(err, event.ErrInvalid) {
			t.Errorf("Decide(%.80v) error = %v, want ErrInvalidEvent", ev, err)
		}
	}
	if calls := h.cat.callLog(); len(calls) != 0 {
		t.Errorf("catalog was called for invalid events: %v", calls)
	}
}

func TestDecideBoundsEventTime(t *testing.T) {
	atTime := func(at time.Time) event.Event {
		ev := sendEvent()
		ev.Time = at
		return ev
	}
	at := func(d time.Duration) event.Event { return atTime(t0.Add(d)) }
	tests := []struct {
		name string
		ev   event.Event
		want time.Time // the time observed; zero when the event is rejected
	}{
		{"no time takes the clock's", sendEvent(), t0},
		{"slightly ahead is kept", at(DefaultMaxFutureSkew), t0.Add(DefaultMaxFutureSkew)},
		{"further ahead takes the clock's", at(DefaultMaxFutureSkew + time.Millisecond), t0},
		{"a month ahead takes the clock's", at(30 * 24 * time.Hour), t0},
		{"centuries ahead takes the clock's", atTime(time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)), t0},
		{"in another zone", atTime(t0.Add(-time.Hour).In(time.FixedZone("BRT", -3*60*60))), t0.Add(-time.Hour)},
		{"hours late is kept", at(-5 * time.Hour), t0.Add(-5 * time.Hour)},
		{"as old as allowed is kept", at(-DefaultMaxEventAge), t0.Add(-DefaultMaxEventAge)},
		{"older is rejected", at(-DefaultMaxEventAge - time.Millisecond), time.Time{}},
		{"1970 is rejected", event.Event{Type: event.Send, AccountID: "a", Time: time.Unix(0, 0)}, time.Time{}},
		{"an old leak report takes the clock's", event.Event{Type: event.KeyLeak, APIKeyID: "key_9", Time: time.Unix(0, 0)}, t0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A clock that stands still, so the observed time is exact.
			h := newHarness(t, Options{Now: func() time.Time { return t0 }})
			_, err := h.eng.Decide(context.Background(), tt.ev)
			if tt.want.IsZero() {
				if !errors.Is(err, ErrInvalidEvent) || !strings.Contains(err.Error(), "in the past") {
					t.Fatalf("error = %v, want an event rejected for its age", err)
				}
				if len(h.cat.observed) != 0 {
					t.Error("a rejected event was observed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := h.cat.observed[0].Time; !got.Equal(tt.want) || got.Location() != time.UTC {
				t.Errorf("observed time = %s, want %s in UTC", got, tt.want)
			}
		})
	}
}

func TestDecideCountsEventTimesOutOfBounds(t *testing.T) {
	h := newHarness(t, Options{MaxFutureSkew: time.Minute, MaxEventAge: time.Hour})
	ahead, late := sendEvent(), sendEvent()
	ahead.Time = t0.Add(2 * time.Minute)
	late.Time = t0.Add(-2 * time.Hour)
	h.decide(t, ahead)
	if _, err := h.eng.Decide(context.Background(), late); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("late event: error = %v", err)
	}
	within := sendEvent()
	within.Time = t0.Add(-30 * time.Minute)
	h.decide(t, within)
	for bound, want := range map[string]float64{"future": 1, "past": 1} {
		if got := counter(t, h.reg, "catraca_event_times_out_of_bounds_total", map[string]string{"bound": bound}); got != want {
			t.Errorf("out of bounds {bound=%s} = %v, want %v", bound, got, want)
		}
	}
}

func TestDecideTrustEventTime(t *testing.T) {
	h := newHarness(t, Options{TrustEventTime: true})
	past, future := sendEvent(), sendEvent()
	past.Time = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	future.Time = t0.Add(365 * 24 * time.Hour)
	h.decide(t, past)
	h.decide(t, future)
	if got := h.cat.observed; !got[0].Time.Equal(past.Time) || !got[1].Time.Equal(future.Time) {
		t.Errorf("observed times %s and %s, want the events' own", got[0].Time, got[1].Time)
	}
}

func TestDecideKeyLeakWithAnOldTime(t *testing.T) {
	h := newHarness(t, Options{})
	d := h.decide(t, event.Event{Type: event.KeyLeak, APIKeyID: "key_9", Time: time.Unix(0, 0)})
	if calls := h.cat.callLog(); len(calls) != 2 || calls[0] != "mark:key_9" {
		t.Errorf("catalog calls %v, want the key marked leaked, then observed", calls)
	}
	if d.ID == "" {
		t.Errorf("decision %+v", d)
	}
}

func TestDecideWithoutRuleset(t *testing.T) {
	h := newHarness(t, Options{Rules: &rules.Holder{}})
	if _, err := h.eng.Decide(context.Background(), sendEvent()); !errors.Is(err, ErrNoRuleset) {
		t.Errorf("error = %v, want ErrNoRuleset", err)
	}
	if calls := h.cat.callLog(); len(calls) != 0 {
		t.Errorf("catalog was called: %v", calls)
	}
}

func TestDecideCombinesEnforcedMatches(t *testing.T) {
	tests := []struct {
		name       string
		account    map[string]any
		key        map[string]any
		action     decision.Action
		retryAfter time.Duration
		enforced   []string
		shadow     []string
	}{
		{
			name:    "throttle",
			account: map[string]any{"sends_1m": int64(150), "age_hours": 5000.0},
			action:  decision.Throttle, retryAfter: 30 * time.Second, enforced: []string{"burst"},
		},
		{
			name:    "largest retry_after among enforced throttles",
			account: map[string]any{"sends_1m": int64(5000), "age_hours": 5000.0},
			action:  decision.Throttle, retryAfter: 5 * time.Minute, enforced: []string{"burst", "big-burst"},
		},
		{
			name:    "shadow match is recorded but does not act",
			account: map[string]any{"sends_1m": int64(3), "age_hours": 2.0},
			action:  decision.Allow, shadow: []string{"young"},
		},
		{
			name:    "block outranks throttle and clears retry_after",
			account: map[string]any{"sends_1m": int64(5000), "age_hours": 2.0},
			key:     map[string]any{"leaked": true},
			action:  decision.Block, enforced: []string{"leaked", "burst", "big-burst"}, shadow: []string{"young"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Options{})
			h.cat.set.Account = tt.account
			if tt.key != nil {
				h.cat.set.Key = tt.key
			}
			d := h.decide(t, sendEvent())
			if d.Action != tt.action || d.RetryAfter != tt.retryAfter {
				t.Errorf("action = %s retry_after = %s, want %s %s", d.Action, d.RetryAfter, tt.action, tt.retryAfter)
			}
			if !slices.Equal(ruleIDs(d.Matches), tt.enforced) || !slices.Equal(ruleIDs(d.Shadow), tt.shadow) {
				t.Errorf("enforced = %v shadow = %v, want %v %v", ruleIDs(d.Matches), ruleIDs(d.Shadow), tt.enforced, tt.shadow)
			}
		})
	}
}

func TestDecideStoreFailure(t *testing.T) {
	h := newHarness(t, Options{})
	h.cat.set = signal.Set{Event: map[string]any{"type": "send", "api_key_id": "key_1"}}
	h.cat.err = errors.New("redis: connection refused")

	d := h.decide(t, sendEvent())
	if !d.Degraded {
		t.Error("decision is not degraded")
	}
	// leaked fails closed, so the send is blocked; burst, big-burst and
	// young fail open and are skipped.
	if d.Action != decision.Block || !slices.Equal(ruleIDs(d.Matches), []string{"leaked"}) || !d.Matches[0].Errored {
		t.Errorf("matches = %+v, want leaked matched as errored", d.Matches)
	}
	if len(d.Shadow) != 0 {
		t.Errorf("shadow = %v, want none: young fails open", ruleIDs(d.Shadow))
	}
	var errored []string
	for _, e := range d.Errors {
		errored = append(errored, e.RuleID)
	}
	if !slices.Equal(errored, []string{"leaked", "burst", "big-burst", "young"}) {
		t.Errorf("errors = %v", d.Errors)
	}
	if !strings.Contains(d.Errors[1].Error, "signal account.sends_1m is absent") {
		t.Errorf("error message = %q", d.Errors[1].Error)
	}
	if got := counter(t, h.reg, "catraca_degraded_decisions_total", nil); got != 1 {
		t.Errorf("degraded counter = %v, want 1", got)
	}
	// leaked lists revoke_key, but it matched only by failing closed: an
	// outage must not revoke every key that sends.
	if effects := d.Effects(); len(effects) != 0 || len(h.disp.calls) != 0 {
		t.Errorf("effects = %v, dispatched %d times, want none for an errored match", effects, len(h.disp.calls))
	}
}

func TestDecideStoreFailureWithAKnownLeakedKey(t *testing.T) {
	h := newHarness(t, Options{})
	h.cat.set = signal.Set{
		Event: map[string]any{"type": "send", "api_key_id": "key_1"},
		Key:   map[string]any{"leaked": true},
	}
	h.cat.err = errors.New("redis: connection refused")

	d := h.decide(t, sendEvent())
	if !d.Degraded || d.Action != decision.Block || !slices.Equal(ruleIDs(d.Matches), []string{"leaked"}) || d.Matches[0].Errored {
		t.Errorf("decision = %+v, want a degraded block by leaked, not errored", d)
	}
	if len(h.disp.calls) != 1 || !slices.Equal(h.disp.calls[0].d.Effects(), []string{"revoke_key"}) {
		t.Errorf("dispatched %d times, want once with revoke_key", len(h.disp.calls))
	}
}

func TestDecideStoreFailureWithoutKey(t *testing.T) {
	h := newHarness(t, Options{})
	h.cat.set = signal.Set{Event: map[string]any{"type": "send", "api_key_id": ""}}
	h.cat.err = errors.New("timeout")

	ev := sendEvent()
	ev.APIKeyID = ""
	d := h.decide(t, ev)
	if d.Action != decision.Allow || !d.Degraded {
		t.Errorf("decision = %+v, want a degraded allow: a broken store never blocks everyone", d)
	}
}

func TestDecideObserveDeadline(t *testing.T) {
	h := newHarness(t, Options{Deadline: 20 * time.Millisecond, Now: time.Now})
	h.cat.hang = true

	start := time.Now()
	d := h.decide(t, sendEvent())
	elapsed := time.Since(start)

	if !d.Degraded {
		t.Error("decision is not degraded after the deadline")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Decide took %s; the deadline did not bound Observe", elapsed)
	}
	if left := h.cat.deadline.Sub(start); left <= 0 || left > 20*time.Millisecond+deadlineSlack {
		t.Errorf("Observe got a deadline %s after the call, want about 20ms", left)
	}
	if d.LatencyMicros < 20_000 {
		t.Errorf("latency = %dµs, want at least the 20ms deadline", d.LatencyMicros)
	}
}

func TestDecideDefaultDeadline(t *testing.T) {
	h := newHarness(t, Options{Now: time.Now})
	start := time.Now()
	h.decide(t, sendEvent())
	if left := h.cat.deadline.Sub(start); left <= 0 || left > DefaultDeadline+deadlineSlack {
		t.Errorf("Observe deadline is %s away, want about %s", left, DefaultDeadline)
	}
}

func TestDecideKeyLeak(t *testing.T) {
	h := newHarness(t, Options{})
	h.cat.set = signal.Set{Event: map[string]any{"type": "key_leak", "api_key_id": "key_9"}, Key: map[string]any{"leaked": true}}

	d := h.decide(t, event.Event{Type: event.KeyLeak, APIKeyID: "key_9", Leak: &event.LeakInfo{Source: "github"}})
	if calls := h.cat.callLog(); !slices.Equal(calls, []string{"mark:key_9", "observe"}) {
		t.Errorf("catalog calls = %v, want the key marked before Observe", calls)
	}
	if d.Action != decision.Flag || !slices.Equal(ruleIDs(d.Matches), []string{"leak-report"}) {
		t.Errorf("decision = %+v", d)
	}
	if len(h.disp.calls) != 1 {
		t.Errorf("dispatcher calls = %d, want 1 for the revoke_key effect", len(h.disp.calls))
	}
}

func TestDecideKeyLeakMarkFailure(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 4)}
	h := newHarness(t, Options{Recorder: rec})
	h.cat.markErr = errors.New("store down")

	_, err := h.eng.Decide(context.Background(), event.Event{Type: event.KeyLeak, APIKeyID: "key_9"})
	if err == nil || !strings.Contains(err.Error(), "store down") {
		t.Fatalf("error = %v, want the MarkLeaked failure", err)
	}
	if calls := h.cat.callLog(); !slices.Equal(calls, []string{"mark:key_9"}) {
		t.Errorf("catalog calls = %v, want nothing observed so the caller can retry", calls)
	}
	if err := h.eng.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rec.ch) != 0 {
		t.Error("a failed decision was recorded")
	}
}

// TestDecideKeyLeakMarkDeadline checks that marking a key leaked gives up at
// the deadline instead of waiting for the store as long as the caller does.
func TestDecideKeyLeakMarkDeadline(t *testing.T) {
	h := newHarness(t, Options{Deadline: 20 * time.Millisecond, Now: time.Now})
	h.cat.markHang = true

	start := time.Now()
	_, err := h.eng.Decide(context.Background(), event.Event{Type: event.KeyLeak, APIKeyID: "key_9"})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the deadline", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Decide took %s; the deadline did not bound MarkLeaked", elapsed)
	}
	if left := h.cat.markDeadline.Sub(start); left <= 0 || left > 20*time.Millisecond+deadlineSlack {
		t.Errorf("MarkLeaked got a deadline %s after the call, want about 20ms", left)
	}
	if calls := h.cat.callLog(); !slices.Equal(calls, []string{"mark:key_9"}) {
		t.Errorf("catalog calls = %v, want nothing observed so the caller can retry", calls)
	}
}

// TestDecideKeyLeakWithRedisUnreachable runs key_leak events against the
// Redis store the server opens, pointed at a server that accepts connections
// and never answers, as when packets are dropped. Decide must answer at the
// deadline, not after the client's read timeout.
func TestDecideKeyLeakWithRedisUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	s, err := store.OpenRedis("redis://"+ln.Addr().String()+"/0", store.RedisOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cat := signal.NewCatalog(s, signal.Options{})
	t.Cleanup(func() { cat.Close() })
	h := newHarness(t, Options{Catalog: cat, Deadline: 50 * time.Millisecond, Now: time.Now})

	for _, key := range []string{"key_a", "key_b"} {
		start := time.Now()
		_, err := h.eng.Decide(context.Background(), event.Event{Type: event.KeyLeak, APIKeyID: key})
		if err == nil {
			t.Fatalf("%s: Decide succeeded with Redis not answering", key)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("%s: Decide took %s, want about the 50ms deadline", key, elapsed)
		}
	}
}

func TestDecideRecordsEveryDecision(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 16)}
	h := newHarness(t, Options{Recorder: rec})

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "trace-1"))
	var want []string
	for range 3 {
		d, err := h.eng.Decide(ctx, sendEvent())
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, d.ID)
	}
	cancel()
	if err := h.eng.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(rec.ch)
	var got []string
	for r := range rec.ch {
		got = append(got, r.d.ID)
		if r.ev.ID != r.d.EventID || r.ev.ID == "" {
			t.Errorf("recorded event id %q does not match decision event id %q", r.ev.ID, r.d.EventID)
		}
		if r.ctx.Err() != nil || r.ctx.Value(ctxKey{}) != "trace-1" {
			t.Error("recorder context is canceled or lost the caller's values")
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("recorded %v, want %v in order", got, want)
	}
}

type ctxKey struct{}

func TestDecideDropsRecordsWhenTheRecorderIsSlow(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 100), block: make(chan struct{})}
	h := newHarness(t, Options{Recorder: rec, RecordQueue: 2})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10 {
			if _, err := h.eng.Decide(context.Background(), sendEvent()); err != nil {
				t.Error(err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Decide blocked on a slow recorder")
	}
	// One record is in the recorder, two wait in the queue, the rest drop.
	if got := counter(t, h.reg, "catraca_records_dropped_total", nil); got < 7 {
		t.Errorf("dropped = %v, want at least 7", got)
	}
}

func TestCloseTimesOut(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 1), block: make(chan struct{})}
	h := newHarness(t, Options{Recorder: rec})
	h.decide(t, sendEvent())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h.eng.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close error = %v, want the context's deadline", err)
	}
	close(rec.block)
	if err := h.eng.Close(context.Background()); err != nil {
		t.Errorf("second Close error = %v", err)
	}
	// Decisions after Close still work; they are just not recorded.
	h.decide(t, sendEvent())
}

func TestCloseWithoutRecorder(t *testing.T) {
	h := newHarness(t, Options{})
	if err := h.eng.Close(context.Background()); err != nil {
		t.Error(err)
	}
	if err := h.eng.Sync(context.Background()); err != nil {
		t.Errorf("Sync without a recorder = %v", err)
	}
}

// TestSyncWaitsForQueuedDecisions checks that Sync returns only once the
// decisions made before it have reached the recorder, so a read that
// follows a decision's response finds it.
func TestSyncWaitsForQueuedDecisions(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 16), block: make(chan struct{})}
	h := newHarness(t, Options{Recorder: rec})
	var want []string
	for range 3 {
		want = append(want, h.decide(t, sendEvent()).ID)
	}

	synced := make(chan error, 1)
	go func() { synced <- h.eng.Sync(context.Background()) }()
	// The recorder holds the first decision, so Sync cannot return yet.
	select {
	case err := <-synced:
		t.Fatalf("Sync returned %v while the decisions were still queued", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(rec.block)
	if err := <-synced; err != nil {
		t.Fatalf("Sync = %v", err)
	}
	if len(rec.ch) != len(want) {
		t.Fatalf("Sync returned with %d of %d decisions recorded", len(rec.ch), len(want))
	}
	for _, id := range want {
		if r := <-rec.ch; r.d.ID != id {
			t.Errorf("recorded %s, want %s", r.d.ID, id)
		}
	}
}

func TestSyncEndsWithItsContext(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 4), block: make(chan struct{})}
	h := newHarness(t, Options{Recorder: rec, RecordQueue: 1})
	// One decision in the recorder and one filling the queue: Sync's marker
	// has to wait for room.
	h.decide(t, sendEvent())
	waitFor(t, func() bool { return len(h.eng.records.jobs) == 0 })
	h.decide(t, sendEvent())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h.eng.Sync(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Sync with the queue full = %v, want the context's deadline", err)
	}
	close(rec.block)
	if err := h.eng.Sync(context.Background()); err != nil {
		t.Errorf("Sync once the recorder moves = %v", err)
	}
	if err := h.eng.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Sync(context.Background()); err != nil {
		t.Errorf("Sync after Close = %v", err)
	}
	if len(rec.ch) != 2 {
		t.Errorf("recorded %d decisions, want 2", len(rec.ch))
	}
}

// waitFor polls cond until it holds, for state another goroutine changes.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met after 10s")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDecideDispatchesEnforcedEffects(t *testing.T) {
	h := newHarness(t, Options{})

	// Shadow effects (young) and matches without effects (burst) do not
	// dispatch.
	h.cat.set.Account = map[string]any{"sends_1m": int64(150), "age_hours": 2.0}
	h.decide(t, sendEvent())
	if len(h.disp.calls) != 0 {
		t.Fatalf("dispatched %d times for a decision without enforced effects", len(h.disp.calls))
	}

	h.cat.set.Key = map[string]any{"leaked": true}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := h.eng.Decide(ctx, sendEvent())
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(h.disp.calls) != 1 {
		t.Fatalf("dispatched %d times, want 1", len(h.disp.calls))
	}
	call := h.disp.calls[0]
	if call.d.ID != d.ID || !slices.Equal(call.d.Effects(), []string{"revoke_key"}) || call.ev.ID != d.EventID {
		t.Errorf("dispatched %+v", call.d)
	}
	if call.ctx.Err() != nil {
		t.Error("dispatcher context is canceled with the caller's")
	}
}

func TestDecideUsesTheCurrentRuleset(t *testing.T) {
	h := newHarness(t, Options{})
	before := h.decide(t, sendEvent())

	next, err := rules.Parse([]byte("version: 1\nrules:\n  - id: all\n    when: event.type == \"send\"\n    action: hold\n    mode: enforce\n    on_error: open\n    reason: everything\n"))
	if err != nil {
		t.Fatal(err)
	}
	h.holder.Store(next)
	after := h.decide(t, sendEvent())
	if after.Action != decision.Hold || after.RulesetVersion != next.Version() || after.RulesetVersion == before.RulesetVersion {
		t.Errorf("after swap: %+v", after)
	}
}

func TestDecideMetrics(t *testing.T) {
	h := newHarness(t, Options{})
	h.decide(t, sendEvent())
	h.cat.set.Account = map[string]any{"sends_1m": int64(150), "age_hours": 2.0}
	h.decide(t, sendEvent())
	h.cat.set.Account = map[string]any{}
	h.decide(t, sendEvent())

	checks := []struct {
		name   string
		labels map[string]string
		want   float64
	}{
		{"catraca_decisions_total", map[string]string{"action": "allow"}, 2},
		{"catraca_decisions_total", map[string]string{"action": "throttle"}, 1},
		{"catraca_decisions_total", map[string]string{"action": "block"}, 0},
		{"catraca_rule_matches_total", map[string]string{"rule": "burst", "mode": "enforce"}, 1},
		{"catraca_rule_matches_total", map[string]string{"rule": "young", "mode": "shadow"}, 1},
		{"catraca_rule_errors_total", map[string]string{"rule": "burst"}, 1},
		{"catraca_rule_errors_total", map[string]string{"rule": "young"}, 1},
		{"catraca_degraded_decisions_total", nil, 0},
	}
	for _, c := range checks {
		if got := counter(t, h.reg, c.name, c.labels); got != c.want {
			t.Errorf("%s%v = %v, want %v", c.name, c.labels, got, c.want)
		}
	}
	hist := family(t, h.reg, "catraca_decision_duration_seconds").GetMetric()[0].GetHistogram()
	if hist.GetSampleCount() != 3 || hist.GetBucket()[0].GetUpperBound() != 0.0001 {
		t.Errorf("histogram = %v", hist)
	}
}

func TestNew(t *testing.T) {
	cat := &fakeCatalog{}
	holder := &rules.Holder{}
	if _, err := New(Options{Rules: holder}); err == nil {
		t.Error("New without a catalog succeeded")
	}
	if _, err := New(Options{Catalog: cat}); err == nil {
		t.Error("New without rules succeeded")
	}
	if _, err := New(Options{Catalog: cat, Rules: holder, Deadline: -time.Second}); err == nil {
		t.Error("New with a negative deadline succeeded")
	}
	if _, err := New(Options{Catalog: cat, Rules: holder, MaxFutureSkew: -time.Second}); err == nil {
		t.Error("New with a negative MaxFutureSkew succeeded")
	}
	if _, err := New(Options{Catalog: cat, Rules: holder, MaxEventAge: -time.Second}); err == nil {
		t.Error("New with a negative MaxEventAge succeeded")
	}
	if _, err := New(Options{Catalog: cat, Rules: holder}); err != nil {
		t.Errorf("New without a registerer: %v", err)
	}
	reg := prometheus.NewRegistry()
	if _, err := New(Options{Catalog: cat, Rules: holder, Registerer: reg}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Catalog: cat, Rules: holder, Registerer: reg}); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("second engine on one registry: error = %v", err)
	}
}

func TestDecideConcurrently(t *testing.T) {
	rec := &chanRecorder{ch: make(chan recorded, 1000)}
	h := newHarness(t, Options{Recorder: rec, Now: time.Now})
	var mu sync.Mutex
	ids := map[string]bool{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				d, err := h.eng.Decide(context.Background(), sendEvent())
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				ids[d.ID] = true
				ids[d.EventID] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(ids) != 1600 {
		t.Errorf("got %d distinct ids, want 1600", len(ids))
	}
}

func family(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	t.Fatalf("metric %s is not registered", name)
	return nil
}

// counter returns the value of the counter with exactly these labels, or 0
// when that series does not exist yet.
func counter(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	for _, m := range family(t, reg, name).GetMetric() {
		if len(m.GetLabel()) != len(labels) {
			continue
		}
		match := true
		for _, l := range m.GetLabel() {
			if labels[l.GetName()] != l.GetValue() {
				match = false
			}
		}
		if match {
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func TestDecisionTimeIsUTC(t *testing.T) {
	brasilia := time.FixedZone("BRT", -3*60*60)
	h := newHarness(t, Options{Now: func() time.Time { return time.Date(2026, 10, 15, 20, 17, 50, 0, brasilia) }})
	d := h.decide(t, sendEvent())
	if d.Time.Location() != time.UTC || d.Time.Hour() != 23 {
		t.Errorf("decision time = %s, want the same instant in UTC", d.Time)
	}
}

func TestLatencyIsMeasuredWithoutFakeClock(t *testing.T) {
	h := newHarness(t, Options{})
	d := h.decide(t, sendEvent())
	if d.LatencyMicros < 0 || d.LatencyMicros > 1_000_000 {
		t.Errorf("latency = %dµs", d.LatencyMicros)
	}
}
