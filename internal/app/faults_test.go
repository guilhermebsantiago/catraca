package app_test

// The fault scenarios run the server as it is deployed, with its HTTP
// server, a real Redis and, in CI, a real Postgres, each reached through a
// faultproxy, and break one dependency in the middle of a run. Each checks
// what docs/design.md promises for its fault (docs/faults.md lists them)
// and, throughout, that:
//
//   - every decision is answered, within the deadline plus latencyMargin;
//   - /readyz stays ready, while /readyz?verbose and the metrics say what
//     is wrong;
//   - nothing panics, and the goroutines the fault held up return once it
//     is over, and every goroutine once the test has closed the server;
//   - the server recovers fully once the dependency is back.
//
// They take minutes, so they run only when CATRACA_TEST_FAULTS is set. They
// never run in parallel, since each counts the process's goroutines.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/faultproxy"
	"github.com/guilhermebsantiago/catraca/internal/hooks"
	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

const (
	// faultsEnv turns the fault scenarios on.
	faultsEnv = "CATRACA_TEST_FAULTS"
	// postgresURLEnv points the Postgres scenarios at a server, as it
	// points the audit package's contract tests at one.
	postgresURLEnv = "CATRACA_TEST_POSTGRES_URL"

	// latencyMargin is how much longer than the engine's budget a decision
	// may take, seen from the client: the HTTP round trip and the
	// scheduling of a machine busy with the load. Every fault that holds a
	// call up holds it longer than the deadline plus this margin, so a
	// decision that waited for it is caught.
	latencyMargin = time.Second
	// goroutineSlack is how many more goroutines than before a fault may
	// remain once the server has recovered: dependency checks and
	// connections come and go.
	goroutineSlack = 10
	// loadWorkers is how many requests the load keeps in flight.
	loadWorkers = 16
)

// needFaults skips the test unless the fault scenarios are turned on.
func needFaults(t *testing.T) {
	t.Helper()
	if os.Getenv(faultsEnv) == "" {
		t.Skip("set " + faultsEnv + "=1 to run the fault scenarios; see docs/faults.md")
	}
}

// await polls ok until it holds, and fails the test with what it waited for
// once timeout has passed.
func await(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// goroutines returns the stacks of the goroutines running, but for the
// proxies': those stand for the network, and they run for as long as the
// server keeps a connection open, idle in a pool or not.
func goroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var out []string
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if !strings.Contains(g, "/internal/faultproxy.") {
			out = append(out, g)
		}
	}
	return out
}

// closeIdleConns closes the idle keep-alive connections of the test's
// client and of http.DefaultTransport, which the hooks and the resolver
// use. Each holds goroutines until it times out, which a count of the
// goroutines would take for a leak. h may be nil once it is closed.
func closeIdleConns(h *harness) {
	if h != nil {
		h.srv.Client().CloseIdleConnections()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
}

// quietGoroutines returns the fewest goroutines seen over half a second,
// which leaves out those that only come and go.
func quietGoroutines(h *harness) int {
	closeIdleConns(h)
	n := len(goroutines())
	for range 10 {
		time.Sleep(50 * time.Millisecond)
		n = min(n, len(goroutines()))
	}
	return n
}

// settled waits for the goroutines to come back to at most baseline plus
// goroutineSlack, and fails the test with their stacks if they do not
// within timeout: something the fault held up never returned.
func settled(t *testing.T, h *harness, what string, baseline int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		closeIdleConns(h)
		gs := goroutines()
		if len(gs) <= baseline+goroutineSlack {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%s: %d goroutines, %d before; they did not return within %s:\n\n%s",
				what, len(gs), baseline, timeout, strings.Join(gs, "\n\n"))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// leakCheck fails the test when goroutines it started are still running
// once it has ended and every cleanup has run: the server, the proxies and
// the fakes are all closed by then. Call it first, so its cleanup runs
// last.
func leakCheck(t *testing.T) {
	t.Helper()
	start := len(goroutines())
	t.Cleanup(func() { settled(t, nil, "after the test", start, 20*time.Second) })
}

// metric returns the value of series on the /metrics page, written as the
// page writes it, labels in order, such as
// catraca_store_breaker_state{state="open"}. It returns NaN when the page
// has no such series, which fails every comparison.
func (h *harness) metric(series string) float64 {
	h.t.Helper()
	for line := range strings.Lines(h.metrics()) {
		rest, ok := strings.CutPrefix(line, series+" ")
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
		if err != nil {
			h.t.Fatalf("metric %s: %v", series, err)
		}
		return v
	}
	return math.NaN()
}

// readiness returns /readyz?verbose, and fails the test unless the server
// is ready: a dependency that fails degrades decisions, and it is not a
// reason to take the server out of the load balancer.
func (h *harness) readiness() api.ReadyResponse {
	h.t.Helper()
	r := h.do("GET", "/readyz?verbose", "", nil)
	var ready api.ReadyResponse
	r.json(h.t, &ready)
	if r.status != http.StatusOK || ready.Status != "ready" {
		h.t.Errorf("readyz?verbose: %d %s; a dependency made the server unready", r.status, r.body)
	}
	return ready
}

// awaitDependency waits until /readyz?verbose reports the dependency with
// status, and checks that catraca_dependency_up agrees.
func (h *harness) awaitDependency(name, status string) api.DependencyStatus {
	h.t.Helper()
	var dep api.DependencyStatus
	// The checks run every 5 seconds and time out after 2.
	await(h.t, fmt.Sprintf("/readyz?verbose reports %s %s", name, status), 30*time.Second, func() bool {
		dep = h.readiness().Dependencies[name]
		return dep.Status == status
	})
	want := 0.0
	if status == "ok" {
		want = 1
	}
	// A scrape reads the leaked-key reports from the audit database, for
	// up to 2 seconds when it hangs.
	await(h.t, fmt.Sprintf("catraca_dependency_up for %s is %v", name, want), 15*time.Second, func() bool {
		return h.metric(`catraca_dependency_up{dependency="`+name+`"}`) == want
	})
	return dep
}

// checkNoPanics fails the test if the server logged a panic, such as one the
// HTTP server recovered from.
func (h *harness) checkNoPanics() {
	h.t.Helper()
	if logs := h.logs.String(); strings.Contains(logs, "panic") {
		h.t.Errorf("the server logged a panic:\n%s", logs)
	}
}

// load sends decisions from loadWorkers goroutines, as a busy platform does,
// and keeps what the server answered.
type load struct {
	base   string
	cancel context.CancelFunc
	wg     sync.WaitGroup
	client *http.Client
	once   sync.Once

	mu sync.Mutex
	// window is what came back since the last take, total since the
	// start.
	window, total loadStats
}

// loadStats is what a load got back.
type loadStats struct {
	requests, degraded, uncounted int
	statuses                      map[int]int
	// failures are the first requests that got no answer.
	failures []string
	// took is how long each request took, seen from the client, and
	// decided how long each decision took, as the engine measured it.
	took, decided []time.Duration
}

func newLoadStats() loadStats { return loadStats{statuses: map[int]int{}} }

func (s *loadStats) add(status int, d decision.Decision, took time.Duration) {
	s.requests++
	s.statuses[status]++
	if d.Degraded {
		s.degraded++
	}
	if d.Uncounted {
		s.uncounted++
	}
	s.took = append(s.took, took)
	s.decided = append(s.decided, time.Duration(d.LatencyMicros)*time.Microsecond)
}

func (s *loadStats) fail(msg string) {
	if len(s.failures) < 5 {
		s.failures = append(s.failures, msg)
	}
}

// loadSend is the event worker sends the ith time: a send from one of a
// few accounts of its own.
func loadSend(worker, i int) map[string]any {
	return send(fmt.Sprintf("acct_load_%d_%d", worker, i%20), "news@load.example")
}

// startLoad starts sending events made by next to h, until stop.
func startLoad(t *testing.T, h *harness, next func(worker, i int) map[string]any) *load {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	l := &load{
		base:   h.srv.URL,
		cancel: cancel,
		client: &http.Client{
			// Keep a connection per worker, rather than open one per
			// request, which runs out of ports on Windows.
			Transport: &http.Transport{MaxIdleConnsPerHost: loadWorkers},
			// A request that never comes back is reported as a failure
			// rather than hanging the test.
			Timeout: 30 * time.Second,
		},
		window: newLoadStats(),
		total:  newLoadStats(),
	}
	for w := range loadWorkers {
		l.wg.Go(func() {
			for i := 0; ctx.Err() == nil; i++ {
				l.send(ctx, next(w, i))
			}
		})
	}
	t.Cleanup(func() { l.stop() })
	return l
}

func (l *load) send(ctx context.Context, ev map[string]any) {
	body, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", l.base+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := l.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			l.fail(err.Error())
		}
		return
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	took := time.Since(start)
	if err != nil {
		if ctx.Err() == nil {
			l.fail(err.Error())
		}
		return
	}
	var out api.DecisionResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, &out); err != nil {
			l.fail(fmt.Sprintf("decode %s: %v", data, err))
			return
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.window.add(resp.StatusCode, out.Decision, took)
	l.total.add(resp.StatusCode, out.Decision, took)
}

func (l *load) fail(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.window.fail(msg)
	l.total.fail(msg)
}

// take returns what came back since the last take, or since the start.
func (l *load) take() loadStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.window
	l.window = newLoadStats()
	return s
}

// stop stops the load, closes its connections and returns everything that
// came back.
func (l *load) stop() loadStats {
	l.once.Do(func() {
		l.cancel()
		l.wg.Wait()
		l.client.CloseIdleConnections()
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// awaitClean waits for a second of decisions none of which is degraded.
func (l *load) awaitClean(t *testing.T, timeout time.Duration) {
	t.Helper()
	l.take()
	await(t, "a second of decisions none of which is degraded", timeout, func() bool {
		time.Sleep(time.Second)
		s := l.take()
		return s.requests > 0 && s.degraded == 0
	})
}

// percentiles describes ds by its median, 99th percentile and maximum.
func percentiles(ds []time.Duration) string {
	if len(ds) == 0 {
		return "none"
	}
	s := slices.Sorted(slices.Values(ds))
	at := func(p float64) time.Duration { return s[min(len(s)-1, int(p*float64(len(s))))] }
	return fmt.Sprintf("p50 %s, p99 %s, max %s", at(0.5), at(0.99), s[len(s)-1])
}

// check fails the test unless every request of the phase got a decision,
// each within budget, the time the engine may take, and latencyMargin.
func (s loadStats) check(t *testing.T, phase string, budget time.Duration) {
	t.Helper()
	t.Logf("%s: %d decisions, %d degraded, %d uncounted, statuses %v; requests %s; decisions %s",
		phase, s.requests, s.degraded, s.uncounted, s.statuses, percentiles(s.took), percentiles(s.decided))
	if s.requests == 0 {
		t.Errorf("%s: no decision was answered", phase)
	}
	for status, n := range s.statuses {
		if status != http.StatusOK {
			t.Errorf("%s: %d decisions answered %d", phase, n, status)
		}
	}
	if len(s.failures) > 0 {
		t.Errorf("%s: requests got no answer: %v", phase, s.failures)
	}
	if len(s.took) > 0 {
		if slowest, bound := slices.Max(s.took), budget+latencyMargin; slowest > bound {
			t.Errorf("%s: a decision took %s, more than its %s budget and the %s margin", phase, slowest, budget, latencyMargin)
		}
	}
}

// The Redis scenarios.

const (
	// redisDeadline is the engine's deadline in the Redis scenarios: short,
	// so that every fault dwarfs it, and long enough that a healthy Redis
	// on a busy machine makes it.
	redisDeadline = 100 * time.Millisecond
	// redisCooldown is the breaker's cooldown in the Redis scenarios.
	redisCooldown = time.Second
	// redisSlots is server.max_inflight in the Redis scenarios: room for
	// the load and for the adaptive limit to move.
	redisSlots = 2 * loadWorkers
)

// redisBehindProxy returns the URL of the Redis server at
// storetest.RedisURLEnv reached through a fault proxy, a key prefix of the
// test's own, whose keys are deleted when it ends, and a client that
// reaches the server directly.
func redisBehindProxy(t *testing.T) (string, string, *faultproxy.Proxy, *redis.Client) {
	t.Helper()
	if skip := storetest.RedisServerSkip(); skip != "" {
		t.Skip(skip)
	}
	direct, prefix := storetest.RedisServer(t)
	u, err := url.Parse(os.Getenv(storetest.RedisURLEnv))
	if err != nil || u.Host == "" {
		t.Fatalf("%s must be a redis:// URL with a host", storetest.RedisURLEnv)
	}
	proxy := faultproxy.New(t, direct.Options().Addr)
	u.Host = proxy.Addr()
	return u.String(), prefix, proxy, direct
}

// redisFaults sets the server up for a Redis scenario: counters under
// prefix, the deadline given, a breaker that cools down quickly and room
// for the load in the decision slots.
func redisFaults(prefix string, deadline time.Duration) func(*config.Config) {
	return func(c *config.Config) {
		c.Store.Redis.Prefix = prefix
		c.Engine.Deadline = deadline
		c.Engine.DispatchTimeout = deadline
		c.Engine.Breaker.Cooldown = redisCooldown
		c.Server.MaxInflight = redisSlots
	}
}

// warmUp runs the load against a healthy server, so connections, scripts
// and pools are in place, and returns how many goroutines run once it is
// over.
func warmUp(t *testing.T, h *harness, budget time.Duration) int {
	t.Helper()
	l := startLoad(t, h, loadSend)
	time.Sleep(time.Second)
	l.stop().check(t, "warm-up", budget)
	return quietGoroutines(h)
}

// TestFaultRedisLatency makes every Redis reply 2.4 seconds late: later
// than the deadline, the dependency check's timeout and the margin, sooner
// than go-redis's read timeout, so Redis answers and applies each call,
// late. Decisions are degraded at the deadline, the adaptive limit drops,
// the breaker opens, and all of it recovers once Redis is fast again.
func TestFaultRedisLatency(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	redisURL, prefix, proxy, _ := redisBehindProxy(t)
	h := newHarness(t, options{redisURL: redisURL, edit: redisFaults(prefix, redisDeadline)})
	h.awaitDependency("store", "ok")
	baseline := warmUp(t, h, redisDeadline)

	proxy.SetLatency(2400*time.Millisecond, 200*time.Millisecond)
	l := startLoad(t, h, loadSend)
	await(t, "the breaker opened", 15*time.Second, func() bool {
		return h.metric(`catraca_store_breaker_transitions_total{from="closed",to="open"}`) >= 1
	})
	await(t, "the adaptive limit dropped", 15*time.Second, func() bool {
		return h.metric(`catraca_admission_limit{group="decisions"}`) < redisSlots
	})
	h.awaitDependency("store", "timeout")
	slow := l.stop()
	slow.check(t, "slow Redis", redisDeadline)
	// Calls that missed the deadline still applied, so their decisions
	// are degraded but counted; those the breaker skipped are not.
	if slow.degraded == 0 || slow.degraded == slow.uncounted {
		t.Errorf("slow Redis: %d degraded decisions, %d of them uncounted; want some degraded and counted", slow.degraded, slow.uncounted)
	}

	proxy.Heal()
	l = startLoad(t, h, loadSend)
	await(t, "the breaker closed", redisCooldown+15*time.Second, func() bool {
		return h.metric(`catraca_store_breaker_state{state="closed"}`) == 1
	})
	await(t, "the adaptive limit climbed back", 30*time.Second, func() bool {
		return h.metric(`catraca_admission_limit{group="decisions"}`) >= loadWorkers
	})
	l.awaitClean(t, 30*time.Second)
	l.stop().check(t, "after", redisDeadline)
	h.awaitDependency("store", "ok")
	if n := h.metric(`catraca_store_breaker_transitions_total{from="half_open",to="closed"}`); n < 1 {
		t.Errorf("the breaker closed %v times from half-open, want at least once", n)
	}
	settled(t, h, "after Redis was slow", baseline, 30*time.Second)
	h.checkNoPanics()
}

// TestFaultRedisBlackhole drops every packet to and from Redis: calls hang
// until the client's read timeout. The breaker opens once they have failed
// for its window, from then on key leaks are answered 503 at once instead
// of at the deadline, and the store is used again after the cooldown once
// Redis is back.
func TestFaultRedisBlackhole(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	// A longer deadline than the other scenarios', so that a key leak
	// answered at once stands out from one answered at the deadline.
	const deadline = 300 * time.Millisecond
	redisURL, prefix, proxy, _ := redisBehindProxy(t)
	h := newHarness(t, options{redisURL: redisURL, edit: redisFaults(prefix, deadline)})
	h.awaitDependency("store", "ok")
	baseline := warmUp(t, h, deadline)

	proxy.SetBlackhole(true)
	start := time.Now()
	l := startLoad(t, h, loadSend)
	await(t, "the breaker opened", 15*time.Second, func() bool {
		return h.metric(`catraca_store_breaker_state{state="open"}`) == 1
	})
	// It opens once calls have failed for its window, and the first
	// failures end at the deadline.
	if opened, limit := time.Since(start), deadline+engine.DefaultBreakerWindow+2*time.Second; opened > limit {
		t.Errorf("the breaker opened %s into the blackhole, later than the deadline, its window and a margin (%s)", opened, limit)
	}
	var took []time.Duration
	for i := range 5 {
		start := time.Now()
		r := h.do("POST", "/v1/events", token, fmt.Sprintf(`{"type":"key_leak","api_key_id":"key_blackhole_%d"}`, i))
		took = append(took, time.Since(start))
		if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "1" || r.errorCode(t) != "unavailable" {
			t.Errorf("key_leak with Redis in a blackhole: %d %v %s", r.status, r.header, r.body)
		}
	}
	// A key leak that is a probe of the half-open breaker waits for the
	// deadline; the others are answered at once.
	slices.Sort(took)
	if median := took[len(took)/2]; median >= deadline/2 {
		t.Errorf("key leaks were answered in %v with the breaker open; want most at once, not at the %s deadline", took, deadline)
	}
	h.awaitDependency("store", "timeout")
	if n := h.metric("catraca_short_circuited_decisions_total"); !(n > 0) {
		t.Errorf("catraca_short_circuited_decisions_total = %v, want some", n)
	}
	down := l.stop()
	down.check(t, "Redis in a blackhole", deadline)
	if down.degraded == 0 {
		t.Error("no decision was degraded with Redis in a blackhole")
	}

	proxy.Heal()
	healed := time.Now()
	l = startLoad(t, h, loadSend)
	await(t, "the breaker closed", redisCooldown+15*time.Second, func() bool {
		return h.metric(`catraca_store_breaker_state{state="closed"}`) == 1
	})
	t.Logf("the breaker closed %s after Redis came back", time.Since(healed))
	l.awaitClean(t, 30*time.Second)
	l.stop().check(t, "after", deadline)
	if r := h.do("POST", "/v1/events", token, `{"type":"key_leak","api_key_id":"key_blackhole_after"}`); r.status != http.StatusAccepted {
		t.Errorf("key_leak once Redis is back: %d %s", r.status, r.body)
	}
	h.awaitDependency("store", "ok")
	// The calls the blackhole held finish at go-redis's 3 second read
	// timeout.
	settled(t, h, "after the blackhole", baseline, 30*time.Second)
	h.checkNoPanics()
}

// TestFaultRedisLostReply closes the connection after Redis ran a script
// call and before its reply, as a connection lost at the wrong moment
// does. The decision comes back uncounted, so feedback is answered 503 and
// sent again, and the retry, with the same event id, counts once: the
// script applied the first time, and the dedupe key it set makes the retry
// a duplicate. The client does not resend the call itself, which on the
// EOF it sees would count the event twice.
func TestFaultRedisLostReply(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	redisURL, prefix, proxy, _ := redisBehindProxy(t)
	h := newHarness(t, options{redisURL: redisURL, edit: redisFaults(prefix, redisDeadline)})
	baseline := warmUp(t, h, redisDeadline)

	// Generic feedback: complaints holds an account with two complaints.
	complaint := func(id string) string {
		return fmt.Sprintf(`{"id":%q,"account_id":"acct_lost_fb","feedback":{"kind":"complaint"}}`, id)
	}
	proxy.DropReply("evalsha")
	r := h.signedFeedback(complaint("fb-lost"), secret)
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("complaint whose reply was lost: %d %s; want 503 with Retry-After, so the provider sends it again", r.status, r.body)
	}
	r = h.signedFeedback(complaint("fb-lost"), secret)
	var out api.DecisionResponse
	r.json(t, &out)
	if r.status != http.StatusAccepted || !out.Decision.Duplicate {
		t.Errorf("complaint sent again: %d %s; want 202 and a duplicate, since the lost call applied", r.status, r.body)
	}
	if d, _ := h.decide(send("acct_lost_fb", "a@lost.example")); d.Action != decision.Allow || d.Degraded {
		t.Errorf("send after one complaint sent twice: %+v; want allowed, the complaint counted once", d)
	}
	if r := h.signedFeedback(complaint("fb-second"), secret); r.status != http.StatusAccepted {
		t.Fatalf("second complaint: %d %s", r.status, r.body)
	}
	if d, _ := h.decide(send("acct_lost_fb", "a@lost.example")); d.Action != decision.Hold {
		t.Errorf("send after two complaints: %+v; want held", d)
	}

	// A send: burst throttles the fourth in a minute.
	proxy.DropReply("evalsha")
	d, _ := h.decide(send("acct_lost_send", "a@lost.example", "id", "msg-lost"))
	if !d.Degraded || !d.Uncounted {
		t.Errorf("send whose reply was lost: %+v; want degraded and uncounted", d)
	}
	if d, _ := h.decide(send("acct_lost_send", "a@lost.example", "id", "msg-lost")); !d.Duplicate || d.Degraded {
		t.Errorf("send sent again: %+v; want a duplicate", d)
	}
	for _, id := range []string{"msg-2", "msg-3"} {
		if d, _ := h.decide(send("acct_lost_send", "a@lost.example", "id", id)); d.Action != decision.Allow {
			t.Errorf("%s: %+v; want allowed, the lost send counted once", id, d)
		}
	}
	if d, _ := h.decide(send("acct_lost_send", "a@lost.example", "id", "msg-4")); d.Action != decision.Throttle {
		t.Errorf("fourth send: %+v; want throttled", d)
	}

	for _, want := range []string{
		`catraca_feedback_outcomes_total{outcome="uncounted",provider="generic"} 1`,
		`catraca_duplicate_events_total{type="feedback"} 1`,
		`catraca_duplicate_events_total{type="send"} 1`,
		`catraca_store_breaker_state{state="closed"} 1`,
	} {
		if !strings.Contains(h.metrics(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	h.readiness()
	settled(t, h, "after the lost replies", baseline, 15*time.Second)
	h.checkNoPanics()
}

// TestFaultRedisRestart does to Redis what a restart without persistence
// does: connections are reset, refused for a moment, and the counters,
// dedupe keys and loaded scripts are gone when it is back. Decisions go on,
// degraded meanwhile, and the counters start again from zero without an
// error: the script is loaded again on the NOSCRIPT that follows.
func TestFaultRedisRestart(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	redisURL, prefix, proxy, direct := redisBehindProxy(t)
	h := newHarness(t, options{redisURL: redisURL, edit: redisFaults(prefix, redisDeadline)})
	baseline := warmUp(t, h, redisDeadline)

	burst := func(phase string) {
		t.Helper()
		for i := range 4 {
			d, _ := h.decide(send("acct_restart", "a@restart.example"))
			want := decision.Allow
			if i == 3 {
				want = decision.Throttle
			}
			if d.Action != want || d.Degraded {
				t.Errorf("%s, send %d: %+v; want %s, not degraded", phase, i+1, d, want)
			}
		}
	}
	burst("before the restart")

	l := startLoad(t, h, loadSend)
	proxy.SetRefuse(true)
	proxy.ResetConns()
	ctx := context.Background()
	for keys := storetest.ScanKeys(t, ctx, direct, prefix); len(keys) > 0; {
		n := min(len(keys), 1000)
		if err := direct.Unlink(ctx, keys[:n]...).Err(); err != nil {
			t.Fatal(err)
		}
		keys = keys[n:]
	}
	if err := direct.ScriptFlush(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	proxy.SetRefuse(false)
	await(t, "the breaker closed", redisCooldown+15*time.Second, func() bool {
		return h.metric(`catraca_store_breaker_state{state="closed"}`) == 1
	})
	l.awaitClean(t, 30*time.Second)
	l.stop().check(t, "during and after the restart", redisDeadline)

	// The account's sends were lost with the rest, so it gets three more
	// before it is throttled.
	burst("after the restart")
	h.awaitDependency("store", "ok")
	settled(t, h, "after the restart", baseline, 30*time.Second)
	h.checkNoPanics()
}

// The webhook and secret scanning scenarios, on the memory store and a
// SQLite audit database.

// effectsRules adds to testRules a rule that calls the notify hook as well
// as revoke_key.
const effectsRules = testRules + `  - id: both-hooks
    when: event.type == "send" && event.from_domain == "effects.example"
    action: flag
    mode: enforce
    on_error: open
    effects: [revoke_key, notify]
    reason: Calls both hooks
`

// receiver is a webhook receiver that answers 500 while failing is set, and
// 204 otherwise, and records each attempt by idempotency key.
type receiver struct {
	*httptest.Server
	failing atomic.Bool

	mu        sync.Mutex
	attempts  map[string][]time.Time
	delivered map[string]bool
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	rc := &receiver{attempts: map[string][]time.Time{}, delivered: map[string]bool{}}
	rc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		key := r.Header.Get(hooks.IdempotencyKeyHeader)
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.attempts[key] = append(rc.attempts[key], time.Now())
		if rc.failing.Load() {
			http.Error(w, "receiver failing", http.StatusInternalServerError)
			return
		}
		rc.delivered[key] = true
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(rc.Close)
	return rc
}

// deliveries returns how many deliveries the receiver accepted.
func (rc *receiver) deliveries() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.delivered)
}

// accepted reports whether the receiver accepted the delivery of every
// idempotency key in keys.
func (rc *receiver) accepted(keys []string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for _, k := range keys {
		if !rc.delivered[k] {
			return false
		}
	}
	return true
}

// attemptTimes returns the times of every delivery's attempts.
func (rc *receiver) attemptTimes() map[string][]time.Time {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make(map[string][]time.Time, len(rc.attempts))
	for k, v := range rc.attempts {
		out[k] = slices.Clone(v)
	}
	return out
}

// TestFaultWebhookReceiverDown points the notify hook at a receiver that
// first hangs, then answers 500, then recovers, while revoke_key's receiver
// is healthy. Each hook has its own lane: notify's attempts time out or
// fail and back off, holding at most its own concurrency of the workers,
// and revoke_key keeps delivering at once. Every notify delivery arrives
// once its receiver is back.
func TestFaultWebhookReceiverDown(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	notify := newReceiver(t)
	proxy := faultproxy.New(t, notify.Listener.Addr().String())
	h := newHarness(t, options{rules: effectsRules, edit: func(c *config.Config) {
		// Two workers, so a lane that took them all would stop the other.
		c.Outbox.Workers = 2
		c.Hooks[0].Concurrency = 1
		c.Hooks = append(c.Hooks, config.Hook{
			Name: "notify", URL: "http://" + proxy.Addr(), Secret: config.Secret(secret),
			Timeout: 500 * time.Millisecond, Concurrency: 1,
			MaxAttempts: hooks.DefaultMaxAttempts, MaxAge: hooks.DefaultMaxAge,
		})
	}})
	baseline := quietGoroutines(h)
	decided := 0
	decideEffects := func(n int) {
		t.Helper()
		for range n {
			d, _ := h.decide(send(fmt.Sprintf("acct_hooks_%d", decided), "news@effects.example"))
			decided++
			if effects := d.Effects(); !slices.Equal(effects, []string{"revoke_key", "notify"}) {
				t.Fatalf("decision effects = %v, want revoke_key and notify", effects)
			}
		}
	}

	// notify's receiver hangs.
	proxy.SetBlackhole(true)
	start := time.Now()
	decideEffects(10)
	await(t, "revoke_key delivered everything while notify hangs", 15*time.Second, func() bool {
		return len(h.hook.calls()) == 10
	})
	t.Logf("revoke_key delivered 10 effects in %s while notify hung", time.Since(start))
	await(t, "notify's attempts timed out and are retried", 15*time.Second, func() bool {
		return h.metric("catraca_hooks_retries_total") >= 2
	})

	// Then it answers 500.
	notify.failing.Store(true)
	proxy.Heal()
	start = time.Now()
	decideEffects(5)
	await(t, "revoke_key delivered everything while notify fails", 15*time.Second, func() bool {
		return len(h.hook.calls()) == 15
	})
	t.Logf("revoke_key delivered 5 effects in %s while notify failed", time.Since(start))
	await(t, "a notify delivery was attempted three times", 30*time.Second, func() bool {
		for _, times := range notify.attemptTimes() {
			if len(times) >= 3 {
				return true
			}
		}
		return false
	})
	// Retries wait at least half the minimum backoff of 2 seconds, so a
	// failing receiver is not hammered.
	for key, times := range notify.attemptTimes() {
		for i := 1; i < len(times); i++ {
			if gap := times[i].Sub(times[i-1]); gap < 900*time.Millisecond {
				t.Errorf("delivery %s: attempt %d came %s after the one before; want a backoff of a second or more", key, i+1, gap)
			}
		}
	}
	if n := notify.deliveries(); n != 0 {
		t.Errorf("notify accepted %d deliveries while failing", n)
	}

	// It recovers, and gets every delivery, each once.
	notify.failing.Store(false)
	await(t, "notify got every delivery", 90*time.Second, func() bool { return notify.deliveries() == 15 })
	if n := len(h.hook.calls()); n != 15 {
		t.Errorf("revoke_key got %d deliveries, want 15", n)
	}
	for _, want := range []string{
		"catraca_hooks_delivered_total 30",
		"catraca_hooks_dead_total 0",
		"catraca_hooks_enqueue_errors_total 0",
	} {
		if !strings.Contains(h.metrics(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	h.readiness()
	settled(t, h, "after the receiver recovered", baseline, 20*time.Second)
	h.checkNoPanics()
}

// TestFaultSecretScanningResolverDown accepts a leaked-key batch while the
// platform's resolver refuses connections: the reports are stored, stay
// pending through failed attempts, and are acted on once it is back.
func TestFaultSecretScanningResolverDown(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	resolver := newSwitchableResolver(t)
	proxy := faultproxy.New(t, resolver.Listener.Addr().String())
	proxy.SetRefuse(true)
	h := newHarness(t, options{resolverURL: "http://" + proxy.Addr()})
	baseline := quietGoroutines(h)

	if r := h.postLeaks(leakBatch); r.status != http.StatusAccepted {
		t.Fatalf("batch with the resolver down: %d %s; want it stored and accepted", r.status, r.body)
	}
	await(t, "attempts failed and are retried", 20*time.Second, func() bool {
		return h.metric(`catraca_secret_scanning_outcomes_total{outcome="retry"}`) >= 2
	})
	m := h.metrics()
	for _, want := range []string{
		`catraca_secret_scanning_reports{status="pending"} 2`,
		`catraca_secret_scanning_reports{status="dead"} 0`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if d, _ := h.decide(send("acct_resolver", "app@leak.example", "api_key_id", "key_leaked")); d.Action != decision.Allow || d.Degraded {
		t.Errorf("send with the key not yet resolved: %+v", d)
	}

	proxy.Heal()
	// Attempts back off from a second, doubling.
	await(t, "the reports were acted on", 60*time.Second, func() bool {
		m := h.metrics()
		return strings.Contains(m, `catraca_secret_scanning_reports{status="pending"} 0`) &&
			strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="leaked"} 1`) &&
			strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="not_found"} 1`)
	})
	if d, _ := h.decide(send("acct_resolver_after", "app@leak.example", "api_key_id", "key_leaked")); d.Action != decision.Block {
		t.Errorf("send with the leaked key once resolved: %+v; want blocked", d)
	}
	await(t, "revoke_key was called", 15*time.Second, func() bool { return len(h.hook.calls()) == 1 })
	h.readiness()
	settled(t, h, "after the resolver came back", baseline, 20*time.Second)
	h.checkNoPanics()
}

// The Postgres scenarios run where CATRACA_TEST_POSTGRES_URL points at a
// server: in CI.

// postgresDeadline is the engine's deadline and dispatch budget in the
// Postgres scenarios.
const postgresDeadline = 100 * time.Millisecond

// postgresBehindProxy creates a schema of the test's own on the Postgres
// server at postgresURLEnv, dropped when it ends, and returns a DSN that
// reaches it through a fault proxy.
func postgresBehindProxy(t *testing.T) (string, *faultproxy.Proxy) {
	t.Helper()
	base := os.Getenv(postgresURLEnv)
	if base == "" {
		t.Skip("set " + postgresURLEnv + " to run the Postgres fault scenarios")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" {
		t.Fatalf("%s must be a postgres:// URL with a host", postgresURLEnv)
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("catraca_fault_%d", time.Now().UnixNano())
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
	target := u.Host
	if u.Port() == "" {
		target = u.Hostname() + ":5432"
	}
	proxy := faultproxy.New(t, target)
	q := u.Query()
	q.Set("search_path", schema)
	// As docs/config.md advises: without it, a connection opened into a
	// partition waits for the operating system to give up on it, and
	// database/sql opens some in the background, with no deadline of
	// their own.
	q.Set("connect_timeout", "5")
	u.RawQuery = q.Encode()
	u.Host = proxy.Addr()
	return u.String(), proxy
}

// postgresScenario is a server whose audit database is Postgres behind a
// proxy, with a resolver and a revoke_key receiver the test can break.
type postgresScenario struct {
	*harness
	proxy    *faultproxy.Proxy
	resolver *switchableResolver
	revoke   *receiver
	// leaks counts the key_leak events sent, each with a key of its own.
	leaks int
	// revocations are the idempotency keys of the revoke_key deliveries
	// that were written to the outbox, and must arrive.
	revocations []string
}

func newPostgresScenario(t *testing.T) *postgresScenario {
	t.Helper()
	dsn, proxy := postgresBehindProxy(t)
	s := &postgresScenario{proxy: proxy, resolver: newSwitchableResolver(t), revoke: newReceiver(t)}
	s.harness = newHarness(t, options{auditDSN: dsn, resolverURL: s.resolver.URL, edit: func(c *config.Config) {
		c.Engine.Deadline = postgresDeadline
		c.Engine.DispatchTimeout = postgresDeadline
		c.Hooks[0].URL = s.revoke.URL
	}})
	s.awaitDependency("audit", "ok")
	return s
}

// keyLeak reports a leaked key through /v1/events, whose decision calls
// revoke_key, and checks that it is answered within the deadline, the
// dispatch budget and the margin, however the outbox is doing. written says
// whether the outbox is expected to keep the delivery, so that it must
// arrive.
func (s *postgresScenario) keyLeak(written bool) {
	s.t.Helper()
	s.leaks++
	start := time.Now()
	r := s.do("POST", "/v1/events", token, fmt.Sprintf(`{"type":"key_leak","api_key_id":"key_pg_%d"}`, s.leaks))
	took := time.Since(start)
	var out api.DecisionResponse
	r.json(s.t, &out)
	if r.status != http.StatusAccepted || !slices.Equal(out.Decision.Effects(), []string{"revoke_key"}) {
		s.t.Fatalf("key_leak: %d %s", r.status, r.body)
	}
	if budget := 2*postgresDeadline + latencyMargin; took > budget {
		s.t.Errorf("key_leak took %s; the deadline, the dispatch budget and the margin are %s", took, budget)
	}
	if written {
		s.revocations = append(s.revocations, out.Decision.ID+":revoke_key")
	}
}

// pending queues work in the audit database that waits on others: three
// key revocations whose receiver fails, and two leaked-key reports whose
// resolver is down.
func (s *postgresScenario) pending() {
	s.t.Helper()
	s.revoke.failing.Store(true)
	s.resolver.down.Store(true)
	for range 3 {
		s.keyLeak(true)
	}
	await(s.t, "each revocation was attempted", 30*time.Second, func() bool { return len(s.revoke.attemptTimes()) == 3 })
	if r := s.postLeaks(leakBatch); r.status != http.StatusAccepted {
		s.t.Fatalf("batch: %d %s", r.status, r.body)
	}
	await(s.t, "the reports were attempted", 30*time.Second, func() bool {
		return s.metric(`catraca_secret_scanning_outcomes_total{outcome="retry"}`) >= 2
	})
}

// fillAuditQueue keeps the load on until the audit queue overflows and
// drops decisions, and returns what the load got back.
func (s *postgresScenario) fillAuditQueue() loadStats {
	s.t.Helper()
	l := startLoad(s.t, s.harness, loadSend)
	await(s.t, "the audit queue overflowed and dropped decisions", 3*time.Minute, func() bool {
		return s.metric("catraca_audit_dropped_total") > 0
	})
	return l.stop()
}

// recovered checks that the work pending says the database is back: every
// revocation is delivered, the leaked-key reports are acted on, a batch is
// accepted again, and a new decision is written and read back.
func (s *postgresScenario) recovered() {
	s.t.Helper()
	s.awaitDependency("audit", "ok")
	// A delivery or report claimed as the database went down waits for its
	// lease, 40 and 60 seconds, before it is claimed again.
	await(s.t, "every revocation written was delivered", 3*time.Minute, func() bool { return s.revoke.accepted(s.revocations) })
	await(s.t, "the leaked-key reports were acted on", 3*time.Minute, func() bool {
		m := s.metrics()
		return strings.Contains(m, `catraca_secret_scanning_reports{status="pending"} 0`) &&
			strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="leaked"} 1`)
	})
	if r := s.postLeaks(leakBatch); r.status != http.StatusAccepted {
		s.t.Errorf("batch once the database is back: %d %s", r.status, r.body)
	}
	d, _ := s.decide(send("acct_pg_after", "a@shop.example"))
	await(s.t, "a new decision was written", 30*time.Second, func() bool {
		return s.do("GET", "/v1/decisions/"+d.ID, token, nil).status == http.StatusOK
	})
	await(s.t, "the audit queue drained", time.Minute, func() bool { return s.metric("catraca_audit_queued") == 0 })
}

// TestFaultPostgresDown stops Postgres mid-run, as a crash or a restart
// does: connections are reset and refused. Decisions go on unaffected; the
// decisions the audit log cannot write are counted as failed, and dropped
// once its queue is full; effects that cannot be written to the outbox are
// counted and logged; GitHub's batches are answered 503. Once Postgres is
// back, the deliveries and the leaked-key reports waiting in it resume.
func TestFaultPostgresDown(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	s := newPostgresScenario(t)
	s.pending()
	baseline := quietGoroutines(s.harness)

	s.proxy.SetRefuse(true)
	s.proxy.ResetConns()
	s.awaitDependency("audit", "unavailable")
	s.fillAuditQueue().check(t, "Postgres down", postgresDeadline)
	if n := s.metric("catraca_audit_failed_total"); !(n > 0) {
		t.Errorf("catraca_audit_failed_total = %v, want the writes that failed counted", n)
	}
	lost := s.metric("catraca_hooks_enqueue_errors_total")
	s.keyLeak(false)
	await(t, "the lost effect was counted", 15*time.Second, func() bool {
		return s.metric("catraca_hooks_enqueue_errors_total") > lost
	})
	if !strings.Contains(s.logs.String(), "effects lost") {
		t.Error("no log line names the effect that was lost")
	}
	if r := s.postLeaks(leakBatch); r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Errorf("batch with Postgres down: %d %s; want 503 with Retry-After", r.status, r.body)
	}

	s.revoke.failing.Store(false)
	s.resolver.down.Store(false)
	s.proxy.Heal()
	s.recovered()
	settled(t, s.harness, "after Postgres came back", baseline, 30*time.Second)
	s.checkNoPanics()
}

// TestFaultPostgresPartition cuts the network to Postgres mid-run: packets
// are dropped, so queries hang rather than fail, and the connections they
// were on are dead for good. Every call to the database is bounded, so
// decisions and their effects are answered within their budgets, and once
// the network is back the work waiting in the database resumes on new
// connections.
func TestFaultPostgresPartition(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	s := newPostgresScenario(t)
	s.pending()
	baseline := quietGoroutines(s.harness)

	s.proxy.SetBlackhole(true)
	s.awaitDependency("audit", "timeout")
	s.fillAuditQueue().check(t, "Postgres partitioned", postgresDeadline)
	deferred := s.metric("catraca_hooks_enqueue_deferred_total")
	s.keyLeak(false)
	await(t, "the effect whose write outlasted the dispatch budget was counted", 15*time.Second, func() bool {
		return s.metric("catraca_hooks_enqueue_deferred_total") > deferred
	})
	// The write goes on in the background until it gives up, at the
	// outbox's 5 second write timeout.
	await(t, "the lost effect was counted", 30*time.Second, func() bool {
		return s.metric("catraca_hooks_enqueue_errors_total") > 0
	})
	start := time.Now()
	if r := s.postLeaks(leakBatch); r.status != http.StatusServiceUnavailable {
		t.Errorf("batch with Postgres partitioned: %d %s; want 503", r.status, r.body)
	}
	t.Logf("a batch was answered in %s with Postgres partitioned", time.Since(start))

	s.revoke.failing.Store(false)
	s.resolver.down.Store(false)
	s.proxy.Heal()
	s.recovered()
	settled(t, s.harness, "after the partition", baseline, time.Minute)
	s.checkNoPanics()
}

// TestFaultPostgresSlow makes every Postgres reply 300ms late: slow enough
// that the audit writer, at four round trips a batch, falls behind the
// load, and quick enough that an outbox write fits in its 5 seconds.
// Decisions are unaffected; the audit queue fills and drops decisions; a
// decision with effects is answered within the dispatch budget while the
// outbox write goes on in the background, and the effect is delivered; and
// once Postgres is fast again the queue drains.
func TestFaultPostgresSlow(t *testing.T) {
	needFaults(t)
	leakCheck(t)
	s := newPostgresScenario(t)
	s.pending()
	baseline := quietGoroutines(s.harness)

	s.proxy.SetLatency(300*time.Millisecond, 30*time.Millisecond)
	await(t, "/readyz?verbose shows the audit database slow", 30*time.Second, func() bool {
		return s.readiness().Dependencies["audit"].DurationMS >= 250
	})
	s.fillAuditQueue().check(t, "Postgres slow", postgresDeadline)
	deferred := s.metric("catraca_hooks_enqueue_deferred_total")
	s.revoke.failing.Store(false)
	s.resolver.down.Store(false)
	for range 3 {
		s.keyLeak(true)
	}
	await(t, "the effects whose writes outlasted the dispatch budget were counted", 30*time.Second, func() bool {
		return s.metric("catraca_hooks_enqueue_deferred_total") > deferred
	})
	await(t, "the effects were delivered from the slow outbox", 3*time.Minute, func() bool {
		return s.revoke.accepted(s.revocations)
	})
	if n := s.metric("catraca_hooks_enqueue_errors_total"); n != 0 {
		t.Errorf("catraca_hooks_enqueue_errors_total = %v with Postgres slow, want every effect written", n)
	}

	s.proxy.Heal()
	s.recovered()
	settled(t, s.harness, "after Postgres was slow", baseline, 30*time.Second)
	s.checkNoPanics()
}
