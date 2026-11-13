package senderauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/guilhermebsantiago/catraca/internal/store"
)

// fakeClock is a clock tests move by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// write is one result a Refresher wrote.
type write struct {
	domain string
	res    Result
	ttl    time.Duration
}

// testRefresher returns a Refresher over dns and a memory store whose
// writes are also sent to the returned channel. It is closed at the end
// of the test.
func testRefresher(t *testing.T, dns *fakeDNS, opts Options) (*Refresher, *fakeClock, chan write) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)}
	if opts.Store == nil {
		opts.Store = store.NewMemory()
	}
	if opts.Checker == nil {
		opts.Checker = &Checker{Resolver: dns, Providers: []string{"amazonses.com"}, Selectors: []string{"s1"}}
	}
	opts.Now = clock.now
	r, err := NewRefresher(opts)
	if err != nil {
		t.Fatal(err)
	}
	writes := make(chan write, 100)
	put := r.put
	r.put = func(ctx context.Context, domain string, res Result, ttl time.Duration) error {
		err := put(ctx, domain, res, ttl)
		writes <- write{domain, res, ttl}
		return err
	}
	t.Cleanup(func() {
		if err := r.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return r, clock, writes
}

func next(t *testing.T, writes chan write) write {
	t.Helper()
	select {
	case w := <-writes:
		return w
	case <-time.After(10 * time.Second):
		t.Fatal("no result was written")
	}
	return write{}
}

func counter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func authZone() *fakeDNS {
	return newFakeDNS(map[string][]string{
		"example.com":               {"v=spf1 include:amazonses.com -all"},
		"amazonses.com":             {"v=spf1 ip4:199.255.192.0/22 -all"},
		"s1._domainkey.example.com": {"v=DKIM1; p=" + testKeys()["rsa2048"]},
		"_dmarc.example.com":        {"v=DMARC1; p=reject"},
	})
}

func TestRefresherCachesResults(t *testing.T) {
	s := store.NewMemory()
	r, clock, writes := testRefresher(t, authZone(), Options{Store: s, TTL: 2 * time.Hour, NegativeTTL: 10 * time.Minute})
	r.Start()
	if _, ok, _ := Get(context.Background(), s, "example.com"); ok {
		t.Fatal("cached before any lookup")
	}
	r.Miss("Example.COM.")
	w := next(t, writes)
	want := Result{CheckedAt: clock.now(), SPF: Found, SPFAll: AllFail, SPFProvider: Yes, DKIM: Found,
		DMARCPolicy: PolicyReject, DMARCPct: 100, DMARCADKIM: Relaxed, DMARCASPF: Relaxed}
	if w.domain != "example.com" || w.res != want || w.ttl != 2*time.Hour {
		t.Errorf("wrote %+v, want example.com, %+v for 2h", w, want)
	}
	got, ok, err := Get(context.Background(), s, "example.com")
	if err != nil || !ok || got != want {
		t.Errorf("Get = %+v, %v, %v; want %+v", got, ok, err, want)
	}
	if counter(t, r.m.miss) != 1 || counter(t, r.m.lookups.WithLabelValues("dmarc", PolicyReject)) != 1 {
		t.Error("the miss or the lookup was not counted")
	}
}

// TestRefresherNegativeTTL checks that a result with a missing record or a
// failed lookup is kept for the negative TTL, and one whose records are
// all there, valid or not, for the TTL.
func TestRefresherNegativeTTL(t *testing.T) {
	tests := []struct {
		name      string
		zone      map[string][]string
		errs      map[string]error
		selectors []string
		want      time.Duration
	}{
		{"no records", nil, nil, []string{"s1"}, time.Minute},
		{"DMARC missing", map[string][]string{"example.com": {"v=spf1 -all"}, "s1._domainkey.example.com": {"v=DKIM1; p="}}, nil, []string{"s1"}, time.Minute},
		{"a failure", map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {"v=DMARC1; p=none"}},
			map[string]error{"s1._domainkey.example.com": errServFail}, []string{"s1"}, time.Minute},
		{"invalid and revoked are answers", map[string][]string{"example.com": {"v=spf1 bogus"}, "_dmarc.example.com": {"v=DMARC1; p=none"}, "s1._domainkey.example.com": {"v=DKIM1; p="}},
			nil, []string{"s1"}, time.Hour},
		{"DKIM not checked", map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {"v=DMARC1; p=none"}}, nil, nil, time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := newFakeDNS(tt.zone)
			for name, err := range tt.errs {
				dns.errs[name] = err
			}
			r, _, writes := testRefresher(t, dns, Options{TTL: time.Hour, NegativeTTL: time.Minute,
				Checker: &Checker{Resolver: dns, Selectors: tt.selectors}})
			r.Start()
			r.Miss("example.com")
			if w := next(t, writes); w.ttl != tt.want {
				t.Errorf("ttl = %s, want %s (%+v)", w.ttl, tt.want, w.res)
			}
		})
	}
}

// TestRefresherNegativeTTLIsAtMostTTL checks the clamp: a negative TTL
// longer than the TTL would keep a missing record longer than a found one.
func TestRefresherNegativeTTLIsAtMostTTL(t *testing.T) {
	r, _, writes := testRefresher(t, newFakeDNS(nil), Options{TTL: time.Minute, NegativeTTL: time.Hour})
	r.Start()
	r.Miss("example.com")
	if w := next(t, writes); w.ttl != time.Minute {
		t.Errorf("ttl = %s, want the TTL, 1m", w.ttl)
	}
}

// TestRefresherSingleflight checks that a burst of sends from a domain
// nobody cached yet costs one check.
func TestRefresherSingleflight(t *testing.T) {
	dns := authZone()
	dns.block = make(chan struct{})
	dns.started = make(chan string, 100)
	r, _, writes := testRefresher(t, dns, Options{Workers: 8})
	r.Start()
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Go(func() {
			if i%2 == 0 {
				r.Miss("example.com")
			} else {
				r.Miss("EXAMPLE.com")
			}
		})
	}
	wg.Wait()
	<-dns.started // the check is under way, and blocked
	close(dns.block)
	next(t, writes)
	if n := dns.callsTo("_dmarc.example.com"); n != 1 {
		t.Errorf("_dmarc.example.com looked up %d times, want once", n)
	}
	if got := counter(t, r.m.miss); got != 100 {
		t.Errorf("misses = %v, want 100", got)
	}
	select {
	case w := <-writes:
		t.Errorf("a second result was written: %+v", w)
	default:
	}
}

// TestRefresherRateLimit checks that a domain is looked up at most once per
// negative TTL, even when its result does not reach the cache.
func TestRefresherRateLimit(t *testing.T) {
	dns := authZone()
	r, clock, writes := testRefresher(t, dns, Options{NegativeTTL: 5 * time.Minute})
	r.put = func(context.Context, string, Result, time.Duration) error {
		writes <- write{}
		return errors.New("store full")
	}
	idle := make(chan string, 10)
	r.done = func(domain string) { idle <- domain }
	r.Start()
	if !r.Enqueue("example.com") {
		t.Fatal("not queued")
	}
	next(t, writes)
	<-idle
	if counter(t, r.m.writeErrors) != 1 {
		t.Error("the write error was not counted")
	}
	clock.add(5*time.Minute - time.Millisecond)
	if r.Enqueue("example.com") {
		t.Error("queued again within the negative TTL")
	}
	clock.add(time.Millisecond)
	if !r.Enqueue("example.com") {
		t.Error("not queued again after the negative TTL")
	}
	next(t, writes)
}

// TestRefresherQueueFull checks that a full queue drops domains without
// blocking, counts them, and lets them in again once there is room.
func TestRefresherQueueFull(t *testing.T) {
	r, _, _ := testRefresher(t, authZone(), Options{QueueSize: 2})
	// No workers: the queue only fills.
	if !r.Enqueue("a.example") || !r.Enqueue("b.example") {
		t.Fatal("not queued")
	}
	if r.Enqueue("c.example") {
		t.Error("queued past the queue size")
	}
	if got := counter(t, r.m.dropped); got != 1 {
		t.Errorf("dropped = %v, want 1", got)
	}
	<-r.queue
	if !r.Enqueue("c.example") {
		t.Error("a dropped domain was not queued once there was room")
	}
}

// TestRefresherTimeout checks that a check that runs out of time is cached
// as unknown, briefly, rather than as missing.
func TestRefresherTimeout(t *testing.T) {
	dns := authZone()
	dns.block = make(chan struct{}) // never closed
	r, _, writes := testRefresher(t, dns, Options{Timeout: time.Millisecond, TTL: time.Hour, NegativeTTL: time.Minute})
	r.Start()
	r.Miss("example.com")
	w := next(t, writes)
	if want := UnknownResult(); w.res.SPF != want.SPF || w.res.DKIM != Unknown || w.res.DMARCPolicy != Unknown || w.ttl != time.Minute {
		t.Errorf("wrote %+v for %s, want every state unknown for 1m", w.res, w.ttl)
	}
}

// TestRefresherClose checks that closing cancels the lookups in flight
// without writing what they found, and that nothing is queued after.
func TestRefresherClose(t *testing.T) {
	dns := authZone()
	dns.block = make(chan struct{})
	dns.started = make(chan string, 100)
	r, _, writes := testRefresher(t, dns, Options{})
	r.Start()
	r.Miss("example.com")
	<-dns.started
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-writes:
		t.Errorf("wrote %+v after Close", w)
	default:
	}
	if r.Enqueue("other.example") {
		t.Error("queued after Close")
	}
	r.Start() // no workers start after Close
}

func TestRefresherIgnoresInvalidDomains(t *testing.T) {
	r, _, _ := testRefresher(t, authZone(), Options{})
	for _, d := range []string{"", "localhost", "exa mple.com", "[192.0.2.1]"} {
		if r.Enqueue(d) {
			t.Errorf("queued %q", d)
		}
	}
}

func TestNewRefresherOptions(t *testing.T) {
	dns := newFakeDNS(nil)
	for _, opts := range []Options{
		{},
		{Store: store.NewMemory()},
		{Store: store.NewMemory(), Checker: &Checker{}},
		{Store: store.NewMemory(), Checker: &Checker{Resolver: dns}, Workers: -1},
		{Store: store.NewMemory(), Checker: &Checker{Resolver: dns}, TTL: -time.Second},
	} {
		if _, err := NewRefresher(opts); err == nil {
			t.Errorf("NewRefresher(%+v) succeeded", opts)
		}
	}
	reg := prometheus.NewRegistry()
	opts := Options{Store: store.NewMemory(), Checker: &Checker{Resolver: dns}, Registerer: reg}
	if _, err := NewRefresher(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRefresher(opts); err == nil {
		t.Error("registered the same metrics twice")
	}
}
