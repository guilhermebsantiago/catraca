package signal_test

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/senderauth"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// unknownAuth is the domain map of a send whose From domain is not cached,
// or whose store failed, with no verified domains attribute.
var unknownAuth = map[string]any{
	"spf": "unknown", "spf_all": "unknown", "spf_provider": "unknown", "dkim": "unknown",
	"dmarc_policy": "unknown", "dmarc_pct": int64(-1), "dmarc_adkim": "unknown", "dmarc_aspf": "unknown",
	"verified": "unknown",
}

// authKeys are the names of the sender authentication signals.
var authKeys = slices.Sorted(maps.Keys(unknownAuth))

// authOf returns the sender authentication signals of a domain map.
func authOf(domain map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range authKeys {
		if v, ok := domain[k]; ok {
			out[k] = v
		}
	}
	return out
}

// recordingCache is an AuthCache that records what the catalog told it.
type recordingCache struct {
	mu     sync.Mutex
	hits   int
	misses []string
}

func (c *recordingCache) Hit() {
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
}

func (c *recordingCache) Miss(domain string) {
	c.mu.Lock()
	c.misses = append(c.misses, domain)
	c.mu.Unlock()
}

var protected = senderauth.Result{
	CheckedAt: t0, SPF: senderauth.Found, SPFAll: senderauth.AllFail, SPFProvider: senderauth.No, DKIM: senderauth.Missing,
	DMARCPolicy: senderauth.PolicyReject, DMARCPct: 100, DMARCADKIM: senderauth.Strict, DMARCASPF: senderauth.Relaxed,
}

func sendFrom(from string, attrs map[string]string) event.Event {
	return event.Event{Type: event.Send, Time: t0, AccountID: "acct-1", From: from, To: []string{"a@inbox.example"}, Attributes: attrs}
}

func TestSenderAuthSignals(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			if b.skip != nil {
				if why := b.skip(); why != "" {
					t.Skip(why)
				}
			}
			s := b.new(t)
			ctx := context.Background()
			cache := &recordingCache{}
			c := signal.NewCatalog(s, signal.Options{SenderAuth: signal.SenderAuth{Cache: cache}})

			// Not cached: unknown, and queued under the normalized domain.
			set, err := c.Observe(ctx, sendFrom("Alice <alice@Bank.Example>", nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := authOf(set.Domain); !reflect.DeepEqual(got, unknownAuth) {
				t.Errorf("before caching: %v, want %v", got, unknownAuth)
			}
			if set.Domain["sends_1h"] != int64(1) {
				t.Errorf("the counters are gone: %v", set.Domain)
			}
			if !slices.Equal(cache.misses, []string{"bank.example"}) || cache.hits != 0 {
				t.Errorf("misses %v, hits %d; want one miss for bank.example", cache.misses, cache.hits)
			}

			// Cached: read in the same round trip, a hit.
			if err := senderauth.Put(ctx, s, "bank.example", protected, time.Hour); err != nil {
				t.Fatal(err)
			}
			set, err = c.Observe(ctx, sendFrom("alice@bank.example", nil))
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"spf": "found", "spf_all": "fail", "spf_provider": "no", "dkim": "missing",
				"dmarc_policy": "reject", "dmarc_pct": int64(100), "dmarc_adkim": "strict", "dmarc_aspf": "relaxed",
				"verified": "unknown",
			}
			if got := authOf(set.Domain); !reflect.DeepEqual(got, want) {
				t.Errorf("cached: %v, want %v", got, want)
			}
			if cache.hits != 1 || len(cache.misses) != 1 {
				t.Errorf("hits %d, misses %v; want one hit and no new miss", cache.hits, cache.misses)
			}

			// Explaining reads the cache but queues nothing and counts
			// nothing.
			set, _ = c.Observe(signal.WithoutLookups(ctx), sendFrom("alice@bank.example", nil))
			if authOf(set.Domain)["dmarc_policy"] != "reject" {
				t.Errorf("without lookups, the cache was not read: %v", set.Domain)
			}
			set, _ = c.Observe(signal.WithoutLookups(ctx), sendFrom("bob@other.example", nil))
			if got := authOf(set.Domain); !reflect.DeepEqual(got, unknownAuth) {
				t.Errorf("without lookups, not cached: %v", got)
			}
			if cache.hits != 1 || len(cache.misses) != 1 {
				t.Errorf("without lookups: hits %d, misses %v; want them unchanged", cache.hits, cache.misses)
			}

			// A value the catalog cannot read is a miss.
			var batch store.Batch
			batch.Set(senderauth.CacheKey("broken.example"), "{not json", time.Hour)
			if err := s.Do(ctx, &batch); err != nil {
				t.Fatal(err)
			}
			set, _ = c.Observe(ctx, sendFrom("x@broken.example", nil))
			if got := authOf(set.Domain); !reflect.DeepEqual(got, unknownAuth) || cache.misses[len(cache.misses)-1] != "broken.example" {
				t.Errorf("unreadable value: %v, misses %v", got, cache.misses)
			}

			// Feedback reads nothing: unknown, no miss.
			n := len(cache.misses)
			fb := event.Event{Type: event.Feedback, Time: t0, AccountID: "acct-1", From: "alice@bank.example",
				Feedback: &event.FeedbackInfo{Kind: event.Complaint}}
			set, _ = c.Observe(ctx, fb)
			if authOf(set.Domain)["dmarc_policy"] != "unknown" || len(cache.misses) != n {
				t.Errorf("feedback: %v, misses %v", set.Domain, cache.misses)
			}

			// A From that is no domain reads nothing.
			set, _ = c.Observe(ctx, sendFrom("root@localhost", nil))
			if authOf(set.Domain)["spf"] != "unknown" || len(cache.misses) != n {
				t.Errorf("localhost: %v, misses %v", set.Domain, cache.misses)
			}
		})
	}
}

// TestSenderAuthWithoutCache checks the catalog of a server with
// sender_auth off, and of replays: every state unknown, nothing read.
func TestSenderAuthWithoutCache(t *testing.T) {
	s := store.NewMemory()
	if err := senderauth.Put(context.Background(), s, "bank.example", protected, time.Hour); err != nil {
		t.Fatal(err)
	}
	c := signal.NewCatalog(s, signal.Options{})
	set, err := c.Observe(context.Background(), sendFrom("alice@bank.example", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := authOf(set.Domain); !reflect.DeepEqual(got, unknownAuth) {
		t.Errorf("auth signals = %v, want %v", got, unknownAuth)
	}
	if set, _ := c.Observe(context.Background(), sendFrom("", nil)); set.Domain != nil {
		t.Errorf("a send without From has domain signals %v", set.Domain)
	}
}

func TestVerified(t *testing.T) {
	tests := []struct {
		from, list string
		attr       string // the attribute name the catalog reads; "" is the default
		absent     bool
		want       string
	}{
		{from: "alice@example.com", absent: true, want: "unknown"},
		{from: "alice@example.com", list: "example.com", want: "exact"},
		{from: "alice@Example.COM", list: "other.example, EXAMPLE.com.", want: "exact"},
		{from: "alice@mail.example.com", list: "example.com", want: "relaxed"},
		{from: "alice@example.com", list: "mail.example.com", want: "relaxed"},
		{from: "alice@news.example.com", list: "mail.example.com", want: "relaxed"},
		{from: "alice@news.example.com", list: "mail.example.com example.com news.example.com", want: "exact"},
		{from: "alice@mail.example.co.uk", list: "example.co.uk", want: "relaxed"},
		{from: "alice@example.co.uk", list: "other.co.uk,co.uk", want: "no"},
		{from: "alice@victim.github.io", list: "attacker.github.io", want: "no"},
		{from: "ceo@paypal.com", list: "acme.example", want: "no"},
		{from: "ceo@paypal.com", list: "", want: "no"},
		{from: "ceo@paypal.com", list: " , ,", want: "no"},
		{from: "ceo@paypal.com", list: "not a domain, paypal.com.evil.example", want: "no"},
		{from: "ceo@bücher.example", list: "xn--bcher-kva.example", want: "exact"},
		{from: "root@localhost", list: "localhost", want: "unknown"},
		{from: "alice@example.com", list: "example.com", attr: "domains", want: "unknown"},
		{from: "alice@example.com", list: "example.com", attr: "verified", want: "exact"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s in %q", tt.from, tt.list), func(t *testing.T) {
			name := tt.attr
			if name == "" {
				name = signal.DefaultVerifiedDomainsAttribute
			}
			var attrs map[string]string
			if !tt.absent {
				attrs = map[string]string{"verified": tt.list}
				if tt.attr == "" {
					attrs = map[string]string{"verified_domains": tt.list}
				}
			}
			c := signal.NewCatalog(store.NewMemory(), signal.Options{SenderAuth: signal.SenderAuth{VerifiedDomainsAttribute: name}})
			set, err := c.Observe(context.Background(), sendFrom(tt.from, attrs))
			if err != nil {
				t.Fatal(err)
			}
			if got := set.Domain["verified"]; got != tt.want {
				t.Errorf("verified = %v, want %s", got, tt.want)
			}
		})
	}
}

// blockingResolver blocks every lookup until release is closed, so a
// decision that waited for DNS would never return.
type blockingResolver struct {
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (r *blockingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	switch name {
	case "bank.example":
		return []string{"v=spf1 -all"}, nil
	case "_dmarc.bank.example":
		return []string{"v=DMARC1; p=reject"}, nil
	}
	return nil, fmt.Errorf("%w: %s", senderauth.ErrNotFound, name)
}

// notifyingStore tells done of every batch it ran.
type notifyingStore struct {
	store.Store
	done chan error
}

func (n notifyingStore) Do(ctx context.Context, b *store.Batch) error {
	err := n.Store.Do(ctx, b)
	n.done <- err
	return err
}

// TestDecideNeverWaitsForDNS runs the production path: a decision for a
// domain nobody cached returns while every DNS lookup is blocked, with the
// states unknown and a rule that fails closed unmatched; once the
// background lookup lands, decisions and explanations see it.
func TestDecideNeverWaitsForDNS(t *testing.T) {
	s := store.NewMemory()
	dns := &blockingResolver{release: make(chan struct{})}
	written := notifyingStore{Store: s, done: make(chan error, 10)}
	r, err := senderauth.NewRefresher(senderauth.Options{
		Store: written, Checker: &senderauth.Checker{Resolver: dns, Selectors: []string{"s1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Start()
	t.Cleanup(func() { _ = r.Close(context.Background()) })
	cat := signal.NewCatalog(s, signal.Options{SenderAuth: signal.SenderAuth{Cache: r}})
	eng, err := engine.New(engine.Options{Catalog: cat, Rules: rules.NewHolder(decideRules(t)), Deadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(context.Background()) })
	ctx := context.Background()
	ev := sendFrom("ceo@bank.example", map[string]string{"verified_domains": "acme.example"})
	ev.Time = time.Now()

	// DNS is blocked: had the decision waited for it, it would never
	// return.
	d, err := eng.Decide(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != decision.Allow || len(d.Matches) != 0 || len(d.Errors) != 0 {
		t.Errorf("not cached: decision %+v, want allow with no match and no error", d)
	}
	x, err := eng.Explain(ctx, ev, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := x.Signals.Domain["dmarc_policy"]; got != "unknown" {
		t.Errorf("explained before the lookup: dmarc_policy = %v", got)
	}

	close(dns.release)
	if err := <-written.done; err != nil {
		t.Fatal(err)
	}
	ev.Time = time.Now()
	d, err = eng.Decide(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != decision.Hold || len(d.Matches) != 1 || d.Matches[0].RuleID != "spoofed-protected-domain" {
		t.Errorf("cached: decision %+v, want a hold by spoofed-protected-domain", d)
	}
	x, err = eng.Explain(ctx, ev, false)
	if err != nil {
		t.Fatal(err)
	}
	// Without observe the store is not read: unknown, and nothing queued.
	if got := x.Signals.Domain["dmarc_policy"]; got != "unknown" {
		t.Errorf("explained without observing: dmarc_policy = %v", got)
	}
	x, err = eng.Explain(ctx, ev, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := authOf(x.Signals.Domain), (map[string]any{
		"spf": "found", "spf_all": "fail", "spf_provider": "unknown", "dkim": "missing",
		"dmarc_policy": "reject", "dmarc_pct": int64(100), "dmarc_adkim": "relaxed", "dmarc_aspf": "relaxed",
		"verified": "no",
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("explained after the lookup: %v, want %v", got, want)
	}
	if !x.Rules[0].Matched {
		t.Errorf("explanation: %+v, want the rule matched", x.Rules)
	}
	select {
	case err := <-written.done:
		t.Errorf("a second lookup was written (%v): decisions after the first should hit the cache", err)
	default:
	}
}

func decideRules(t *testing.T) *rules.Ruleset {
	t.Helper()
	rs, err := rules.Parse([]byte(`version: 1
rules:
  - id: spoofed-protected-domain
    when: event.type == "send" && domain.dmarc_policy in ["reject", "quarantine"] && domain.verified == "no"
    action: hold
    mode: enforce
    on_error: closed
    reason: spoofing
`))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
