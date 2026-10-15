package signal

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

const (
	day  = 24 * time.Hour
	week = 7 * day
	// newIPLookback is how long an IP stays known to an account or key
	// after its last send: new_ip is true for IPs not seen for this long.
	newIPLookback = 30 * day
	// DefaultRetention is the default for Options.Retention.
	DefaultRetention = 365 * day
)

// Options configures a catalog.
type Options struct {
	// Retention is how long the first-seen time of an account or key, and an
	// account's creation time, are kept after the last event that touched
	// them. An account or key idle for longer looks new again. Default
	// DefaultRetention.
	Retention time.Duration
}

// NewCatalog returns a Catalog that keeps its counters in s and computes the
// signals documented in docs/signals.md. Close closes s.
func NewCatalog(s store.Store, opts Options) Catalog {
	if opts.Retention <= 0 {
		opts.Retention = DefaultRetention
	}
	return &catalog{store: s, retention: opts.Retention}
}

type catalog struct {
	store     store.Store
	retention time.Duration
}

// Store keys, before the store's own prefix and layout. Entity ids come last
// and the names before them never contain ':', so no two entities share a key.
func accountKey(name, id string) string { return "account:" + name + ":" + id }
func apiKeyKey(name, id string) string  { return "key:" + name + ":" + id }
func ipKey(name, ip string) string      { return "ip:" + name + ":" + ip }
func domainKey(name, d string) string   { return "domain:" + name + ":" + d }

func (c *catalog) Observe(ctx context.Context, ev event.Event) (Set, error) {
	f := factsOf(ev)
	set := Set{Event: eventSignals(ev, f)}
	if ev.Time.IsZero() {
		return set, errors.New("signal: event has no time")
	}

	var b store.Batch
	acct := c.account(&b, ev, f)
	key := c.apiKey(&b, ev, f)
	ip := ipSignals(&b, ev, f)
	dom := domainSignals(&b, ev, f)
	// Marked last, so new_ip compares against the IPs seen before this event.
	if ev.Type == event.Send && f.ip != "" {
		if ev.AccountID != "" {
			b.MarkSeen(accountKey("seen_ips", ev.AccountID), f.ip, ev.Time, newIPLookback)
		}
		if ev.APIKeyID != "" {
			b.MarkSeen(apiKeyKey("seen_ips", ev.APIKeyID), f.ip, ev.Time, newIPLookback)
		}
	}

	if err := c.store.Do(ctx, &b); err != nil {
		return set, fmt.Errorf("signal: observe %s event: %w", ev.Type, err)
	}
	set.Account = acct.signals(ev.Time)
	set.Key = key.signals(ev.Time)
	set.IP = ip.signals()
	set.Domain = dom.signals()
	return set, nil
}

func (c *catalog) MarkLeaked(ctx context.Context, apiKeyID string) error {
	if apiKeyID == "" {
		return errors.New("signal: mark leaked: empty API key id")
	}
	var b store.Batch
	b.Set(apiKeyKey("leaked", apiKeyID), "1", 0)
	if err := c.store.Do(ctx, &b); err != nil {
		return fmt.Errorf("signal: mark key leaked: %w", err)
	}
	return nil
}

func (c *catalog) Close() error { return c.store.Close() }

type accountReads struct {
	sends1m, sends1h, sends24h, sends7d                      *store.IntResult
	recipients1h, recipients24h                              *store.IntResult
	recipientDomains1h, recipientDomains24h                  *store.IntResult
	ips24h, keys24h                                          *store.IntResult
	bounces24h, hardBounces24h, complaints24h, deliveries24h *store.IntResult
	firstSeen                                                *store.TimeResult
	createdAt                                                *store.StringResult
	seenIP                                                   *store.BoolResult // nil without an IP
}

// account queues the account's writes and reads, or returns nil when the
// event has no account.
func (c *catalog) account(b *store.Batch, ev event.Event, f facts) *accountReads {
	id := ev.AccountID
	if id == "" {
		return nil
	}
	at := ev.Time
	sends, rcpts, domains := accountKey("sends", id), accountKey("recipients", id), accountKey("recipient_domains", id)
	ips, keys := accountKey("ips", id), accountKey("keys", id)
	bounces, hard := accountKey("bounces", id), accountKey("hard_bounces", id)
	complaints, deliveries := accountKey("complaints", id), accountKey("deliveries", id)
	created := accountKey("created_at", id)

	switch ev.Type {
	case event.Send:
		for _, w := range []time.Duration{time.Minute, time.Hour, day, week} {
			b.Incr(sends, w, at, 1)
		}
		if n := int64(len(ev.To)); n > 0 {
			b.Incr(rcpts, time.Hour, at, n)
			b.Incr(rcpts, day, at, n)
		}
		for _, d := range f.toDomains {
			b.AddDistinct(domains, d, time.Hour, at)
			b.AddDistinct(domains, d, day, at)
		}
		if f.ip != "" {
			b.AddDistinct(ips, f.ip, day, at)
		}
		if ev.APIKeyID != "" {
			b.AddDistinct(keys, ev.APIKeyID, day, at)
		}
	case event.Feedback:
		if fb := ev.Feedback; fb != nil {
			switch fb.Kind {
			case event.Bounce:
				b.Incr(bounces, day, at, 1)
				if strings.EqualFold(fb.BounceType, "permanent") {
					b.Incr(hard, day, at, 1)
				}
			case event.Complaint:
				b.Incr(complaints, day, at, 1)
			case event.Delivery:
				b.Incr(deliveries, day, at, 1)
			}
		}
	}
	if ev.Account != nil && ev.Account.CreatedAt != nil {
		b.Set(created, strconv.FormatInt(ev.Account.CreatedAt.UnixMilli(), 10), c.retention)
	}

	r := &accountReads{
		sends1m:             b.Count(sends, time.Minute, at),
		sends1h:             b.Count(sends, time.Hour, at),
		sends24h:            b.Count(sends, day, at),
		sends7d:             b.Count(sends, week, at),
		recipients1h:        b.Count(rcpts, time.Hour, at),
		recipients24h:       b.Count(rcpts, day, at),
		recipientDomains1h:  b.Distinct(domains, time.Hour, at),
		recipientDomains24h: b.Distinct(domains, day, at),
		ips24h:              b.Distinct(ips, day, at),
		keys24h:             b.Distinct(keys, day, at),
		bounces24h:          b.Count(bounces, day, at),
		hardBounces24h:      b.Count(hard, day, at),
		complaints24h:       b.Count(complaints, day, at),
		deliveries24h:       b.Count(deliveries, day, at),
		firstSeen:           b.FirstSeen(accountKey("first_seen", id), at, c.retention),
		createdAt:           b.Get(created),
	}
	if f.ip != "" {
		r.seenIP = b.SeenWithin(accountKey("seen_ips", id), f.ip, newIPLookback, at)
	}
	return r
}

func (r *accountReads) signals(at time.Time) map[string]any {
	if r == nil {
		return nil
	}
	sends24h := r.sends24h.Val()
	baseline := float64(r.sends7d.Val()) / week.Hours()
	origin := r.firstSeen.Val()
	if ms, err := strconv.ParseInt(r.createdAt.Val(), 10, 64); r.createdAt.Found() && err == nil {
		origin = time.UnixMilli(ms)
	}
	m := map[string]any{
		"sends_1m":                       r.sends1m.Val(),
		"sends_1h":                       r.sends1h.Val(),
		"sends_24h":                      sends24h,
		"sends_7d":                       r.sends7d.Val(),
		"recipients_1h":                  r.recipients1h.Val(),
		"recipients_24h":                 r.recipients24h.Val(),
		"distinct_recipient_domains_1h":  r.recipientDomains1h.Val(),
		"distinct_recipient_domains_24h": r.recipientDomains24h.Val(),
		"distinct_ips_24h":               r.ips24h.Val(),
		"distinct_keys_24h":              r.keys24h.Val(),
		"bounces_24h":                    r.bounces24h.Val(),
		"hard_bounces_24h":               r.hardBounces24h.Val(),
		"complaints_24h":                 r.complaints24h.Val(),
		"deliveries_24h":                 r.deliveries24h.Val(),
		"bounce_rate_24h":                rate(r.bounces24h.Val(), sends24h),
		"hard_bounce_rate_24h":           rate(r.hardBounces24h.Val(), sends24h),
		"complaint_rate_24h":             rate(r.complaints24h.Val(), sends24h),
		"age_hours":                      ageHours(at, origin),
		"hourly_baseline_7d":             baseline,
		"volume_ratio_1h":                float64(r.sends1h.Val()) / max(baseline, 1),
	}
	if r.seenIP != nil {
		m["new_ip"] = !r.seenIP.Val()
	}
	return m
}

type apiKeyReads struct {
	sends1m, sends1h *store.IntResult
	ips1h, ips24h    *store.IntResult
	firstSeen        *store.TimeResult
	leaked           *store.StringResult
	seenIP           *store.BoolResult // nil without an IP
}

// apiKey queues the API key's writes and reads, or returns nil when the event
// has no key.
func (c *catalog) apiKey(b *store.Batch, ev event.Event, f facts) *apiKeyReads {
	id := ev.APIKeyID
	if id == "" {
		return nil
	}
	at := ev.Time
	sends, ips, leaked := apiKeyKey("sends", id), apiKeyKey("ips", id), apiKeyKey("leaked", id)

	switch ev.Type {
	case event.Send:
		b.Incr(sends, time.Minute, at, 1)
		b.Incr(sends, time.Hour, at, 1)
		if f.ip != "" {
			b.AddDistinct(ips, f.ip, time.Hour, at)
			b.AddDistinct(ips, f.ip, day, at)
		}
	case event.KeyLeak:
		// The report itself; MarkLeaked does the same for callers that learn
		// of a leak some other way.
		b.Set(leaked, "1", 0)
	}

	r := &apiKeyReads{
		sends1m:   b.Count(sends, time.Minute, at),
		sends1h:   b.Count(sends, time.Hour, at),
		ips1h:     b.Distinct(ips, time.Hour, at),
		ips24h:    b.Distinct(ips, day, at),
		firstSeen: b.FirstSeen(apiKeyKey("first_seen", id), at, c.retention),
		leaked:    b.Get(leaked),
	}
	if f.ip != "" {
		r.seenIP = b.SeenWithin(apiKeyKey("seen_ips", id), f.ip, newIPLookback, at)
	}
	return r
}

func (r *apiKeyReads) signals(at time.Time) map[string]any {
	if r == nil {
		return nil
	}
	m := map[string]any{
		"sends_1m":         r.sends1m.Val(),
		"sends_1h":         r.sends1h.Val(),
		"distinct_ips_1h":  r.ips1h.Val(),
		"distinct_ips_24h": r.ips24h.Val(),
		"age_hours":        ageHours(at, r.firstSeen.Val()),
		"leaked":           r.leaked.Found(),
	}
	if r.seenIP != nil {
		m["new_ip"] = !r.seenIP.Val()
	}
	return m
}

type ipReads struct {
	sends1m, sends1h *store.IntResult
	accounts24h      *store.IntResult
	keys24h          *store.IntResult
	signups24h       *store.IntResult
}

// ipSignals queues the IP's writes and reads, or returns nil when the event
// has no IP.
func ipSignals(b *store.Batch, ev event.Event, f facts) *ipReads {
	if f.ip == "" {
		return nil
	}
	at := ev.Time
	sends, accounts, keys, signups := ipKey("sends", f.ip), ipKey("accounts", f.ip), ipKey("keys", f.ip), ipKey("signups", f.ip)

	switch ev.Type {
	case event.Send:
		b.Incr(sends, time.Minute, at, 1)
		b.Incr(sends, time.Hour, at, 1)
		if ev.AccountID != "" {
			b.AddDistinct(accounts, ev.AccountID, day, at)
		}
		if ev.APIKeyID != "" {
			b.AddDistinct(keys, ev.APIKeyID, day, at)
		}
	case event.Account:
		if ev.Account != nil && ev.Account.Action == "signup" {
			b.Incr(signups, day, at, 1)
		}
	}

	return &ipReads{
		sends1m:     b.Count(sends, time.Minute, at),
		sends1h:     b.Count(sends, time.Hour, at),
		accounts24h: b.Distinct(accounts, day, at),
		keys24h:     b.Distinct(keys, day, at),
		signups24h:  b.Count(signups, day, at),
	}
}

func (r *ipReads) signals() map[string]any {
	if r == nil {
		return nil
	}
	return map[string]any{
		"sends_1m":              r.sends1m.Val(),
		"sends_1h":              r.sends1h.Val(),
		"distinct_accounts_24h": r.accounts24h.Val(),
		"distinct_keys_24h":     r.keys24h.Val(),
		"signups_24h":           r.signups24h.Val(),
	}
}

type domainReads struct {
	sends1h       *store.IntResult
	accounts24h   *store.IntResult
	complaints24h *store.IntResult
}

// domainSignals queues the sender domain's writes and reads, or returns nil
// when From has no domain.
func domainSignals(b *store.Batch, ev event.Event, f facts) *domainReads {
	d := f.fromDomain
	if d == "" {
		return nil
	}
	at := ev.Time
	sends, accounts, complaints := domainKey("sends", d), domainKey("accounts", d), domainKey("complaints", d)

	switch ev.Type {
	case event.Send:
		b.Incr(sends, time.Hour, at, 1)
		if ev.AccountID != "" {
			b.AddDistinct(accounts, ev.AccountID, day, at)
		}
	case event.Feedback:
		if ev.Feedback != nil && ev.Feedback.Kind == event.Complaint {
			b.Incr(complaints, day, at, 1)
		}
	}

	return &domainReads{
		sends1h:       b.Count(sends, time.Hour, at),
		accounts24h:   b.Distinct(accounts, day, at),
		complaints24h: b.Count(complaints, day, at),
	}
}

func (r *domainReads) signals() map[string]any {
	if r == nil {
		return nil
	}
	return map[string]any{
		"sends_1h":              r.sends1h.Val(),
		"distinct_accounts_24h": r.accounts24h.Val(),
		"complaints_24h":        r.complaints24h.Val(),
	}
}

// rate returns n / max(of, 1), capped at 1: feedback can outnumber the sends
// in the window when it is about older sends.
func rate(n, of int64) float64 {
	return min(float64(n)/float64(max(of, 1)), 1)
}

// ageHours returns the hours from origin to at, or zero when origin is later.
func ageHours(at, origin time.Time) float64 {
	return max(at.Sub(origin).Hours(), 0)
}
