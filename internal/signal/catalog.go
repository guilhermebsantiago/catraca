package signal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
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
	// DefaultDedupeTTL is the default for Options.DedupeTTL. It outlasts the
	// retries of a platform whose request timed out, and those of the
	// feedback providers Catraca takes: Amazon SNS's default delivery policy
	// and useSend's webhooks both give up within about five minutes. Each
	// event with an id costs an entry for this long, so a longer one costs
	// memory in proportion.
	DefaultDedupeTTL = 10 * time.Minute
)

// Options configures a catalog.
type Options struct {
	// Retention is how long the first-seen time of an account or key, and an
	// account's creation time, are kept after the last event that touched
	// them. An account or key idle for longer looks new again. Default
	// DefaultRetention.
	Retention time.Duration
	// DedupeTTL is how long an event with an id is remembered after it
	// counts, so that the same event observed again meanwhile, such as a
	// retry after a timeout, does not count twice; see Catalog.Observe.
	// Zero means DefaultDedupeTTL. A negative value turns it off: every
	// observation counts.
	DedupeTTL time.Duration
	// RecipientMemory is how long an address that hard-bounced or
	// complained is remembered, for every account: a send to it within
	// this long counts in event.suppressed_recipients. Zero means
	// DefaultRecipientMemory. A negative value turns the memory off, and
	// the suppressed signals with it.
	RecipientMemory time.Duration
	// RecipientHashKey keys the HMAC the recipient memory stores instead of
	// addresses. Without one the digest is a plain hash, which anyone who
	// reads the store can test known addresses against. Changing it
	// forgets every address remembered.
	RecipientHashKey []byte
	// Entities are the attributes counted as entities; see Entity. At most
	// MaxEntities; an invalid or repeated one makes NewCatalog panic, as
	// configuration validates them first.
	Entities []Entity
}

// NewCatalog returns a Catalog that keeps its counters in s and computes the
// signals documented in docs/signals.md. Close closes s.
func NewCatalog(s store.Store, opts Options) Catalog {
	if opts.Retention <= 0 {
		opts.Retention = DefaultRetention
	}
	if opts.DedupeTTL == 0 {
		opts.DedupeTTL = DefaultDedupeTTL
	}
	if opts.RecipientMemory == 0 {
		opts.RecipientMemory = DefaultRecipientMemory
	}
	if len(opts.Entities) > MaxEntities {
		panic(fmt.Sprintf("signal: %d entities, at most %d", len(opts.Entities), MaxEntities))
	}
	seen := map[string]bool{}
	for _, e := range opts.Entities {
		if err := e.Validate(); err != nil {
			panic("signal: " + err.Error())
		}
		if seen[e.Name] {
			panic("signal: entity " + e.Name + " is declared twice")
		}
		seen[e.Name] = true
	}
	return &catalog{
		store: s, retention: opts.Retention, dedupeTTL: opts.DedupeTTL, leaked: newLeakedKeys(maxLeakedKeys),
		recipientMemoryTTL: opts.RecipientMemory, recipientHashKey: slices.Clone(opts.RecipientHashKey),
		entityDefs: slices.Clone(opts.Entities),
	}
}

type catalog struct {
	store     store.Store
	retention time.Duration
	// dedupeTTL is Options.DedupeTTL; deduplication is off when it is
	// negative.
	dedupeTTL time.Duration
	// leaked answers key.leaked when the store cannot. Without it a store
	// outage leaves the signal absent for every key, and a rule that fails
	// closed on it blocks every send with a key, while one that fails open
	// lets known leaked keys send.
	leaked *leakedKeys
	// recipientMemoryTTL is Options.RecipientMemory; the memory is off when
	// it is negative.
	recipientMemoryTTL time.Duration
	recipientHashKey   []byte
	entityDefs         []Entity
}

// Store keys, before the store's own prefix and layout. Entity ids come last
// and the names before them never contain ':', so no two entities share a key.
func accountKey(name, id string) string { return "account:" + name + ":" + id }
func apiKeyKey(name, id string) string  { return "key:" + name + ":" + id }
func ipKey(name, ip string) string      { return "ip:" + name + ":" + ip }
func domainKey(name, d string) string   { return "domain:" + name + ":" + d }

// accountIPKey is the key of what an account did from one IP. Account ids and
// IPs as sent may both contain ':', so the account id is length-prefixed.
func accountIPKey(name, id, ip string) string {
	return accountKey(name, strconv.Itoa(len(id))+":"+id+":"+ip)
}

// dedupeID names ev among the events the store counted: a digest of its
// type, account and id, so that one id sent by two accounts, or for a send
// and then for feedback about it, names two events. The store keeps an entry
// per event under this name, and the digest keeps it short whatever the
// length of the ids, up to 256 bytes each. With 128 bits a collision, which
// would leave one event uncounted, becomes likely only with some 2^64 ids
// remembered at once.
func dedupeID(ev event.Event) string {
	var buf [2*event.MaxIDBytes + 32]byte
	b := append(buf[:0], ev.Type...)
	b = append(b, ':')
	b = strconv.AppendInt(b, int64(len(ev.AccountID)), 10)
	b = append(b, ':')
	b = append(b, ev.AccountID...)
	b = append(b, ev.ID...)
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (c *catalog) Observe(ctx context.Context, ev event.Event) (Set, error) {
	f := factsOf(ev)
	set := Set{Event: eventSignals(ev, f)}
	if ev.Type == event.KeyLeak && ev.APIKeyID != "" {
		// The event is the report itself; remember it before the store
		// write, which may fail.
		c.leaked.add(ev.APIKeyID)
	}
	if ev.Time.IsZero() {
		set.Key = c.knownLeaked(ev.APIKeyID)
		return set, errors.New("signal: event has no time")
	}

	var b store.Batch
	acct := c.account(&b, ev, f)
	key := c.apiKey(&b, ev, f)
	ip := ipSignals(&b, ev, f)
	dom := domainSignals(&b, ev, f)
	suppressed := c.recipientMemory(&b, ev)
	ents := c.entities(&b, ev)
	// Marked last, so new_ip compares against the IPs seen before this event.
	if ev.Type == event.Send && f.ip != "" {
		if ev.AccountID != "" {
			b.MarkSeen(accountKey("seen_ips", ev.AccountID), f.ip, ev.Time, newIPLookback)
		}
		if ev.APIKeyID != "" {
			b.MarkSeen(apiKeyKey("seen_ips", ev.APIKeyID), f.ip, ev.Time, newIPLookback)
		}
	}
	var repeated *store.BoolResult
	if ev.ID != "" && c.dedupeTTL > 0 {
		repeated = b.Dedupe(dedupeID(ev), ev.Time, c.dedupeTTL)
	}

	if err := c.store.Do(ctx, &b); err != nil {
		set.Key = c.knownLeaked(ev.APIKeyID)
		return set, fmt.Errorf("signal: observe %s event: %w", ev.Type, err)
	}
	set.Duplicate = repeated != nil && repeated.Val()
	set.Account = acct.signals(ev.Time)
	set.Key = key.signals(ev.Time)
	set.IP = ip.signals()
	set.Domain = dom.signals()
	set.Entity = entitySignals(ents)
	suppressed.addTo(set.Event)
	if key != nil && key.leaked.Found() {
		// Keys reported to other replicas, or before a restart, are
		// learned here when they are next used.
		c.leaked.add(ev.APIKeyID)
	}
	return set, nil
}

// knownLeaked returns the key signals for an event the store could not
// answer for: leaked alone, for a key this catalog knows leaked, and nil for
// any other key, so rules that read key signals follow on_error.
func (c *catalog) knownLeaked(apiKeyID string) map[string]any {
	if apiKeyID == "" || !c.leaked.has(apiKeyID) {
		return nil
	}
	return map[string]any{"leaked": true}
}

func (c *catalog) MarkLeaked(ctx context.Context, apiKeyID string) error {
	if apiKeyID == "" {
		return errors.New("signal: mark leaked: empty API key id")
	}
	// Remembered even when the write below fails, so key.leaked holds for
	// the key in this process through the outage. The error tells the
	// caller to retry; if it does not, Observe writes the key again the next
	// time it is used here.
	c.leaked.add(apiKeyID)
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
	recipients1h, recipients24h, recipients7d                *store.IntResult
	recipientDomains1h, recipientDomains24h                  *store.IntResult
	ips24h, keys24h                                          *store.IntResult
	bounces24h, hardBounces24h, complaints24h, deliveries24h *store.IntResult
	bounces7d, hardBounces7d, complaints7d                   *store.IntResult
	trapHits7d, blocklistHits7d                              *store.IntResult
	firstSeen                                                *store.TimeResult
	createdAt                                                *store.StringResult
	state                                                    *store.StringResult
	seenIP                                                   *store.BoolResult // nil without an IP
	ipSends24h, ipSends7d                                    *store.IntResult  // nil without an IP
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
	traps, blocklists := accountKey("trap_hits", id), accountKey("blocklist_hits", id)
	created := accountKey("created_at", id)
	ipSends := accountIPKey("ip_sends", id, f.ip)

	switch ev.Type {
	case event.Send:
		for _, w := range []time.Duration{time.Minute, time.Hour, day, week} {
			b.Incr(sends, w, at, 1)
		}
		if f.ip != "" {
			b.Incr(ipSends, day, at, 1)
			b.Incr(ipSends, week, at, 1)
		}
		if n := int64(len(ev.To)); n > 0 {
			b.Incr(rcpts, time.Hour, at, n)
			b.Incr(rcpts, day, at, n)
			b.Incr(rcpts, week, at, n)
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
				b.Incr(bounces, week, at, 1)
				if strings.EqualFold(fb.BounceType, "permanent") {
					b.Incr(hard, day, at, 1)
					b.Incr(hard, week, at, 1)
				}
			case event.Complaint:
				b.Incr(complaints, day, at, 1)
				b.Incr(complaints, week, at, 1)
			case event.Delivery:
				b.Incr(deliveries, day, at, 1)
			case event.Trap:
				b.Incr(traps, week, at, 1)
			case event.Blocklist:
				b.Incr(blocklists, week, at, 1)
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
		recipients7d:        b.Count(rcpts, week, at),
		recipientDomains1h:  b.Distinct(domains, time.Hour, at),
		recipientDomains24h: b.Distinct(domains, day, at),
		ips24h:              b.Distinct(ips, day, at),
		keys24h:             b.Distinct(keys, day, at),
		bounces24h:          b.Count(bounces, day, at),
		hardBounces24h:      b.Count(hard, day, at),
		complaints24h:       b.Count(complaints, day, at),
		deliveries24h:       b.Count(deliveries, day, at),
		bounces7d:           b.Count(bounces, week, at),
		hardBounces7d:       b.Count(hard, week, at),
		complaints7d:        b.Count(complaints, week, at),
		trapHits7d:          b.Count(traps, week, at),
		blocklistHits7d:     b.Count(blocklists, week, at),
		firstSeen:           b.FirstSeen(accountKey("first_seen", id), at, c.retention),
		createdAt:           b.Get(created),
		state:               b.Get(accountKey("state", id)),
	}
	if f.ip != "" {
		r.seenIP = b.SeenWithin(accountKey("seen_ips", id), f.ip, newIPLookback, at)
		r.ipSends24h = b.Count(ipSends, day, at)
		r.ipSends7d = b.Count(ipSends, week, at)
	}
	return r
}

func (r *accountReads) signals(at time.Time) map[string]any {
	if r == nil {
		return nil
	}
	sends24h := r.sends24h.Val()
	// Feedback is counted per recipient, so rates are per recipient too; see
	// recipientsOrSends.
	of24h := recipientsOrSends(r.recipients24h.Val(), sends24h)
	of7d := recipientsOrSends(r.recipients7d.Val(), r.sends7d.Val())
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
		"recipients_7d":                  r.recipients7d.Val(),
		"distinct_recipient_domains_1h":  r.recipientDomains1h.Val(),
		"distinct_recipient_domains_24h": r.recipientDomains24h.Val(),
		"distinct_ips_24h":               r.ips24h.Val(),
		"distinct_keys_24h":              r.keys24h.Val(),
		"bounces_24h":                    r.bounces24h.Val(),
		"hard_bounces_24h":               r.hardBounces24h.Val(),
		"complaints_24h":                 r.complaints24h.Val(),
		"deliveries_24h":                 r.deliveries24h.Val(),
		"bounce_rate_24h":                rate(r.bounces24h.Val(), of24h),
		"hard_bounce_rate_24h":           rate(r.hardBounces24h.Val(), of24h),
		"complaint_rate_24h":             rate(r.complaints24h.Val(), of24h),
		"bounces_7d":                     r.bounces7d.Val(),
		"hard_bounces_7d":                r.hardBounces7d.Val(),
		"complaints_7d":                  r.complaints7d.Val(),
		"bounce_rate_7d":                 rate(r.bounces7d.Val(), of7d),
		"hard_bounce_rate_7d":            rate(r.hardBounces7d.Val(), of7d),
		"complaint_rate_7d":              rate(r.complaints7d.Val(), of7d),
		"trap_hits_7d":                   r.trapHits7d.Val(),
		"blocklist_hits_7d":              r.blocklistHits7d.Val(),
		"age_hours":                      ageHours(at, origin),
		"hourly_baseline_7d":             baseline,
		"volume_ratio_1h":                float64(r.sends1h.Val()) / max(baseline, 1),
	}
	// An unreadable state is left out, so rules that read it follow
	// on_error rather than take the account for active.
	if st, ok := parseAccountState(r.state, time.Now()); ok {
		m["state"] = st.State
	}
	if r.seenIP != nil {
		m["new_ip"] = !r.seenIP.Val()
		ip24h, ip7d := r.ipSends24h.Val(), r.ipSends7d.Val()
		m["ip_sends_24h"] = ip24h
		m["ip_sends_7d"] = ip7d
		// Every send counted over 24 hours is counted over 7 days too, so the
		// difference is the sends from this IP between about a day and about
		// a week ago (docs/signals.md has the exact edges). <= only guards
		// against a store that ever counts fewer over the longer window.
		m["recent_ip"] = ip7d <= ip24h
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

	if ev.Type == event.Send {
		b.Incr(sends, time.Minute, at, 1)
		b.Incr(sends, time.Hour, at, 1)
		if f.ip != "" {
			b.AddDistinct(ips, f.ip, time.Hour, at)
			b.AddDistinct(ips, f.ip, day, at)
		}
	}
	// A key_leak event is the report itself; MarkLeaked does the same for
	// callers that learn of a leak some other way. A key this process
	// already knows leaked is written again, so a report whose write failed
	// during an outage reaches the store, and every replica, the next time
	// the key is used here.
	if ev.Type == event.KeyLeak || c.leaked.has(id) {
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

// recipientsOrSends returns the denominator of the feedback rates: the
// recipients of the window's sends, or its sends when they are more.
//
// Feedback providers report one bounce or complaint per recipient, so a send
// to 50 addresses that all bounce is 50 bounces, and dividing by sends would
// read it as 5,000%. Per recipient is also how the thresholds rules compare
// against are defined: Amazon SES counts every recipient as an email sent,
// and Gmail and Yahoo count a message delivered to each inbox. A send without
// to counts no recipients, yet it reached someone, so a platform that leaves
// to out gets its sends as the denominator, as before; one that sends to on
// some events only gets the larger of the two, which leans toward a higher
// rate.
func recipientsOrSends(recipients, sends int64) int64 {
	return max(recipients, sends)
}

// rate returns n / max(of, 1), capped at 1: feedback can outnumber the
// recipients in the window when it is about older sends.
func rate(n, of int64) float64 {
	return min(float64(n)/float64(max(of, 1)), 1)
}

// ageHours returns the hours from origin to at, or zero when origin is later.
func ageHours(at, origin time.Time) float64 {
	return max(at.Sub(origin).Hours(), 0)
}
