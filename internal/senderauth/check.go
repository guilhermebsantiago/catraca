// Package senderauth checks how a sender domain is set up to authenticate
// its mail: its SPF record, the DKIM keys under the platform's selectors
// and its DMARC policy. It is a pre-send check of the domain's DNS, not
// what a receiver does: it evaluates SPF for no connecting IP and verifies
// no DKIM signature.
//
// Checks need DNS, which never runs while a send is decided. A Refresher
// looks domains up in the background and caches each result in the
// counter store, where the signal catalog reads it in the same round trip
// as every other signal; until it is cached, every state is unknown.
package senderauth

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"
)

// States of a record, the values of SPFReport.State, DKIMReport.State and,
// with the DMARC policies, DMARCReport.State.
const (
	// Found means the record is there and well formed.
	Found = "found"
	// Missing means the name does not exist (NXDOMAIN) or holds no such
	// record: an answer, not a failure.
	Missing = "missing"
	// Invalid means the record is there but malformed, which a receiver
	// reads as a permanent error.
	Invalid = "invalid"
	// Revoked means a DKIM selector publishes an empty key.
	Revoked = "revoked"
	// Unknown means it could not be told: a lookup timed out or failed
	// (SERVFAIL, REFUSED, a network error), the domain is not cached
	// yet, or nothing was configured to check.
	Unknown = "unknown"
)

// Checker checks a domain's records with live lookups.
type Checker struct {
	Resolver Resolver
	// Providers are the domains that sending through the platform needs
	// a domain's SPF record to include, such as amazonses.com, lowercase.
	Providers []string
	// Selectors are the DKIM selectors the platform signs with.
	Selectors []string
}

// Report is everything a check found, for people.
type Report struct {
	Domain    string      `json:"domain"`
	OrgDomain string      `json:"organizational_domain"`
	SPF       SPFReport   `json:"spf"`
	DKIM      DKIMReport  `json:"dkim"`
	DMARC     DMARCReport `json:"dmarc"`
}

// Check looks up domain's records, which must be normalized (see
// NormalizeDomain), until ctx ends: a lookup cut short reads as unknown.
// SPF, DKIM and DMARC are looked up concurrently. Each name is looked up
// once per check, however many includes name it.
func (c *Checker) Check(ctx context.Context, domain string) Report {
	org := OrgDomain(domain)
	rep := Report{Domain: domain, OrgDomain: org}
	lookup := c.memo()
	var wg sync.WaitGroup
	wg.Go(func() { rep.SPF = checkSPF(ctx, lookup, domain, c.Providers) })
	wg.Go(func() { rep.DKIM = checkDKIM(ctx, lookup, domain, c.Selectors) })
	wg.Go(func() { rep.DMARC = checkDMARC(ctx, lookup, domain, org) })
	wg.Wait()
	return rep
}

type answer struct {
	txts []string
	err  error
}

// memo returns a lookup function that asks the resolver once per name.
func (c *Checker) memo() func(context.Context, string) ([]string, error) {
	var mu sync.Mutex
	seen := map[string]answer{}
	return func(ctx context.Context, name string) ([]string, error) {
		name = strings.ToLower(name)
		mu.Lock()
		a, ok := seen[name]
		mu.Unlock()
		if ok {
			return a.txts, a.err
		}
		txts, err := c.Resolver.LookupTXT(ctx, name)
		mu.Lock()
		seen[name] = answer{txts, err}
		mu.Unlock()
		return txts, err
	}
}

// resultVersion is the version of the cached Result encoding. A value of
// another version reads as a cache miss, so a new encoding replaces old
// values as they are looked up again.
const resultVersion = 1

// Result is what the cache keeps of a Report: the states the signals
// expose. See docs/signals.md for each.
type Result struct {
	CheckedAt   time.Time `json:"checked_at"`
	SPF         string    `json:"spf"`
	SPFAll      string    `json:"spf_all"`
	SPFProvider string    `json:"spf_provider"`
	DKIM        string    `json:"dkim"`
	DMARCPolicy string    `json:"dmarc_policy"`
	// DMARCPct is -1 unless DMARCPolicy is a policy.
	DMARCPct   int    `json:"dmarc_pct"`
	DMARCADKIM string `json:"dmarc_adkim"`
	DMARCASPF  string `json:"dmarc_aspf"`
}

// UnknownResult is the Result of a domain that is not cached.
func UnknownResult() Result {
	return Result{SPF: Unknown, SPFAll: Unknown, SPFProvider: Unknown, DKIM: Unknown,
		DMARCPolicy: Unknown, DMARCPct: -1, DMARCADKIM: Unknown, DMARCASPF: Unknown}
}

// Result returns the states of the report, as checked at at.
func (r Report) Result(at time.Time) Result {
	res := UnknownResult()
	res.CheckedAt = at.UTC()
	res.SPF, res.SPFAll, res.SPFProvider = r.SPF.State, r.SPF.All, r.SPF.Provider
	res.DKIM = r.DKIM.State
	res.DMARCPolicy = r.DMARC.State
	if p := r.DMARC.Parsed; p != nil && validPolicy(r.DMARC.State) {
		res.DMARCPct, res.DMARCADKIM, res.DMARCASPF = p.Pct, p.ADKIM, p.ASPF
	}
	return res
}

// negative reports whether the result holds an answer that should be kept
// for the negative TTL: a record missing, or a lookup that failed. A record
// that is there, valid or not, is kept for the TTL, like any DNS answer;
// so is a DKIM state of unknown when no selector was checked.
func (r Result) negative(selectors bool) bool {
	short := []string{Missing, Unknown}
	return slices.Contains(short, r.SPF) || slices.Contains(short, r.DMARCPolicy) ||
		r.DKIM == Missing || (r.DKIM == Unknown && selectors)
}

// CacheKey is the store key of domain's cached Result.
func CacheKey(domain string) string { return "domain:auth:" + domain }

// cached is the stored form of a Result.
type cached struct {
	V int `json:"v"`
	Result
}

// encode returns the stored form of r.
func (r Result) encode() string {
	b, _ := json.Marshal(cached{V: resultVersion, Result: r})
	return string(b)
}

// DecodeResult reads a Result the Refresher stored. It returns false for a
// value it cannot read, which the caller treats as a cache miss. A state it
// does not know reads as unknown.
func DecodeResult(s string) (Result, bool) {
	var c cached
	if err := json.Unmarshal([]byte(s), &c); err != nil || c.V != resultVersion {
		return Result{}, false
	}
	r := c.Result
	r.CheckedAt = r.CheckedAt.UTC()
	if y := r.CheckedAt.Year(); y < 0 || y > 9999 {
		r.CheckedAt = time.Time{}
	}
	known := func(v *string, allowed ...string) {
		if !slices.Contains(allowed, *v) {
			*v = Unknown
		}
	}
	known(&r.SPF, Found, Missing, Invalid)
	known(&r.SPFAll, AllPass, AllFail, AllSoftfail, AllNeutral, AllNone)
	known(&r.SPFProvider, Yes, No)
	known(&r.DKIM, Found, Missing, Invalid, Revoked)
	known(&r.DMARCPolicy, PolicyNone, PolicyQuarantine, PolicyReject, Missing, Invalid)
	known(&r.DMARCADKIM, Relaxed, Strict)
	known(&r.DMARCASPF, Relaxed, Strict)
	if !validPolicy(r.DMARCPolicy) {
		r.DMARCPct, r.DMARCADKIM, r.DMARCASPF = -1, Unknown, Unknown
	} else if r.DMARCPct < 0 || r.DMARCPct > 100 {
		r.DMARCPct = 100
	}
	return r, true
}
