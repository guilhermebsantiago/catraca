package signal

import (
	"context"
	"maps"
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/senderauth"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// DefaultVerifiedDomainsAttribute is the default for
// SenderAuth.VerifiedDomainsAttribute.
const DefaultVerifiedDomainsAttribute = "verified_domains"

// maxVerifiedDomains bounds the domains read from the verified domains
// attribute; the rest are ignored.
const maxVerifiedDomains = 100

// Values of domain.verified.
const (
	VerifiedExact   = "exact"
	VerifiedRelaxed = "relaxed"
	VerifiedNo      = "no"
)

// AuthCache is told of every read of the sender authentication cache that a
// senderauth.Refresher fills. *senderauth.Refresher is one.
type AuthCache interface {
	// Hit counts a send whose From domain was cached.
	Hit()
	// Miss counts a send whose From domain had nothing readable cached.
	// It queues the domain for a lookup, without blocking.
	Miss(domain string)
}

// SenderAuth configures the sender domain authentication signals of the
// domain map.
type SenderAuth struct {
	// Cache, when set, makes each send read its From domain's cached
	// authentication in the same store round trip as its other signals,
	// and queue a lookup on a miss. Nil leaves those signals unknown.
	Cache AuthCache
	// VerifiedDomainsAttribute is the key of event.attributes that lists
	// the domains the account verified, separated by commas or spaces.
	// Empty means DefaultVerifiedDomainsAttribute.
	VerifiedDomainsAttribute string
}

type lookupsKey struct{}

// WithoutLookups returns a context under which Observe queues no sender
// domain lookup on a cache miss, and counts no cache read: explaining an
// event reads the cache as deciding it would, and leaves DNS alone.
func WithoutLookups(ctx context.Context) context.Context {
	return context.WithValue(ctx, lookupsKey{}, true)
}

func lookupsAllowed(ctx context.Context) bool {
	off, _ := ctx.Value(lookupsKey{}).(bool)
	return !off
}

// authRead is the read of a send's From domain in the cache.
type authRead struct {
	domain string // normalized
	val    *store.StringResult
}

// readAuth queues the cache read of the From domain for a send, or returns
// nil when there is nothing to read.
func (c *catalog) readAuth(b *store.Batch, ev event.Event, f facts) *authRead {
	if c.auth.Cache == nil || ev.Type != event.Send || f.fromDomain == "" {
		return nil
	}
	d, err := senderauth.NormalizeDomain(f.fromDomain)
	if err != nil {
		return nil
	}
	return &authRead{domain: d, val: b.Get(senderauth.CacheKey(d))}
}

// addAuth adds the sender authentication signals to m, the domain map: what
// r read when it is not nil and the store answered, every state unknown
// otherwise, and domain.verified, which needs no store.
func (c *catalog) addAuth(ctx context.Context, m map[string]any, ev event.Event, f facts, r *authRead, stored bool) {
	res := senderauth.UnknownResult()
	if r != nil && stored {
		cached, ok := senderauth.DecodeResult(r.val.Val())
		switch {
		case !lookupsAllowed(ctx):
			if r.val.Found() && ok {
				res = cached
			}
		case r.val.Found() && ok:
			res = cached
			c.auth.Cache.Hit()
		default:
			c.auth.Cache.Miss(r.domain)
		}
	}
	maps.Copy(m, SenderAuthSignals(res))
	m["verified"] = c.verified(ev, f)
}

// SenderAuthSignals returns the domain signals a cached result gives: all
// the sender authentication signals but verified, which comes from the
// event.
func SenderAuthSignals(res senderauth.Result) map[string]any {
	return map[string]any{
		"spf":          res.SPF,
		"spf_all":      res.SPFAll,
		"spf_provider": res.SPFProvider,
		"dkim":         res.DKIM,
		"dmarc_policy": res.DMARCPolicy,
		"dmarc_pct":    int64(res.DMARCPct),
		"dmarc_adkim":  res.DMARCADKIM,
		"dmarc_aspf":   res.DMARCASPF,
	}
}

// verified says whether the From domain is one the account verified, as
// the event's verified domains attribute lists them: exact when it is one
// of them, relaxed when it shares its organizational domain with one, as
// DMARC's relaxed alignment does, no when neither, and unknown when the
// event does not carry the attribute or the From domain is not a domain.
// An attribute present but empty says the account verified no domain.
func (c *catalog) verified(ev event.Event, f facts) string {
	list, ok := ev.Attributes[c.auth.VerifiedDomainsAttribute]
	if !ok || f.fromDomain == "" {
		return senderauth.Unknown
	}
	from, err := senderauth.NormalizeDomain(f.fromDomain)
	if err != nil {
		return senderauth.Unknown
	}
	org := ""
	answer := VerifiedNo
	n := 0
	for d := range strings.FieldsFuncSeq(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if n++; n > maxVerifiedDomains {
			break
		}
		d, err := senderauth.NormalizeDomain(d)
		if err != nil {
			continue
		}
		if d == from {
			return VerifiedExact
		}
		if answer == VerifiedRelaxed {
			continue
		}
		if org == "" {
			org = senderauth.OrgDomain(from)
		}
		// Only a domain under the organizational domain can share it, so
		// the public suffix list is consulted for those alone.
		if (d == org || strings.HasSuffix(d, "."+org)) && senderauth.OrgDomain(d) == org {
			answer = VerifiedRelaxed
		}
	}
	return answer
}
