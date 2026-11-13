package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/senderauth"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// Bounds of sender_auth.workers and sender_auth.queue_size.
const (
	maxSenderAuthWorkers = 256
	maxSenderAuthQueue   = 1_000_000
)

// dkimSelector matches a DKIM selector: dot-separated labels of letters,
// digits, hyphens and underscores.
var dkimSelector = regexp.MustCompile(`^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$`)

// SenderAuth configures the checks of sender domains' SPF, DKIM and DMARC
// records behind the domain.spf, domain.dkim and domain.dmarc_* signals.
// They are off unless Enabled, so an upgrade makes no DNS queries it was
// not asked for. Lookups run in the background, never while a send is
// decided; see docs/signals.md.
type SenderAuth struct {
	// Enabled turns the lookups on.
	Enabled bool `yaml:"enabled"`
	// Providers are the domains a sender domain's SPF record must include
	// for mail through the platform to pass, such as amazonses.com.
	Providers []string `yaml:"providers"`
	// DKIMSelectors are the selectors the platform signs with; each is
	// looked up as <selector>._domainkey.<domain>.
	DKIMSelectors []string `yaml:"dkim_selectors"`
	// VerifiedDomainsAttribute is the key of event.attributes that lists
	// the domains the account verified, read for domain.verified even
	// with Enabled false. Default "verified_domains".
	VerifiedDomainsAttribute string `yaml:"verified_domains_attribute"`
	// TTL is how long a result is cached. Default 1h.
	TTL time.Duration `yaml:"ttl"`
	// NegativeTTL is how long a result with a missing record or a failed
	// lookup is cached, at most TTL; each domain is also looked up at most
	// once per NegativeTTL by each server. Default 5m.
	NegativeTTL time.Duration `yaml:"negative_ttl"`
	// Timeout bounds the lookups of one domain. Default 5s.
	Timeout time.Duration `yaml:"timeout"`
	// Workers is how many domains are looked up at once. Default 4.
	Workers int `yaml:"workers"`
	// QueueSize is how many domains may wait for a worker; more are
	// dropped until there is room. Default 1024.
	QueueSize int `yaml:"queue_size"`
	// Resolver is a DNS server, host:port, to ask instead of the system's
	// resolver.
	Resolver string `yaml:"resolver"`
}

// SignalOptions returns what the signal catalog needs: the verified domains
// attribute, and the cache when the lookups are on.
func (s SenderAuth) SignalOptions(cache signal.AuthCache) signal.SenderAuth {
	opts := signal.SenderAuth{VerifiedDomainsAttribute: s.VerifiedDomainsAttribute}
	if s.Enabled {
		opts.Cache = cache
	}
	return opts
}

// Checker returns the checker the section describes, asking r.
func (s SenderAuth) Checker(r senderauth.Resolver) *senderauth.Checker {
	c := &senderauth.Checker{Resolver: r, Selectors: s.DKIMSelectors}
	for _, p := range s.Providers {
		// Validated, so it normalizes.
		d, _ := senderauth.NormalizeDomain(p)
		c.Providers = append(c.Providers, d)
	}
	return c
}

// applyDefaults fills in the keys left out; a key written as 0 is left for
// the validation to refuse.
func (s *SenderAuth) applyDefaults(set func(path string) bool) {
	if !set("sender_auth.verified_domains_attribute") {
		s.VerifiedDomainsAttribute = signal.DefaultVerifiedDomainsAttribute
	}
	if !set("sender_auth.ttl") {
		s.TTL = senderauth.DefaultTTL
	}
	if !set("sender_auth.negative_ttl") {
		s.NegativeTTL = min(senderauth.DefaultNegativeTTL, s.TTL)
	}
	if !set("sender_auth.timeout") {
		s.Timeout = senderauth.DefaultTimeout
	}
	if !set("sender_auth.workers") {
		s.Workers = senderauth.DefaultWorkers
	}
	if !set("sender_auth.queue_size") {
		s.QueueSize = senderauth.DefaultQueueSize
	}
}

func (v *validator) senderAuth(s SenderAuth) {
	const p = "sender_auth"
	for i, d := range s.Providers {
		if _, err := senderauth.NormalizeDomain(d); err != nil {
			v.add(fmt.Sprintf("%s.providers[%d]", p, i), "want a domain such as amazonses.com, got %q", d)
		}
	}
	for i, sel := range s.DKIMSelectors {
		if !dkimSelector.MatchString(sel) {
			v.add(fmt.Sprintf("%s.dkim_selectors[%d]", p, i), "want a DKIM selector such as s1 or resend, got %q", sel)
		}
	}
	if a := s.VerifiedDomainsAttribute; strings.TrimSpace(a) == "" || len(a) > event.MaxIDBytes {
		v.add(p+".verified_domains_attribute", "want an attribute name of 1 to %d bytes, got %q", event.MaxIDBytes, a)
	}
	if s.TTL < time.Second {
		v.add(p+".ttl", "must be at least 1s, got %s", s.TTL)
	}
	switch {
	case s.NegativeTTL < time.Second:
		v.add(p+".negative_ttl", "must be at least 1s, got %s", s.NegativeTTL)
	case s.TTL >= time.Second && s.NegativeTTL > s.TTL:
		v.add(p+".negative_ttl", "must be at most sender_auth.ttl (%s), got %s: a missing record is not kept longer than a found one",
			durationText(s.TTL), durationText(s.NegativeTTL))
	}
	if s.Timeout <= 0 {
		v.add(p+".timeout", "must be a positive duration, got %s", s.Timeout)
	}
	if s.Workers < 1 || s.Workers > maxSenderAuthWorkers {
		v.add(p+".workers", "must be from 1 to %d, got %d", maxSenderAuthWorkers, s.Workers)
	}
	if s.QueueSize < 1 || s.QueueSize > maxSenderAuthQueue {
		v.add(p+".queue_size", "must be from 1 to %d, got %d", maxSenderAuthQueue, s.QueueSize)
	}
	if s.Resolver != "" {
		host, port, err := net.SplitHostPort(s.Resolver)
		if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
			v.add(p+".resolver", "want a DNS server as host:port, such as 1.1.1.1:53, got %q", s.Resolver)
		}
	}
}
