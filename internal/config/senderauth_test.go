package config

import (
	"slices"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/senderauth"
)

// TestSenderAuthIsOffByDefault checks that an upgrade makes no DNS query
// nobody asked for.
func TestSenderAuthIsOffByDefault(t *testing.T) {
	s := mustParse(t, minimal, nil).SenderAuth
	want := SenderAuth{VerifiedDomainsAttribute: "verified_domains", TTL: time.Hour, NegativeTTL: 5 * time.Minute,
		Timeout: 5 * time.Second, Workers: 4, QueueSize: 1024}
	if !slices.Equal(s.Providers, nil) || !slices.Equal(s.DKIMSelectors, nil) {
		t.Errorf("providers %v, selectors %v; want none", s.Providers, s.DKIMSelectors)
	}
	s.Providers, s.DKIMSelectors = nil, nil
	if s.Enabled || s.Resolver != "" || s.VerifiedDomainsAttribute != want.VerifiedDomainsAttribute || s.TTL != want.TTL ||
		s.NegativeTTL != want.NegativeTTL || s.Timeout != want.Timeout || s.Workers != want.Workers || s.QueueSize != want.QueueSize {
		t.Errorf("sender_auth = %+v, want %+v", s, want)
	}
	if opts := s.SignalOptions(nil); opts.Cache != nil || opts.VerifiedDomainsAttribute != "verified_domains" {
		t.Errorf("SignalOptions = %+v", opts)
	}
}

func TestSenderAuthConfig(t *testing.T) {
	cfg := mustParse(t, minimal+`
sender_auth:
  enabled: true
  providers: [AmazonSES.com., mailgun.org]
  dkim_selectors: [resend, s1.rotation]
  verified_domains_attribute: domains
  ttl: 2h
  negative_ttl: 10m
  timeout: 3s
  workers: 8
  queue_size: 50
  resolver: ${DNS}
`, map[string]string{"DNS": "127.0.0.1:5353"})
	s := cfg.SenderAuth
	if !s.Enabled || s.VerifiedDomainsAttribute != "domains" || s.TTL != 2*time.Hour || s.NegativeTTL != 10*time.Minute ||
		s.Timeout != 3*time.Second || s.Workers != 8 || s.QueueSize != 50 || s.Resolver != "127.0.0.1:5353" {
		t.Fatalf("sender_auth = %+v", s)
	}
	c := s.Checker(nil)
	if !slices.Equal(c.Providers, []string{"amazonses.com", "mailgun.org"}) || !slices.Equal(c.Selectors, []string{"resend", "s1.rotation"}) {
		t.Errorf("checker providers %v, selectors %v", c.Providers, c.Selectors)
	}
	var cache senderauth.Refresher
	if opts := s.SignalOptions(&cache); opts.Cache == nil || opts.VerifiedDomainsAttribute != "domains" {
		t.Errorf("SignalOptions = %+v", opts)
	}
}

// A short TTL lowers the default negative TTL with it.
func TestSenderAuthNegativeTTLDefault(t *testing.T) {
	s := mustParse(t, minimal+"sender_auth: {ttl: 1m}\n", nil).SenderAuth
	if s.NegativeTTL != time.Minute {
		t.Errorf("negative_ttl = %s, want 1m", s.NegativeTTL)
	}
}

func TestSenderAuthValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"provider", "sender_auth: {providers: [amazonses.com, 'not a domain']}", `sender_auth.providers[1]: want a domain such as amazonses.com, got "not a domain"`},
		{"provider label", "sender_auth: {providers: [localhost]}", "sender_auth.providers[0]: want a domain"},
		{"selector", "sender_auth: {dkim_selectors: ['s1._domainkey.example.com', 'bad selector']}", `sender_auth.dkim_selectors[1]: want a DKIM selector such as s1 or resend, got "bad selector"`},
		{"selector dot", "sender_auth: {dkim_selectors: ['.s1']}", "sender_auth.dkim_selectors[0]"},
		{"attribute", "sender_auth: {verified_domains_attribute: ' '}", "sender_auth.verified_domains_attribute: want an attribute name"},
		{"ttl", "sender_auth: {ttl: 0s}", "sender_auth.ttl: must be at least 1s, got 0s"},
		{"negative ttl", "sender_auth: {negative_ttl: 500ms}", "sender_auth.negative_ttl: must be at least 1s"},
		{"negative ttl above ttl", "sender_auth: {ttl: 10m, negative_ttl: 1h}", "sender_auth.negative_ttl: must be at most sender_auth.ttl (10m), got 1h"},
		{"timeout", "sender_auth: {timeout: 0s}", "sender_auth.timeout: must be a positive duration"},
		{"workers", "sender_auth: {workers: 0}", "sender_auth.workers: must be from 1 to 256, got 0"},
		{"too many workers", "sender_auth: {workers: 1000}", "sender_auth.workers: must be from 1 to 256"},
		{"queue", "sender_auth: {queue_size: 0}", "sender_auth.queue_size: must be from 1 to 1000000, got 0"},
		{"resolver", "sender_auth: {resolver: '1.1.1.1'}", `sender_auth.resolver: want a DNS server as host:port, such as 1.1.1.1:53, got "1.1.1.1"`},
		{"resolver port", "sender_auth: {resolver: 'dns.internal:dns'}", "sender_auth.resolver: want a DNS server"},
		{"unknown field", "sender_auth: {selectors: [s1]}", "sender_auth.selectors: unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireError(t, parseErrors(t, minimal+tt.yaml+"\n", nil), tt.want)
		})
	}
}
