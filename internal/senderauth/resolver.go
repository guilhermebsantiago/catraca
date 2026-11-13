package senderauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Resolver looks up TXT records. Implementations are safe for concurrent use.
type Resolver interface {
	// LookupTXT returns the TXT records at name, each record's strings
	// joined. It returns an error wrapping ErrNotFound when the name does
	// not exist (NXDOMAIN) or has no TXT record (NODATA), and any other
	// error when the answer could not be had: a timeout, SERVFAIL, REFUSED,
	// a network error. Only ErrNotFound reads as "missing"; every other
	// error reads as "unknown".
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// ErrNotFound is wrapped by Resolver errors for a name that does not exist
// or has no TXT record.
var ErrNotFound = errors.New("no such record")

// NewSystemResolver returns a Resolver that asks the system's DNS resolver
// or, when addr is set, the DNS server at addr (host:port) directly.
//
// It uses Go's net.Resolver, which reads the system configuration on every
// platform and falls back to TCP for long answers, but does not report
// TTLs: results are cached for the configured TTLs instead.
func NewSystemResolver(addr string) Resolver {
	r := &net.Resolver{}
	if addr != "" {
		r.PreferGo = true
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	return systemResolver{r}
}

type systemResolver struct{ r *net.Resolver }

func (s systemResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	// The trailing dot keeps the resolver from trying the name under the
	// search domains of resolv.conf first.
	txt, err := s.r.LookupTXT(ctx, name+".")
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, err
	}
	if len(txt) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return txt, nil
}

// isNotFound reports whether a Resolver error means the record is missing,
// rather than unknown.
func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// NormalizeDomain returns domain as it is looked up and cached: lowercase,
// without a trailing dot, internationalized names in their ASCII (punycode)
// form. It fails for a name that is not a hostname of at least two labels,
// which no From domain that can authenticate is.
func NormalizeDomain(domain string) (string, error) {
	d := strings.TrimSuffix(domain, ".")
	if !isASCII(d) {
		var err error
		if d, err = idna.Lookup.ToASCII(d); err != nil {
			return "", fmt.Errorf("invalid domain %q: %v", domain, err)
		}
	}
	d = strings.ToLower(d)
	if !isHostname(d) || !strings.Contains(d, ".") {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	return d, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// isHostname reports whether name, lowercase and without a trailing dot, is
// a DNS name of letters, digits, hyphens and underscores (which _dmarc and
// _domainkey names have), with labels of 1 to 63 bytes and at most 253 in
// all.
func isHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// OrgDomain returns the organizational domain of a normalized domain, as
// DMARC (RFC 7489) defines it: the registrable domain under the public
// suffix list, such as example.co.uk for mail.example.co.uk. A domain that
// is itself a public suffix is its own organizational domain.
func OrgDomain(domain string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return org
}
