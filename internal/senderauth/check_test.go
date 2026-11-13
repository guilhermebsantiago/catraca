package senderauth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	dns := newFakeDNS(map[string][]string{
		"example.com":                      {"v=spf1 include:_spf.example.com include:_spf.example.com ~all"},
		"_spf.example.com":                 {"v=spf1 include:amazonses.com -all"},
		"amazonses.com":                    {"v=spf1 ip4:199.255.192.0/22 -all"},
		"resend._domainkey.example.com":    {"v=DKIM1; p=" + testKeys()["rsa2048"]},
		"_dmarc.example.com":               {"v=DMARC1; p=quarantine; pct=50; adkim=s"},
		"google._domainkey.example.com":    {"v=DKIM1; p="},
		"unrelated._domainkey.example.com": {"ignored"},
	})
	c := &Checker{Resolver: dns, Providers: []string{"amazonses.com"}, Selectors: []string{"resend", "google"}}
	rep := c.Check(context.Background(), "example.com")
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	got := rep.Result(at)
	want := Result{CheckedAt: at, SPF: Found, SPFAll: AllSoftfail, SPFProvider: Yes, DKIM: Found,
		DMARCPolicy: PolicyQuarantine, DMARCPct: 50, DMARCADKIM: Strict, DMARCASPF: Relaxed}
	if got != want {
		t.Errorf("Result = %+v, want %+v", got, want)
	}
	if rep.OrgDomain != "example.com" || rep.SPF.Lookups != 4 {
		t.Errorf("org %s, lookups %d; want example.com, 4", rep.OrgDomain, rep.SPF.Lookups)
	}
	// Each name once, however many includes name it.
	if n := dns.callsTo("_spf.example.com"); n != 1 {
		t.Errorf("_spf.example.com looked up %d times, want once", n)
	}
	if got.negative(true) {
		t.Error("a fully found result is negative")
	}
}

func TestCheckUnknownDomain(t *testing.T) {
	c := &Checker{Resolver: newFakeDNS(nil), Providers: []string{"amazonses.com"}, Selectors: []string{"s1"}}
	got := c.Check(context.Background(), "nothing.example").Result(time.Time{})
	want := Result{SPF: Missing, SPFAll: Unknown, SPFProvider: No, DKIM: Missing,
		DMARCPolicy: Missing, DMARCPct: -1, DMARCADKIM: Unknown, DMARCASPF: Unknown}
	if got != want {
		t.Errorf("Result = %+v, want %+v", got, want)
	}
	if !got.negative(true) {
		t.Error("a domain without records is not negative")
	}
}

// TestCheckTimeout checks that a check cut short by its context reads as
// unknown, never as missing.
func TestCheckTimeout(t *testing.T) {
	dns := newFakeDNS(nil)
	dns.block = make(chan struct{}) // never closed
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Checker{Resolver: dns, Providers: []string{"amazonses.com"}, Selectors: []string{"s1"}}
	got := c.Check(ctx, "example.com").Result(time.Time{})
	if got != UnknownResult() {
		t.Errorf("Result = %+v, want every state unknown", got)
	}
}

func TestNegative(t *testing.T) {
	base := Result{SPF: Found, SPFAll: AllFail, SPFProvider: Yes, DKIM: Found, DMARCPolicy: PolicyReject, DMARCPct: 100, DMARCADKIM: Relaxed, DMARCASPF: Relaxed}
	tests := []struct {
		name      string
		change    func(*Result)
		selectors bool
		want      bool
	}{
		{"all found", func(*Result) {}, true, false},
		{"SPF missing", func(r *Result) { r.SPF = Missing }, true, true},
		{"SPF unknown", func(r *Result) { r.SPF = Unknown }, true, true},
		{"SPF invalid is an answer", func(r *Result) { r.SPF = Invalid }, true, false},
		{"DMARC missing", func(r *Result) { r.DMARCPolicy = Missing }, true, true},
		{"DMARC none is an answer", func(r *Result) { r.DMARCPolicy = PolicyNone }, true, false},
		{"DKIM missing", func(r *Result) { r.DKIM = Missing }, true, true},
		{"DKIM revoked is an answer", func(r *Result) { r.DKIM = Revoked }, true, false},
		{"DKIM unknown after a failure", func(r *Result) { r.DKIM = Unknown }, true, true},
		{"DKIM unknown without selectors", func(r *Result) { r.DKIM = Unknown }, false, false},
	}
	for _, tt := range tests {
		r := base
		tt.change(&r)
		if got := r.negative(tt.selectors); got != tt.want {
			t.Errorf("%s: negative = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestResultEncoding(t *testing.T) {
	r := Result{CheckedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), SPF: Found, SPFAll: AllSoftfail, SPFProvider: No,
		DKIM: Revoked, DMARCPolicy: PolicyReject, DMARCPct: 10, DMARCADKIM: Relaxed, DMARCASPF: Strict}
	got, ok := DecodeResult(r.encode())
	if !ok || got != r {
		t.Errorf("round trip = %+v, %v; want %+v", got, ok, r)
	}
	for _, bad := range []string{"", "{", "null", `{"v":2,"spf":"found"}`, `{"spf":"found"}`, `[1]`} {
		if _, ok := DecodeResult(bad); ok {
			t.Errorf("DecodeResult(%q) is readable", bad)
		}
	}
	// A state the decoder does not know reads as unknown, and fields that
	// only mean something with a policy are cleared without one.
	got, ok = DecodeResult(`{"v":1,"spf":"pass","spf_all":"fail","spf_provider":"maybe","dkim":"found","dmarc_policy":"missing","dmarc_pct":50,"dmarc_adkim":"strict","dmarc_aspf":"x"}`)
	want := Result{SPF: Unknown, SPFAll: AllFail, SPFProvider: Unknown, DKIM: Found, DMARCPolicy: Missing, DMARCPct: -1, DMARCADKIM: Unknown, DMARCASPF: Unknown}
	if !ok || got != want {
		t.Errorf("DecodeResult = %+v, %v; want %+v", got, ok, want)
	}
	got, _ = DecodeResult(`{"v":1,"dmarc_policy":"reject","dmarc_pct":500,"dmarc_adkim":"relaxed","dmarc_aspf":"relaxed"}`)
	if got.DMARCPct != 100 || got.SPF != Unknown {
		t.Errorf("DecodeResult = %+v, want pct 100 and SPF unknown", got)
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"mail.example.co.uk", "mail.example.co.uk"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"_dmarc.example.com", "_dmarc.example.com"},
		{"localhost", ""},
		{"", ""},
		{"exa mple.com", ""},
		{"-example.com", ""},
		{"example..com", ""},
		{strings.Repeat("a", 64) + ".com", ""},
		{strings.Repeat("a.", 127) + "com", ""},
		{"[192.0.2.1]", ""},
	}
	for _, tt := range tests {
		got, err := NormalizeDomain(tt.in)
		if got != tt.want || (err == nil) != (tt.want != "") {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestOrgDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":           "example.com",
		"a.b.example.com":       "example.com",
		"mail.example.co.uk":    "example.co.uk",
		"co.uk":                 "co.uk",
		"com":                   "com",
		"victim.github.io":      "victim.github.io",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	} {
		if got := OrgDomain(in); got != want {
			t.Errorf("OrgDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
