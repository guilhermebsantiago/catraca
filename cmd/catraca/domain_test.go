package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/senderauth"
)

// zoneResolver answers from a fixed zone; any other name is NXDOMAIN.
type zoneResolver map[string][]string

func (z zoneResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txt, ok := z[name]; ok {
		return txt, nil
	}
	return nil, fmt.Errorf("%w: %s", senderauth.ErrNotFound, name)
}

// useZone makes domain check ask zone, and records the resolver address it
// was given.
func useZone(t *testing.T, zone zoneResolver) *string {
	t.Helper()
	old := newResolver
	t.Cleanup(func() { newResolver = old })
	addr := new(string)
	newResolver = func(a string) senderauth.Resolver {
		*addr = a
		return zone
	}
	return addr
}

var demoZone = zoneResolver{
	"bank.example":               {"v=spf1 include:_spf.bank.example -all", "google-site-verification=abc"},
	"_spf.bank.example":          {"v=spf1 include:amazonses.com ip4:192.0.2.0/24 -all"},
	"amazonses.com":              {"v=spf1 ip4:199.255.192.0/22 -all"},
	"s1._domainkey.bank.example": {"v=DKIM1; p="},
	"_dmarc.bank.example":        {"v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:dmarc@bank.example; adkim=x"},
	"_dmarc.lab.example":         {"v=DMARC1; p=none; sp=reject"},
	"weird.example":              {"v=spf1 include:%{ir}.spf.weird.example ~all"},
}

func TestDomainCheck(t *testing.T) {
	addr := useZone(t, demoZone)
	r := runCLI(t, nil, "domain", "check", "Bank.Example.", "--provider", "amazonses.com", "--selector", "s1,s2", "--resolver", "127.0.0.1:5353")
	expect(t, r, exitOK,
		"bank.example (organizational domain bank.example)",
		"SPF        found",
		"record     v=spf1 include:_spf.bank.example -all",
		"all        fail",
		"provider   yes: include:amazonses.com in _spf.bank.example",
		"lookups    2 of 10",
		"records    bank.example",
		"             include _spf.bank.example",
		"               include amazonses.com",
		"DKIM       revoked",
		"s1         revoked (s1._domainkey.bank.example)",
		"s2         missing (s2._domainkey.bank.example)",
		"DMARC      quarantine",
		"applies    p, the domain's own record",
		"pct        50",
		"warning    adkim=x is not r or s: relaxed applies",
		`domain.dmarc_policy  "quarantine"`,
		"domain.dmarc_pct     50",
		"no DKIM signature",
	)
	if *addr != "127.0.0.1:5353" {
		t.Errorf("resolver address = %q", *addr)
	}

	r = runCLI(t, nil, "domain", "check", "mail.lab.example")
	expect(t, r, exitOK, "SPF        missing", "provider   unknown: no --provider given",
		"selectors  none given", "DMARC      reject", "applies    sp, from the organizational domain's record")

	r = runCLI(t, nil, "domain", "check", "weird.example", "--provider", "amazonses.com")
	expect(t, r, exitOK, "provider   unknown", "note       include:%{ir}.spf.weird.example in weird.example has macros")
}

func TestDomainCheckJSON(t *testing.T) {
	useZone(t, demoZone)
	r := runCLI(t, nil, "domain", "check", "bank.example", "--json", "--provider", "amazonses.com", "--selector", "s1")
	if r.code != exitOK {
		t.Fatal(r)
	}
	var got struct {
		Domain string `json:"domain"`
		SPF    struct {
			State, Provider string
			Lookups         int
		} `json:"spf"`
		DMARC struct {
			State  string `json:"state"`
			Parsed struct {
				SP string `json:"sp"`
			} `json:"parsed"`
		} `json:"dmarc"`
		Signals map[string]any `json:"signals"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, r.stdout)
	}
	if got.Domain != "bank.example" || got.SPF.State != "found" || got.SPF.Provider != "yes" || got.SPF.Lookups != 2 ||
		got.DMARC.State != "quarantine" || got.DMARC.Parsed.SP != "reject" {
		t.Errorf("report = %+v", got)
	}
	if got.Signals["dkim"] != "revoked" || got.Signals["dmarc_pct"] != float64(50) || got.Signals["verified"] != nil {
		t.Errorf("signals = %v", got.Signals)
	}
}

func TestDomainCheckUsage(t *testing.T) {
	useZone(t, demoZone)
	expect(t, runCLI(t, nil, "domain"), exitUsage, "Usage: catraca domain <check>")
	expect(t, runCLI(t, nil, "domain", "check"), exitUsage, "Usage: catraca domain check")
	expect(t, runCLI(t, nil, "domain", "check", "localhost"), exitUsage, `invalid domain "localhost"`)
	expect(t, runCLI(t, nil, "domain", "check", "bank.example", "--provider", "not a domain"), exitUsage, "--provider")
	if r := runCLI(t, nil, "help"); !strings.Contains(r.stdout, "domain check") {
		t.Errorf("help does not list domain check:\n%s", r.stdout)
	}
}
