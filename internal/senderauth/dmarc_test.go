package senderauth

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		record string
		// want is p/sp/pct/adkim/aspf, or the error.
		want    string
		warning string
	}{
		{"v=DMARC1; p=reject", "reject//100/relaxed/relaxed", ""},
		{"v=DMARC1;p=none", "none//100/relaxed/relaxed", ""},
		{"v=DMARC1; p=quarantine; sp=none; pct=25; adkim=s; aspf=r; rua=mailto:d@example.com", "quarantine/none/25/strict/relaxed", ""},
		{"v=dmarc1; P=Reject; SP=Quarantine; ADKIM=S", "reject/quarantine/100/strict/relaxed", ""},
		{"v = DMARC1 ; p = none ; ", "none//100/relaxed/relaxed", ""},
		{"v=DMARC1; p=reject; pct=0", "reject//0/relaxed/relaxed", ""},
		{"v=DMARC1; p=reject; future=tag; ri=86400", "reject//100/relaxed/relaxed", ""},

		{"v=DMARC1; p=reject; pct=101", "reject//100/relaxed/relaxed", "pct=101 is not a whole number"},
		{"v=DMARC1; p=reject; pct=-1", "reject//100/relaxed/relaxed", "pct=-1"},
		{"v=DMARC1; p=reject; pct=+5", "reject//100/relaxed/relaxed", "pct=+5"},
		{"v=DMARC1; p=reject; pct=half", "reject//100/relaxed/relaxed", "pct=half"},
		{"v=DMARC1; p=reject; adkim=x", "reject//100/relaxed/relaxed", "adkim=x is not r or s"},
		{"v=DMARC1; p=reject; aspf=strict", "reject//100/relaxed/relaxed", "aspf=strict is not r or s"},
		{"v=DMARC1; p=reject; p=none", "reject//100/relaxed/relaxed", "p appears more than once"},
		{"v=DMARC1; p=reject; garbage", "reject//100/relaxed/relaxed", `"garbage" is not a tag=value pair`},
		{"v=DMARC1; p=reject; v=DMARC1", "reject//100/relaxed/relaxed", "v appears again"},

		{"v=DMARC1", "the p tag is missing", ""},
		{"v=DMARC1; sp=reject", "the p tag is missing", ""},
		{"v=DMARC1; p=block", "p=block is not none, quarantine or reject", ""},
		{"v=DMARC1; p=reject; sp=block", "sp=block is not none, quarantine or reject", ""},
		{"v=DMARC1; p=; rua=nobody", "p= is not none", ""},
		// With a valid rua, a bad p reads as p=none (RFC 7489 6.6.3).
		{"v=DMARC1; p=block; rua=mailto:dmarc@example.com", "none//100/relaxed/relaxed", "receivers read it as p=none"},
		{"v=DMARC1; rua=mailto:dmarc@example.com; adkim=s", "none//100/strict/relaxed", "the p tag is missing"},
		{"p=reject; v=DMARC1", "does not start with v=DMARC1", ""},
		{"v=DMARC2; p=reject", "does not start with v=DMARC1", ""},
		{"v=spf1 -all", "does not start with v=DMARC1", ""},
		{"", "does not start with v=DMARC1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			rec, err := ParseDMARC(tt.record)
			got := ""
			if err != nil {
				got = err.Error()
			} else {
				got = fmt.Sprintf("%s/%s/%d/%s/%s", rec.P, rec.SP, rec.Pct, rec.ADKIM, rec.ASPF)
			}
			if err != nil && !strings.Contains(got, tt.want) || err == nil && got != tt.want {
				t.Errorf("ParseDMARC(%q) = %q, want %q", tt.record, got, tt.want)
			}
			warnings := strings.Join(rec.Warnings, "\n")
			if tt.warning == "" && warnings != "" || !strings.Contains(warnings, tt.warning) {
				t.Errorf("warnings = %q, want %q", rec.Warnings, tt.warning)
			}
		})
	}
}

func TestCheckDMARC(t *testing.T) {
	tests := []struct {
		name, domain string
		zone         map[string][]string
		errs         map[string]error
		// want is state/applies/record domain/pct.
		want, errHas string
	}{
		{name: "the domain's own record", domain: "example.com",
			zone: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=none"}},
			want: "reject/p/example.com/100"},
		{name: "sp applies to a subdomain without a record", domain: "mail.example.com",
			zone: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=none; sp=quarantine; pct=50"}},
			want: "quarantine/sp/example.com/50"},
		{name: "p applies to a subdomain when there is no sp", domain: "a.b.example.com",
			zone: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			want: "reject/p/example.com/100"},
		{name: "a subdomain's own record wins over the organization's sp", domain: "mail.example.com",
			zone: map[string][]string{"_dmarc.mail.example.com": {"v=DMARC1; p=none"}, "_dmarc.example.com": {"v=DMARC1; p=reject; sp=reject"}},
			want: "none/p/mail.example.com/100"},
		{name: "the organization under a multi-label public suffix", domain: "mail.example.co.uk",
			zone: map[string][]string{"_dmarc.example.co.uk": {"v=DMARC1; p=quarantine; sp=reject"}},
			want: "reject/sp/example.co.uk/100"},
		{name: "a private public suffix", domain: "victim.github.io",
			zone: map[string][]string{"_dmarc.github.io": {"v=DMARC1; p=reject"}},
			want: "missing//"},
		{name: "other TXT records are ignored", domain: "example.com",
			zone: map[string][]string{"_dmarc.example.com": {"hello", "v=DMARC1; p=quarantine"}},
			want: "quarantine/p/example.com/100"},
		{name: "no record anywhere", domain: "mail.example.com", want: "missing//"},
		{name: "only non-DMARC records", domain: "example.com",
			zone: map[string][]string{"_dmarc.example.com": {"v=spf1 -all"}}, want: "missing//"},
		{name: "two records are ignored, with no fallback", domain: "mail.example.com",
			zone: map[string][]string{"_dmarc.mail.example.com": {"v=DMARC1; p=none", "v=DMARC1; p=reject"}, "_dmarc.example.com": {"v=DMARC1; p=reject"}},
			want: "invalid//mail.example.com/", errHas: "2 DMARC records"},
		{name: "a malformed record", domain: "example.com",
			zone: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=bogus"}},
			want: "invalid//example.com/", errHas: "p=bogus"},
		{name: "SERVFAIL on the domain does not fall back", domain: "mail.example.com",
			zone: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			errs: map[string]error{"_dmarc.mail.example.com": errServFail},
			want: "unknown//", errHas: "server misbehaving"},
		{name: "SERVFAIL on the organizational domain", domain: "mail.example.com",
			errs: map[string]error{"_dmarc.example.com": errServFail},
			want: "unknown//", errHas: "looking up _dmarc.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := newFakeDNS(tt.zone)
			if dns.txt == nil {
				dns.txt = map[string][]string{}
			}
			for name, err := range tt.errs {
				dns.errs[name] = err
			}
			rep := checkDMARC(context.Background(), lookupOf(dns), tt.domain, OrgDomain(tt.domain))
			pct := ""
			if rep.Parsed != nil {
				pct = fmt.Sprint(rep.Parsed.Pct)
			}
			got := fmt.Sprintf("%s/%s/%s/%s", rep.State, rep.Applies, rep.RecordDomain, pct)
			if rep.RecordDomain == "" && pct == "" {
				got = fmt.Sprintf("%s/%s/", rep.State, rep.Applies)
			}
			if got != tt.want {
				t.Errorf("state/applies/record domain/pct = %s, want %s (error %q)", got, tt.want, rep.Error)
			}
			if !strings.Contains(rep.Error, tt.errHas) || tt.errHas == "" && rep.Error != "" {
				t.Errorf("error = %q, want %q", rep.Error, tt.errHas)
			}
		})
	}
}
