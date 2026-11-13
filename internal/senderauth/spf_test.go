package senderauth

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestParseSPF(t *testing.T) {
	tests := []struct {
		record string
		terms  string // the terms as parsed, qualifier included, or the error
	}{
		{"v=spf1", ""},
		{"v=spf1 -all", "-all"},
		{"V=SPF1 INCLUDE:AmazonSES.com ~ALL", "+include:AmazonSES.com ~all"},
		{"v=spf1  ip4:192.0.2.0/24   ip6:2001:db8::/32 ?all ", "+ip4:192.0.2.0/24 +ip6:2001:db8::/32 ?all"},
		{"v=spf1 a mx a/24 mx:mail.example.com/24//64 a//64 ptr ptr:example.com", "+a +mx +a/24 +mx:mail.example.com/24//64 +a//64 +ptr +ptr:example.com"},
		{"v=spf1 exists:%{i}._spf.example.com include:%{l1r+-}.example.com -all", "+exists:%{i}._spf.example.com +include:%{l1r+-}.example.com -all"},
		{"v=spf1 redirect=_spf.example.com", "redirect=_spf.example.com"},
		{"v=spf1 exp=explain.%{d} unknown-mod=anything%% -all", "exp=explain.%{d} unknown-mod=anything%% -all"},
		{"v=spf1 include:example.com.", "+include:example.com."},

		{"v=spf10 -all", "does not start with v=spf1"},
		{" v=spf1 -all", "does not start with v=spf1"},
		{"spf1 -all", "does not start with v=spf1"},
		{"v=spf1 foo", `unknown mechanism "foo"`},
		{"v=spf1 +", `unknown mechanism ""`},
		{"v=spf1 include", "include needs a domain"},
		{"v=spf1 include:", "include needs a domain"},
		{"v=spf1 include:com", "does not end with a top-level domain"},
		{"v=spf1 include:example.123", "does not end with a top-level domain"},
		{"v=spf1 include:50%.example.com", "'%' followed by '.'"},
		{"v=spf1 include:%{z}.example.com", "invalid macro"},
		{"v=spf1 include:%{d.example.com", "unterminated macro"},
		{"v=spf1 all:example.com", "all takes no argument"},
		{"v=spf1 ip4:300.1.1.1", "invalid address"},
		{"v=spf1 ip4:01.2.3.4", "invalid address"},
		{"v=spf1 ip4:192.0.2.0/33", "invalid CIDR length"},
		{"v=spf1 ip4:192.0.2.0/024", "invalid CIDR length"},
		{"v=spf1 ip4:2001:db8::1", "is not an IPv4 address"},
		{"v=spf1 ip6:192.0.2.1", "is not an IPv6 address"},
		{"v=spf1 ip6:2001:db8::/129", "invalid CIDR length"},
		{"v=spf1 a/33", "invalid IPv4 CIDR length"},
		{"v=spf1 mx//129", "invalid IPv6 CIDR length"},
		{"v=spf1 a:/24", "a takes :domain"},
		{"v=spf1 redirect=a.example redirect=b.example", "redirect appears more than once"},
		{"v=spf1 exp=a.example exp=b.example", "exp appears more than once"},
		{"v=spf1 redirect=com", "does not end with a top-level domain"},
	}
	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			rec, err := ParseSPF(tt.record)
			got := ""
			if err != nil {
				got = err.Error()
			} else {
				var parts []string
				for _, term := range rec.Terms {
					parts = append(parts, term.Qualifier+term.String())
				}
				got = strings.Join(parts, " ")
			}
			if err != nil && !strings.Contains(got, tt.terms) || err == nil && got != tt.terms {
				t.Errorf("ParseSPF(%q) = %q, want %q", tt.record, got, tt.terms)
			}
		})
	}
}

// spfZone is a zone of SPF records, keyed by domain.
func spfZone(records map[string]string) *fakeDNS {
	zone := map[string][]string{}
	for name, rec := range records {
		zone[name] = []string{rec}
	}
	return newFakeDNS(zone)
}

func TestCheckSPF(t *testing.T) {
	providers := []string{"amazonses.com"}
	ses := "v=spf1 ip4:199.255.192.0/22 -all"
	tests := []struct {
		name      string
		zone      map[string]string
		errs      map[string]error
		extra     map[string][]string // more TXT records, added to zone's
		providers []string
		// want is state/all/provider/lookups.
		want string
		// errHas is in Error; via is ProviderVia; note is in Notes.
		errHas, via, note string
	}{
		{name: "fail", zone: map[string]string{"example.com": "v=spf1 ip4:192.0.2.0/24 -all"}, want: "found/fail/no/0"},
		{name: "softfail", zone: map[string]string{"example.com": "v=spf1 ~all"}, want: "found/softfail/no/0"},
		{name: "neutral", zone: map[string]string{"example.com": "v=spf1 ?all"}, want: "found/neutral/no/0"},
		{name: "pass", zone: map[string]string{"example.com": "v=spf1 +all"}, want: "found/pass/no/0"},
		{name: "all without qualifier passes", zone: map[string]string{"example.com": "v=spf1 all"}, want: "found/pass/no/0"},
		{name: "no all", zone: map[string]string{"example.com": "v=spf1 ip4:192.0.2.1"}, want: "found/none/no/0"},
		{name: "provider included", zone: map[string]string{"example.com": "v=spf1 include:amazonses.com ~all", "amazonses.com": ses},
			want: "found/softfail/yes/1", via: "include:amazonses.com in example.com"},
		{name: "provider in any case", zone: map[string]string{"example.com": "v=spf1 INCLUDE:AmazonSES.com. -all", "amazonses.com": ses},
			want: "found/fail/yes/1"},
		{name: "provider nested", zone: map[string]string{
			"example.com":      "v=spf1 include:_spf.example.com -all",
			"_spf.example.com": "v=spf1 ip4:192.0.2.0/24 include:amazonses.com -all",
			"amazonses.com":    ses,
		}, want: "found/fail/yes/2", via: "include:amazonses.com in _spf.example.com"},
		{name: "provider by redirect, whose all applies", zone: map[string]string{
			"example.com": "v=spf1 redirect=amazonses.com", "amazonses.com": ses,
		}, want: "found/fail/yes/1", via: "redirect=amazonses.com in example.com"},
		{name: "provider behind a softfail include is not authorized", zone: map[string]string{
			"example.com": "v=spf1 ~include:amazonses.com -all", "amazonses.com": ses,
		}, want: "found/fail/no/1"},
		{name: "provider under a neutral include is not authorized", zone: map[string]string{
			"example.com": "v=spf1 ?include:_spf.example.com -all", "_spf.example.com": "v=spf1 include:amazonses.com -all", "amazonses.com": ses,
		}, want: "found/fail/no/2"},
		{name: "other provider", zone: map[string]string{
			"example.com": "v=spf1 include:_spf.google.com ~all", "_spf.google.com": "v=spf1 ip4:203.0.113.0/24 ~all",
		}, want: "found/softfail/no/1"},
		{name: "no providers configured", providers: []string{}, zone: map[string]string{
			"example.com": "v=spf1 include:amazonses.com ~all", "amazonses.com": ses,
		}, want: "found/softfail/unknown/1"},
		{name: "terms after all are never evaluated", zone: map[string]string{
			"example.com": "v=spf1 -all include:amazonses.com a mx", "amazonses.com": ses,
		}, want: "found/fail/no/0"},
		{name: "redirect is ignored when there is all", zone: map[string]string{
			"example.com": "v=spf1 ~all redirect=amazonses.com", "amazonses.com": ses,
		}, want: "found/softfail/no/0"},

		{name: "NXDOMAIN", zone: map[string]string{}, want: "missing/unknown/no/0"},
		{name: "TXT records but no SPF", extra: map[string][]string{"example.com": {"google-site-verification=abc", "v=spf10 -all"}},
			want: "missing/unknown/no/0"},
		{name: "two SPF records", extra: map[string][]string{"example.com": {"v=spf1 -all", "v=spf1 ~all"}},
			want: "invalid/unknown/no/0", errHas: "publishes 2 SPF records"},
		{name: "SPF and other records", extra: map[string][]string{"example.com": {"v=spf1 -all", "google-site-verification=abc"}},
			want: "found/fail/no/0"},
		{name: "syntax error", zone: map[string]string{"example.com": "v=spf1 include:amazonses.com ip4:1.2.3.4/40 -all"},
			want: "invalid/unknown/no/0", errHas: "invalid CIDR length"},
		{name: "include target without a record", zone: map[string]string{"example.com": "v=spf1 include:gone.example -all"},
			want: "invalid/unknown/no/1", errHas: "include target gone.example has no SPF record"},
		{name: "redirect target without a record", zone: map[string]string{"example.com": "v=spf1 redirect=gone.example"},
			want: "invalid/unknown/no/1", errHas: "redirect target gone.example has no SPF record"},
		{name: "syntax error in an include", zone: map[string]string{
			"example.com": "v=spf1 include:_spf.example.com -all", "_spf.example.com": "v=spf1 bogus -all",
		}, want: "invalid/unknown/no/1", errHas: `_spf.example.com: bogus: unknown mechanism`},

		{name: "SERVFAIL", errs: map[string]error{"example.com": errServFail}, want: "unknown/unknown/unknown/0", errHas: "server misbehaving"},
		{name: "SERVFAIL in an include before the provider", zone: map[string]string{
			"example.com": "v=spf1 include:_spf.example.com include:amazonses.com -all", "amazonses.com": ses,
		}, errs: map[string]error{"_spf.example.com": errServFail}, want: "unknown/unknown/unknown/1", errHas: "looking up _spf.example.com"},
		{name: "SERVFAIL in an include after the provider", zone: map[string]string{
			"example.com": "v=spf1 include:amazonses.com include:_spf.example.com -all", "amazonses.com": ses,
		}, errs: map[string]error{"_spf.example.com": errServFail}, want: "unknown/unknown/yes/2", errHas: "looking up _spf.example.com"},

		{name: "ten lookups is the limit", zone: map[string]string{
			"example.com":      "v=spf1 a mx ptr exists:x.example.com include:_spf.example.com -all",
			"_spf.example.com": "v=spf1 a:a.example.com a:b.example.com mx:c.example.com include:amazonses.com redirect=_r.example.com",
			"amazonses.com":    ses,
			"_r.example.com":   "v=spf1 -all",
		}, want: "found/fail/yes/10", note: "ptr"},
		{name: "eleven lookups is a permanent error", zone: map[string]string{
			"example.com": "v=spf1 a mx a mx a mx a mx a mx a -all",
		}, want: "invalid/unknown/no/11", errHas: "more than 10 DNS lookups"},
		{name: "the limit counts nested includes", zone: map[string]string{
			"example.com":    "v=spf1 include:i1.example.com -all",
			"i1.example.com": "v=spf1 include:i2.example.com -all", "i2.example.com": "v=spf1 include:i3.example.com -all",
			"i3.example.com": "v=spf1 include:i4.example.com -all", "i4.example.com": "v=spf1 include:i5.example.com -all",
			"i5.example.com": "v=spf1 include:i6.example.com -all", "i6.example.com": "v=spf1 include:i7.example.com -all",
			"i7.example.com": "v=spf1 include:i8.example.com -all", "i8.example.com": "v=spf1 include:i9.example.com -all",
			"i9.example.com": "v=spf1 include:i10.example.com -all", "i10.example.com": "v=spf1 include:i11.example.com -all",
			"i11.example.com": "v=spf1 -all",
		}, want: "invalid/unknown/no/11", errHas: "more than 10 DNS lookups"},
		{name: "a provider reached within the limit still authorizes", zone: map[string]string{
			"example.com": "v=spf1 include:amazonses.com a a a a a a a a a a -all", "amazonses.com": ses,
		}, want: "invalid/unknown/yes/11", errHas: "more than 10 DNS lookups"},

		{name: "include loop", zone: map[string]string{
			"example.com": "v=spf1 include:a.example.com -all", "a.example.com": "v=spf1 include:example.com -all",
		}, want: "invalid/unknown/no/2", errHas: "include loop: example.com -> a.example.com -> example.com"},
		{name: "redirect to itself", zone: map[string]string{"example.com": "v=spf1 redirect=EXAMPLE.com"},
			want: "invalid/unknown/no/1", errHas: "redirect loop"},
		{name: "the same include twice is no loop", zone: map[string]string{
			"example.com":      "v=spf1 include:a.example.com include:b.example.com -all",
			"a.example.com":    "v=spf1 include:_spf.example.com -all",
			"b.example.com":    "v=spf1 include:_spf.example.com -all",
			"_spf.example.com": "v=spf1 ip4:192.0.2.1 -all",
		}, want: "found/fail/no/4"},

		{name: "include with macros is not evaluated", zone: map[string]string{"example.com": "v=spf1 include:%{ir}.%{v}._spf.example.com -all"},
			want: "found/fail/unknown/1", note: "has macros"},
		{name: "include with macros after the provider", zone: map[string]string{
			"example.com": "v=spf1 include:amazonses.com include:%{ir}._spf.example.com -all", "amazonses.com": ses,
		}, want: "found/fail/yes/2"},
		{name: "exists with macros counts but never includes", zone: map[string]string{"example.com": "v=spf1 exists:%{i}._spf.example.com -all"},
			want: "found/fail/no/1"},
		{name: "redirect with macros", zone: map[string]string{"example.com": "v=spf1 redirect=%{d}._spf.example.com"},
			want: "found/none/unknown/1", note: "has macros"},
		{name: "softfail include with macros cannot authorize", zone: map[string]string{"example.com": "v=spf1 ~include:%{i}.example.com -all"},
			want: "found/fail/no/1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := spfZone(tt.zone)
			for name, recs := range tt.extra {
				dns.txt[name] = append(dns.txt[name], recs...)
			}
			for name, err := range tt.errs {
				dns.errs[name] = err
			}
			p := providers
			if tt.providers != nil {
				p = tt.providers
			}
			rep := checkSPF(context.Background(), lookupOf(dns), "example.com", p)
			got := fmt.Sprintf("%s/%s/%s/%d", rep.State, rep.All, rep.Provider, rep.Lookups)
			if got != tt.want {
				t.Errorf("state/all/provider/lookups = %s, want %s (error %q, tree %+v)", got, tt.want, rep.Error, rep.Tree)
			}
			if !strings.Contains(rep.Error, tt.errHas) || (tt.errHas == "" && rep.Error != "") {
				t.Errorf("error = %q, want it to contain %q", rep.Error, tt.errHas)
			}
			if tt.via != "" && rep.ProviderVia != tt.via {
				t.Errorf("provider via = %q, want %q", rep.ProviderVia, tt.via)
			}
			if tt.note != "" && !strings.Contains(strings.Join(rep.Notes, "\n"), tt.note) {
				t.Errorf("notes = %q, want one about %q", rep.Notes, tt.note)
			}
			if rep.State == Found || rep.State == Invalid && !strings.Contains(rep.Error, "SPF records") {
				if rep.Record == "" && tt.extra == nil {
					t.Errorf("record is empty")
				}
			}
		})
	}
}

// TestCheckSPFTree checks the order of the records visited, as the CLI
// prints them.
func TestCheckSPFTree(t *testing.T) {
	dns := spfZone(map[string]string{
		"example.com":      "v=spf1 include:_spf.example.com redirect=_r.example.com",
		"_spf.example.com": "v=spf1 include:amazonses.com -all",
		"amazonses.com":    "v=spf1 -all",
		"_r.example.com":   "v=spf1 ~all",
	})
	rep := checkSPF(context.Background(), lookupOf(dns), "example.com", []string{"amazonses.com"})
	var got []string
	for _, n := range rep.Tree {
		got = append(got, fmt.Sprintf("%d %s %s", n.Depth, n.Via, n.Domain))
	}
	want := []string{"0  example.com", "1 include _spf.example.com", "2 include amazonses.com", "1 redirect _r.example.com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tree = %q, want %q", got, want)
	}
	if rep.All != AllSoftfail {
		t.Errorf("all = %s, want the redirect target's softfail", rep.All)
	}
}
