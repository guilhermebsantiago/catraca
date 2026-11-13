package senderauth

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The parsers read records anyone can publish, so the fuzz targets check
// that no record makes them panic, loop or return a value outside what the
// signals expect.

var spfSeeds = []string{
	"v=spf1 -all",
	"v=spf1 include:amazonses.com ~all",
	"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx/24//64 ptr ?all",
	"v=spf1 exists:%{i}._spf.example.com include:%{l1r+-}.example.com redirect=_spf.example.com",
	"v=spf1 exp=explain.%{d} unknown=%% -all",
	"v=spf1 include:com",
	"V=SPF1 A:Mail.Example.COM/24 -ALL",
	"v=spf1 redirect=a.example redirect=b.example",
	"v=spf1 include:%{",
}

// FuzzParseSPF checks that a record that parses parses again, to the same
// terms, from the terms written back.
func FuzzParseSPF(f *testing.F) {
	for _, s := range spfSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		rec, err := ParseSPF(record)
		if err != nil {
			return
		}
		parts := []string{"v=spf1"}
		for _, term := range rec.Terms {
			if term.Modifier != (term.Qualifier == "") {
				t.Fatalf("term %+v: a modifier has no qualifier and a mechanism always has one", term)
			}
			if term.Name != strings.ToLower(term.Name) {
				t.Fatalf("term name %q is not lowercase", term.Name)
			}
			parts = append(parts, term.Qualifier+term.String())
		}
		again, err := ParseSPF(strings.Join(parts, " "))
		if err != nil {
			t.Fatalf("%q parsed, but %q, its terms written back, does not: %v", record, strings.Join(parts, " "), err)
		}
		if !reflect.DeepEqual(again, rec) {
			t.Fatalf("%q parsed to %+v, and written back to %+v", record, rec, again)
		}
	})
}

// FuzzCheckSPF walks a zone where every name holds the fuzzed record, so
// each include and redirect leads back to it: the walk must end, within
// the lookup limit, in a state the signals know.
func FuzzCheckSPF(f *testing.F) {
	for _, s := range spfSeeds {
		f.Add(s, "amazonses.com")
	}
	f.Add("v=spf1 include:a.example include:b.example -all", "b.example")
	f.Fuzz(func(t *testing.T, record, provider string) {
		dns := newFakeDNS(nil)
		dns.onLookup = func(name string) {
			dns.mu.Lock()
			dns.txt[name] = []string{record}
			dns.mu.Unlock()
		}
		dns.txt = map[string][]string{}
		rep := checkSPF(context.Background(), lookupOf(dns), "example.com", []string{strings.ToLower(provider)})
		if !slices.Contains([]string{Found, Missing, Invalid}, rep.State) {
			t.Fatalf("state %q", rep.State)
		}
		if rep.Lookups > MaxSPFLookups+1 {
			t.Fatalf("%d lookups counted, past the limit", rep.Lookups)
		}
		if n := dns.totalCalls(); n > MaxSPFLookups+1 {
			t.Fatalf("%d DNS queries for one check", n)
		}
		if rep.State != Found && rep.All != Unknown || rep.State == Found && rep.All == Unknown {
			t.Fatalf("state %s with all %s", rep.State, rep.All)
		}
		if !slices.Contains([]string{Yes, No, Unknown}, rep.Provider) {
			t.Fatalf("provider %q", rep.Provider)
		}
	})
}

// FuzzParseDMARC checks that a record that parses holds values a rule can
// compare against.
func FuzzParseDMARC(f *testing.F) {
	for _, s := range []string{
		"v=DMARC1; p=reject",
		"v=DMARC1; p=quarantine; sp=none; pct=25; adkim=s; aspf=r; rua=mailto:d@example.com",
		"v=dmarc1;P=Reject;pct=101;adkim=x",
		"v=DMARC1; p=bogus; rua=mailto:a@example.com",
		"v=DMARC1; p=none; p=reject;;; garbage",
		"p=reject; v=DMARC1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		rec, err := ParseDMARC(record)
		if err != nil {
			return
		}
		if !validPolicy(rec.P) || rec.SP != "" && !validPolicy(rec.SP) {
			t.Fatalf("p=%q sp=%q", rec.P, rec.SP)
		}
		if rec.Pct < 0 || rec.Pct > 100 {
			t.Fatalf("pct=%d", rec.Pct)
		}
		for _, mode := range []string{rec.ADKIM, rec.ASPF} {
			if mode != Relaxed && mode != Strict {
				t.Fatalf("alignment mode %q", mode)
			}
		}
	})
}

// FuzzParseDKIMKey checks that a key that parses is revoked or usable.
func FuzzParseDKIMKey(f *testing.F) {
	for _, s := range []string{
		"v=DKIM1; k=rsa; p=" + testKeys()["rsa2048"],
		"v=DKIM1; k=ed25519; p=" + testKeys()["ed25519"],
		"v=DKIM1; p=",
		"v=DKIM1; p=" + testKeys()["rsa512"],
		"k=rsa; v=DKIM1; p=abc",
		"v=DKIM1; t=y:s; p=" + testKeys()["pkcs1"],
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		key, err := ParseDKIMKey(record)
		if err != nil || key.Revoked {
			return
		}
		switch key.Type {
		case "rsa":
			if key.Bits < minRSABits {
				t.Fatalf("an RSA key of %d bits parsed", key.Bits)
			}
		case "ed25519":
		default:
			t.Fatalf("key type %q parsed", key.Type)
		}
	})
}

// FuzzDecodeResult checks that whatever the store holds decodes to states
// the signals know.
func FuzzDecodeResult(f *testing.F) {
	f.Add(UnknownResult().encode())
	f.Add(`{"v":1,"spf":"found","spf_all":"fail","dmarc_policy":"reject","dmarc_pct":50}`)
	f.Add(`{"v":1,"dmarc_policy":"none","dmarc_pct":-7}`)
	f.Fuzz(func(t *testing.T, s string) {
		r, ok := DecodeResult(s)
		if !ok {
			return
		}
		if again, ok := DecodeResult(r.encode()); !ok || again != r {
			t.Fatalf("%+v does not survive encoding: %+v", r, again)
		}
		if validPolicy(r.DMARCPolicy) != (r.DMARCPct >= 0) || r.DMARCPct > 100 {
			t.Fatalf("policy %q with pct %d", r.DMARCPolicy, r.DMARCPct)
		}
	})
}
