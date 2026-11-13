package senderauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
)

// testKeys are base64 public keys of each kind, made once per test binary.
var testKeys = sync.OnceValue(func() map[string]string {
	keys := map[string]string{}
	for _, bits := range []int{1024, 2048} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			panic(err)
		}
		keys[fmt.Sprint("rsa", bits)] = base64.StdEncoding.EncodeToString(der)
		if bits == 2048 {
			keys["pkcs1"] = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&k.PublicKey))
		}
	}
	// A 512 bit key, which Go no longer generates: a public key needs only
	// a modulus of that size.
	n := new(big.Int).Lsh(big.NewInt(1), 511)
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		panic(err)
	}
	keys["rsa512"] = base64.StdEncoding.EncodeToString(der)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	keys["ed25519"] = base64.StdEncoding.EncodeToString(pub)
	return keys
})

func TestParseDKIMKey(t *testing.T) {
	k := testKeys()
	tests := []struct {
		name, record string
		// want is "type bits" for a key, "revoked", or the error.
		want string
	}{
		{"RSA 2048", "v=DKIM1; k=rsa; p=" + k["rsa2048"], "rsa 2048"},
		{"without v and k", "p=" + k["rsa1024"], "rsa 1024"},
		{"PKCS #1", "v=DKIM1; p=" + k["pkcs1"], "rsa 2048"},
		{"folded key", "v=DKIM1; p=" + k["rsa2048"][:40] + " \t " + k["rsa2048"][40:], "rsa 2048"},
		{"unpadded", "v=DKIM1; p=" + strings.TrimRight(k["rsa2048"], "="), "rsa 2048"},
		{"Ed25519", "v=DKIM1; k=ed25519; p=" + k["ed25519"], "ed25519 0"},
		{"other tags", "v=DKIM1; h=sha256; s=email; t=s; n=note; p=" + k["rsa2048"] + ";", "rsa 2048"},
		{"revoked", "v=DKIM1; k=rsa; p=", "revoked"},
		{"revoked with spaces", "v=DKIM1; p= ;", "revoked"},

		{"no p", "v=DKIM1; k=rsa", "the p tag (the public key) is missing"},
		{"not DKIM at all", "google-site-verification=abc", "the p tag (the public key) is missing"},
		{"empty", "", "the p tag (the public key) is missing"},
		{"v not first", "k=rsa; v=DKIM1; p=" + k["rsa2048"], "v must be DKIM1 and the first tag"},
		{"v wrong", "v=DKIM2; p=" + k["rsa2048"], "v=DKIM2"},
		{"repeated tag", "v=DKIM1; p=" + k["rsa2048"] + "; p=", "tag p appears more than once"},
		{"tag without value", "v=DKIM1; rsa; p=" + k["rsa2048"], `"rsa" is not a tag=value pair`},
		{"bad base64", "v=DKIM1; p=not*base64", "p is not valid base64"},
		{"not a key", "v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("hello")), "p is not a DER-encoded RSA public key"},
		{"short RSA", "v=DKIM1; p=" + k["rsa512"], "the RSA key has 512 bits; verifiers reject keys under 1024"},
		{"Ed25519 key as RSA", "v=DKIM1; k=rsa; p=" + k["ed25519"], "p is not a DER-encoded RSA public key"},
		{"RSA key as Ed25519", "v=DKIM1; k=ed25519; p=" + k["rsa2048"], "the Ed25519 key is 294 bytes"},
		{"unknown key type", "v=DKIM1; k=dsa; p=" + k["rsa2048"], "unknown key type k=dsa"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseDKIMKey(tt.record)
			var got string
			switch {
			case err != nil:
				got = err.Error()
			case key.Revoked:
				got = "revoked"
			default:
				got = fmt.Sprintf("%s %d", key.Type, key.Bits)
			}
			if err != nil && !strings.Contains(got, tt.want) || err == nil && got != tt.want {
				t.Errorf("ParseDKIMKey = %q, want %q", got, tt.want)
			}
		})
	}
	if key, err := ParseDKIMKey("v=DKIM1; t=s:y; p=" + k["rsa2048"]); err != nil || !key.Testing {
		t.Errorf("t=s:y: key %+v, error %v; want testing", key, err)
	}
}

func TestCheckDKIM(t *testing.T) {
	good := "v=DKIM1; p=" + testKeys()["rsa2048"]
	tests := []struct {
		name      string
		selectors []string
		zone      map[string][]string
		errs      map[string]error
		want      string // the domain state, then each selector's
	}{
		{"one of two found", []string{"s1", "s2"},
			map[string][]string{"s2._domainkey.example.com": {good}}, nil, "found: missing found"},
		{"found wins over a failure", []string{"s1", "s2"},
			map[string][]string{"s1._domainkey.example.com": {good}}, map[string]error{"s2._domainkey.example.com": errServFail}, "found: found unknown"},
		{"none", []string{"s1", "s2"}, nil, nil, "missing: missing missing"},
		{"revoked", []string{"s1", "s2"},
			map[string][]string{"s1._domainkey.example.com": {"v=DKIM1; p="}}, nil, "revoked: revoked missing"},
		{"invalid wins over revoked", []string{"s1", "s2"},
			map[string][]string{"s1._domainkey.example.com": {"v=DKIM1; p="}, "s2._domainkey.example.com": {"v=DKIM1"}}, nil, "invalid: revoked invalid"},
		{"a failure is unknown, not missing", []string{"s1", "s2"},
			nil, map[string]error{"s1._domainkey.example.com": errServFail}, "unknown: unknown missing"},
		{"two records", []string{"s1"},
			map[string][]string{"s1._domainkey.example.com": {good, good}}, nil, "invalid: invalid"},
		{"no selectors", nil, nil, nil, "unknown:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := newFakeDNS(tt.zone)
			for name, err := range tt.errs {
				dns.errs[name] = err
			}
			rep := checkDKIM(context.Background(), lookupOf(dns), "example.com", tt.selectors)
			got := rep.State + ":"
			for _, s := range rep.Selectors {
				got += " " + s.State
			}
			if got != tt.want {
				t.Errorf("states = %q, want %q (%+v)", got, tt.want, rep.Selectors)
			}
		})
	}
}
