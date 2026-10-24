package secretscan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// GitHub's documented example, as in TestGitHubDocumentedSignature:
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program#implement-signature-verification-in-your-secret-alert-service
const (
	docPayload = `[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]`
	docKeyID   = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c"
	docSig     = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg=="
	docKey     = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYAGMWO8XgCamYKMJS6jc/qgvSlAd\n" +
		"AjPuDPRcXU22YxgBrz+zoN19MzuRyW87qEt9/AmtoNP5GrobzUvQSyJFVw==\n-----END PUBLIC KEY-----\n"
)

// fuzzKeyring returns a keyring that holds GitHub's documented key and a
// key of the test's own, under fuzzKeyID. A refresh, for a key id it does
// not know, fails without a network.
func fuzzKeyring(tb testing.TB) (*keyring, *ecdsa.PrivateKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	doc, err := parseP256Key(docKey)
	if err != nil {
		tb.Fatal(err)
	}
	offline := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}
	return &keyring{
		url: "https://api.github.invalid/keys", client: offline, maxAge: 24 * time.Hour, minRefresh: time.Hour,
		log: slog.New(slog.DiscardHandler), now: time.Now, fetchedAt: time.Now(),
		keys: map[string]*ecdsa.PublicKey{docKeyID: doc, fuzzKeyID: &priv.PublicKey},
	}, priv
}

const fuzzKeyID = "fuzz-key"

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FuzzGitHubBatch signs any body as GitHub does and checks the signature
// holds for it and for no other body, then turns what decodes into reports:
// one per match with a token, keyed and hashed as documented, with values
// that fit an event and a raw token that opens only under its own report.
func FuzzGitHubBatch(f *testing.F) {
	for _, seed := range []string{
		docPayload,
		`[{"token":12345,"type":"pin"},{"token":"","type":"x"}]`,
		`[{"token":"odd","type":"` + strings.Repeat("t", 300) + `","url":"https://github.com/\u0000octo","source":"commit"}]`,
		`[{"token":"a","type":"t","source":"s","url":"u"},{"token":"a","type":"t","source":"s","url":"u"}]`,
		`[{"token":"\ud800","type":"é́","source":"issue_comment\n","url":"https://github.com/o/r/blob/` + strings.Repeat("é", 5000) + `"}]`,
		`[{"token":1e400}]`,
		`[{"token":null,"type":null}]`,
		`{"token":"t"}`,
		`not json`,
	} {
		f.Add([]byte(seed), []byte(seed+"\n"))
	}
	kr, priv := fuzzKeyring(f)
	sealer, err := newSealer("resolver-secret-0123456789abcdef")
	if err != nil {
		f.Fatal(err)
	}
	h := &Handler{now: time.Now, seal: sealer}
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, body, other []byte) {
		digest := sha256.Sum256(body)
		der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := base64.StdEncoding.EncodeToString(der)
		if err := kr.verify(ctx, fuzzKeyID, sig, body); err != nil {
			t.Fatalf("verify of a signed body: %v", err)
		}
		if !bytes.Equal(other, body) {
			if err := kr.verify(ctx, fuzzKeyID, sig, other); !errors.Is(err, errBadSignature) {
				t.Fatalf("verify of another body = %v, want errBadSignature", err)
			}
		}

		var alerts []alert
		if json.Unmarshal(body, &alerts) != nil {
			return
		}
		tokens, reports := h.newReports(alerts)
		want := 0
		for _, a := range alerts {
			if a.Token != "" {
				want++
			}
		}
		if len(tokens) != want || len(reports) != want {
			t.Fatalf("%d tokens and %d reports for %d matches with a token", len(tokens), len(reports), want)
		}
		for i, rep := range reports {
			tok := tokens[i]
			sum := sha256.Sum256([]byte(tok.Raw))
			if tok.SHA256 != hex.EncodeToString(sum[:]) || rep.TokenSHA256 != tok.SHA256 || rep.Key != reportKey(tok) {
				t.Errorf("report %d: hash %s, key %s for token %+v", i, rep.TokenSHA256, rep.Key, tok)
			}
			for _, v := range []struct {
				s     string
				limit int
			}{{rep.Type, event.MaxIDBytes}, {rep.Source, event.MaxIDBytes}, {rep.URL, event.MaxTextBytes}} {
				if len(v.s) > v.limit || !utf8.ValidString(v.s) || strings.ContainsRune(v.s, 0) {
					t.Errorf("report %d: %q does not fit %d bytes of UTF-8 without NUL", i, v.s, v.limit)
				}
			}
			// The event a report becomes is refused at every attempt if it
			// is invalid, so whatever GitHub sends must make a valid one.
			if err := leakEvent(rep, Key{APIKeyID: "key_1", AccountID: "acct_1"}).Validate(); err != nil {
				t.Errorf("report %d makes an invalid event: %v", i, err)
			}
			raw, err := sealer.open(rep.SealedToken, rep.Key)
			if err != nil || raw != tok.Raw {
				t.Errorf("report %d: sealed token opens to %q, %v; want %q", i, raw, err, tok.Raw)
			}
			if _, err := sealer.open(rep.SealedToken, rep.Key+"x"); !errors.Is(err, errUnseal) {
				t.Errorf("report %d: sealed token opens under another report: %v", i, err)
			}
		}
	})
}

// FuzzGitHubSignature verifies any signature, key id and body against the
// keyring: nothing panics, an error is one of the keyring's, and only
// GitHub's documented example verifies.
func FuzzGitHubSignature(f *testing.F) {
	f.Add(docKeyID, docSig, []byte(docPayload))
	f.Add(docKeyID, docSig, []byte(docPayload+" "))
	f.Add("unknown", docSig, []byte(docPayload))
	f.Add(docKeyID, "not base64!", []byte(docPayload))
	f.Add(docKeyID, "MAYCAQACAQA=", []byte(docPayload))
	f.Add(fuzzKeyID, "", []byte(nil))
	kr, _ := fuzzKeyring(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, keyID, sig string, body []byte) {
		err := kr.verify(ctx, keyID, sig, body)
		switch {
		case err == nil && (keyID != docKeyID || string(body) != docPayload):
			t.Fatalf("verified a body GitHub did not sign, with key %q and signature %q", keyID, sig)
		case err != nil && !errors.Is(err, errBadSignature) && !errors.Is(err, errUnknownKey):
			t.Fatalf("verify = %v, not one of the keyring's errors", err)
		}
	})
}

// FuzzSeal seals a raw token and opens it: it opens under its own report
// with the same secret, and not when the report, the secret or a single bit
// of what was sealed differs. Opening anything else never panics.
func FuzzSeal(f *testing.F) {
	f.Add("resolver-secret-0123456789abcdef", "acme_live_SECRET", "report-1", "report-2", "another-secret", uint16(0), "v1:AAAA")
	f.Add("s", "", "", "k", "s\x00", uint16(300), "v1:%%%")
	f.Add("s", strings.Repeat("x", 4096), "k", "", "t", uint16(65535), "v2:"+strings.Repeat("A", 40))
	f.Fuzz(func(t *testing.T, secret, raw, key, otherKey, otherSecret string, bit uint16, junk string) {
		s, err := newSealer(secret)
		if err != nil {
			t.Fatal(err)
		}
		sealed := s.seal(raw, key)
		if got, err := s.open(sealed, key); err != nil || got != raw {
			t.Fatalf("open(seal(%q)) = %q, %v", raw, got, err)
		}
		if otherKey != key {
			if _, err := s.open(sealed, otherKey); !errors.Is(err, errUnseal) {
				t.Errorf("opened under another report: %v", err)
			}
		}
		if otherSecret != secret {
			other, err := newSealer(otherSecret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := other.open(sealed, key); !errors.Is(err, errUnseal) {
				t.Errorf("opened with another secret: %v", err)
			}
		}
		b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, sealVersion))
		if err != nil {
			t.Fatal(err)
		}
		b[int(bit/8)%len(b)] ^= 1 << (bit % 8)
		if got, err := s.open(sealVersion+base64.RawStdEncoding.EncodeToString(b), key); !errors.Is(err, errUnseal) {
			t.Errorf("opened with bit %d flipped: %q, %v", bit, got, err)
		}
		// Only a sealing made with the secret, for the report, opens.
		if got, err := s.open(junk, key); err == nil {
			t.Errorf("junk %q opened to %q", junk, got)
		}
	})
}
