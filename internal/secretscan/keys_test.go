package secretscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

func newTestKeyring(url string, now *time.Time) *keyring {
	return &keyring{
		url:        url,
		token:      "ghp_test",
		client:     &http.Client{Timeout: 5 * time.Second},
		maxAge:     time.Hour,
		minRefresh: time.Minute,
		log:        slog.New(slog.DiscardHandler),
		now:        func() time.Time { return *now },
	}
}

func TestKeyringConditionalRefresh(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := newKeysServer(t, key)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	k := newTestKeyring(srv.URL, &now)
	ctx := context.Background()
	body := []byte(`[]`)

	if err := k.verify(ctx, "k1", key.sign(t, body), body); err != nil {
		t.Fatal(err)
	}
	ifNoneMatch, auth := srv.last()
	if auth != "Bearer ghp_test" {
		t.Errorf("Authorization %q, want the GitHub token", auth)
	}
	if ifNoneMatch != "" {
		t.Errorf("first fetch sent If-None-Match %q", ifNoneMatch)
	}

	// Past maxAge the keys are revalidated with the ETag; a 304 keeps them.
	now = now.Add(2 * time.Hour)
	if err := k.verify(ctx, "k1", key.sign(t, body), body); err != nil {
		t.Fatal(err)
	}
	if ifNoneMatch, _ := srv.last(); srv.requests.Load() != 2 || ifNoneMatch == "" {
		t.Fatalf("%d fetches, If-None-Match %q; want a conditional second fetch", srv.requests.Load(), ifNoneMatch)
	}
	if !k.fetchedAt.Equal(now) {
		t.Errorf("a 304 did not renew the keys")
	}
}

func TestKeyringKeepsStaleKeysWhenGitHubIsDown(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := newKeysServer(t, key)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	k := newTestKeyring(srv.URL, &now)
	ctx := context.Background()
	body := []byte(`[]`)
	if err := k.verify(ctx, "k1", key.sign(t, body), body); err != nil {
		t.Fatal(err)
	}

	srv.setStatus(http.StatusBadGateway)
	now = now.Add(3 * time.Hour)
	if err := k.verify(ctx, "k1", key.sign(t, body), body); err != nil {
		t.Fatalf("stale key rejected while GitHub is down: %v", err)
	}
	if err := k.verify(ctx, "k2", key.sign(t, body), body); !errors.Is(err, errUnknownKey) {
		t.Fatalf("unknown key: %v, want errUnknownKey", err)
	}
}

func TestKeyringRetriesAfterInterval(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := newKeysServer(t, key)
	srv.setStatus(http.StatusServiceUnavailable)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	k := newTestKeyring(srv.URL, &now)
	ctx := context.Background()
	body := []byte(`[]`)

	if err := k.verify(ctx, "k1", key.sign(t, body), body); !errors.Is(err, errKeysUnavailable) {
		t.Fatalf("got %v, want errKeysUnavailable", err)
	}
	srv.setStatus(http.StatusOK)
	if err := k.verify(ctx, "k1", key.sign(t, body), body); !errors.Is(err, errKeysUnavailable) {
		t.Fatalf("within the interval: got %v, want errKeysUnavailable without a fetch", err)
	}
	if srv.requests.Load() != 1 {
		t.Fatalf("%d fetches within the interval, want 1", srv.requests.Load())
	}
	now = now.Add(time.Minute)
	if err := k.verify(ctx, "k1", key.sign(t, body), body); err != nil {
		t.Fatalf("after the interval: %v", err)
	}
}

func TestKeyringSkipsUnusableKeys(t *testing.T) {
	good := newTestKey(t, "good")
	srv := newKeysServer(t, good)
	srv.mu.Lock()
	srv.keys = append(srv.keys,
		map[string]any{"key_identifier": "garbage", "key": "not a pem"},
		map[string]any{"key_identifier": "p384", "key": p384KeyPEM(t)},
	)
	srv.mu.Unlock()
	now := time.Now()
	k := newTestKeyring(srv.URL, &now)
	body := []byte(`[]`)
	if err := k.verify(context.Background(), "good", good.sign(t, body), body); err != nil {
		t.Fatal(err)
	}
	if len(k.keys) != 1 {
		t.Errorf("kept %d keys, want only the P-256 one", len(k.keys))
	}
}

// p384KeyPEM returns an ECDSA key on the wrong curve for GitHub's
// ECDSA-NIST-P256V1-SHA256 signatures.
func p384KeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
