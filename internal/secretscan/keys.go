package secretscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// DefaultKeysURL lists the keys GitHub signs secret scanning alerts with.
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program#implement-signature-verification-in-your-secret-alert-service
const DefaultKeysURL = "https://api.github.com/meta/public_keys/secret_scanning"

// Signature headers GitHub sends with every alert.
const (
	keyIDHeader     = "Github-Public-Key-Identifier"
	signatureHeader = "Github-Public-Key-Signature"
)

var (
	errUnknownKey      = errors.New("secretscan: unknown key identifier")
	errKeysUnavailable = errors.New("secretscan: GitHub public keys unavailable")
	errBadSignature    = errors.New("secretscan: invalid signature")
)

// keyring caches GitHub's public keys. It refreshes them when they are older
// than maxAge or when a request names a key it does not know, at most once
// per minRefresh, so a flood of forged key ids cannot turn into a flood of
// requests to GitHub.
type keyring struct {
	url        string
	token      string
	client     *http.Client
	maxAge     time.Duration
	minRefresh time.Duration
	log        *slog.Logger
	now        func() time.Time

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	etag      string
	fetchedAt time.Time // last successful fetch, 304 included
	triedAt   time.Time // last attempt
}

// verify checks signature (base64 DER ECDSA) over the raw body with the key
// named keyID: ECDSA-NIST-P256V1-SHA256.
func (k *keyring) verify(ctx context.Context, keyID, signature string, body []byte) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errBadSignature
	}
	pub, err := k.key(ctx, keyID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errBadSignature
	}
	return nil
}

func (k *keyring) key(ctx context.Context, id string) (*ecdsa.PublicKey, error) {
	k.mu.RLock()
	pub, ok := k.keys[id]
	fresh := k.now().Sub(k.fetchedAt) < k.maxAge
	k.mu.RUnlock()
	if ok && fresh {
		return pub, nil
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if pub, ok := k.keys[id]; ok && now.Sub(k.fetchedAt) < k.maxAge {
		return pub, nil
	}
	if k.triedAt.IsZero() || now.Sub(k.triedAt) >= k.minRefresh {
		k.triedAt = now
		if err := k.refresh(ctx); err != nil {
			// Stale keys are better than none while GitHub's API is down.
			k.log.WarnContext(ctx, "secretscan: refreshing GitHub public keys", "error", err)
			if k.keys == nil {
				return nil, errKeysUnavailable
			}
		}
	}
	if pub, ok := k.keys[id]; ok {
		return pub, nil
	}
	if k.keys == nil {
		return nil, errKeysUnavailable
	}
	return nil, errUnknownKey
}

// githubKeys is the keys endpoint's response.
type githubKeys struct {
	PublicKeys []struct {
		KeyIdentifier string `json:"key_identifier"`
		Key           string `json:"key"`
		IsCurrent     bool   `json:"is_current"`
	} `json:"public_keys"`
}

// refresh fetches the keys. It sends If-None-Match so an unchanged list
// costs no rate limit, as GitHub suggests:
// https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests
// The caller holds k.mu. The fetch is detached from the request that
// triggered it, so a client that hangs up cannot make it fail and delay the
// next attempt by minRefresh.
func (k *keyring) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}
	if k.etag != "" && k.keys != nil {
		req.Header.Set("If-None-Match", k.etag)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		k.fetchedAt = k.now()
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("keys endpoint returned %s", resp.Status)
	}
	var doc githubKeys
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("decoding keys: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(doc.PublicKeys))
	for _, entry := range doc.PublicKeys {
		pub, err := parseP256Key(entry.Key)
		if err != nil {
			k.log.WarnContext(ctx, "secretscan: skipping GitHub public key", "key_identifier", entry.KeyIdentifier, "error", err)
			continue
		}
		keys[entry.KeyIdentifier] = pub
	}
	if len(keys) == 0 {
		return errors.New("keys endpoint returned no usable key")
	}
	k.keys = keys
	k.etag = resp.Header.Get("ETag")
	k.fetchedAt = k.now()
	return nil
}

func parseP256Key(s string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 key")
	}
	return pub, nil
}
