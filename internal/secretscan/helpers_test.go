package secretscan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// testKey is a GitHub signing key.
type testKey struct {
	id   string
	priv *ecdsa.PrivateKey
}

func newTestKey(t *testing.T, id string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{id: id, priv: priv}
}

func (k testKey) pem(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// sign returns the Github-Public-Key-Signature for body.
func (k testKey) sign(t *testing.T, body []byte) string {
	t.Helper()
	digest := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// keysServer is a fake https://api.github.com/meta/public_keys/secret_scanning.
type keysServer struct {
	*httptest.Server
	mu       sync.Mutex
	keys     []map[string]any
	status   int
	requests atomic.Int32
	// lastIfNoneMatch is the If-None-Match header of the last request.
	lastIfNoneMatch string
	lastAuth        string
}

func newKeysServer(t *testing.T, keys ...testKey) *keysServer {
	t.Helper()
	s := &keysServer{status: http.StatusOK}
	s.set(t, keys...)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.lastIfNoneMatch = r.Header.Get("If-None-Match")
		s.lastAuth = r.Header.Get("Authorization")
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			return
		}
		body, _ := json.Marshal(map[string]any{"public_keys": s.keys})
		etag := `W/"` + base64.StdEncoding.EncodeToString(sha256Sum(body)) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *keysServer) set(t *testing.T, keys ...testKey) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = nil
	for i, k := range keys {
		s.keys = append(s.keys, map[string]any{"key_identifier": k.id, "key": k.pem(t), "is_current": i == len(keys)-1})
	}
}

// last returns the If-None-Match and Authorization headers of the last
// request.
func (s *keysServer) last() (ifNoneMatch, auth string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastIfNoneMatch, s.lastAuth
}

func (s *keysServer) setStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// resolver is a fake Resolver keyed by the token's raw value.
type resolver struct {
	keys map[string]Key
	// gate, when set, blocks each call until it is closed.
	gate chan struct{}
	// failures makes the first n calls for a token fail.
	failures map[string]int

	mu       sync.Mutex
	calls    map[string]int
	tokens   []Token
	active   int
	maxAlive int
}

func (r *resolver) Resolve(ctx context.Context, t Token) (Key, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[t.Raw]++
	n := r.calls[t.Raw]
	r.tokens = append(r.tokens, t)
	r.active++
	r.maxAlive = max(r.maxAlive, r.active)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()

	if r.gate != nil {
		select {
		case <-r.gate:
		case <-ctx.Done():
			return Key{}, ctx.Err()
		}
	}
	if n <= r.failures[t.Raw] {
		return Key{}, errors.New("platform unavailable")
	}
	if k, ok := r.keys[t.Raw]; ok {
		return k, nil
	}
	return Key{}, ErrNotFound
}

func (r *resolver) seen() []Token {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Token(nil), r.tokens...)
}

// recorder is a Decider that records events.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
	fail   bool
}

func (r *recorder) Decide(_ context.Context, ev event.Event) (decision.Decision, error) {
	if r.fail {
		return decision.Decision{}, errors.New("engine down")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return decision.Decision{ID: "dec", Action: decision.Block}, nil
}

func (r *recorder) got() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.events...)
}

// outcomes counts reported outcomes.
type outcomes struct {
	mu sync.Mutex
	n  map[Outcome]int
}

func (o *outcomes) add(x Outcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n == nil {
		o.n = map[Outcome]int{}
	}
	o.n[x]++
}

func (o *outcomes) count(x Outcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n[x]
}

func newTestHandler(t *testing.T, cfg Config) *Handler {
	t.Helper()
	if cfg.Decider == nil {
		cfg.Decider = &recorder{}
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.retryBackoff = time.Millisecond
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})
	return h
}

func shutdown(t *testing.T, h *Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

type match struct {
	Token  string `json:"token"`
	Type   string `json:"type"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

func batch(t *testing.T, matches ...match) []byte {
	t.Helper()
	b, err := json.Marshal(matches)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// send posts body signed by key.
func send(t *testing.T, h http.Handler, key testKey, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, h, body, key.id, key.sign(t, body))
}

func sendWith(t *testing.T, h http.Handler, body []byte, keyID, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/secret-scanning/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if keyID != "" {
		req.Header.Set("Github-Public-Key-Identifier", keyID)
	}
	if sig != "" {
		req.Header.Set("Github-Public-Key-Signature", sig)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
