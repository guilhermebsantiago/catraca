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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
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

// resolver is a fake Resolver. Tests name tokens by their raw value; it
// finds them by hash, as a platform that stores key hashes does, since the
// raw token reaches a Resolver only with Config.RawTokenSecret.
type resolver struct {
	keys map[string]Key
	// gate, when set, blocks each call until it is closed.
	gate chan struct{}
	// failures makes the first n calls for a token fail.
	failures map[string]int

	mu       sync.Mutex
	calls    map[string]int // by hash
	tokens   []Token
	active   int
	maxAlive int
}

func (r *resolver) Resolve(ctx context.Context, t Token) (Key, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[t.SHA256]++
	n := r.calls[t.SHA256]
	r.tokens = append(r.tokens, t)
	r.active++
	r.maxAlive = max(r.maxAlive, r.active)
	raw := r.rawOf(t)
	fail := n <= r.failures[raw]
	k, known := r.keys[raw]
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
	switch {
	case fail:
		return Key{}, errors.New("platform unavailable")
	case known:
		return k, nil
	}
	return Key{}, ErrNotFound
}

// setFailures changes how many calls for the token named raw fail.
func (r *resolver) setFailures(raw string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures[raw] = n
}

// rawOf returns the raw token the test named t by, or "" for a token it
// does not know.
func (r *resolver) rawOf(t Token) string {
	for raw := range r.keys {
		if hashOf(raw) == t.SHA256 {
			return raw
		}
	}
	for raw := range r.failures {
		if hashOf(raw) == t.SHA256 {
			return raw
		}
	}
	return ""
}

// callsFor returns how many times the token named raw was resolved.
func (r *resolver) callsFor(raw string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[hashOf(raw)]
}

// running returns how many calls are in progress.
func (r *resolver) running() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

func (r *resolver) seen() []Token {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Token(nil), r.tokens...)
}

// recorder is a Decider that records events. Its first failures calls fail,
// and every call fails when fail is set.
type recorder struct {
	mu       sync.Mutex
	events   []event.Event
	calls    []event.Event
	fail     bool
	failures int
}

func (r *recorder) Decide(_ context.Context, ev event.Event) (decision.Decision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, ev)
	if r.fail || len(r.calls) <= r.failures {
		return decision.Decision{}, errors.New("engine down")
	}
	r.events = append(r.events, ev)
	return decision.Decision{ID: "dec_" + ev.ID, EventID: ev.ID, Action: decision.Block}, nil
}

// got returns the events decided.
func (r *recorder) got() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.events...)
}

// tried returns every event Decide was called with.
func (r *recorder) tried() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.calls...)
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

func (o *outcomes) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	b, _ := json.Marshal(o.n)
	return string(b)
}

// openReports opens a queue in a SQLite database of its own, closed when
// the test ends, after the handlers using it are shut down.
func openReports(t *testing.T) *audit.DB {
	t.Helper()
	db, err := audit.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "audit.db"),
		audit.Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(context.Background()) })
	return db
}

// newTestHandler returns a handler whose retries and polls take
// milliseconds, on cfg.Reports or a queue of its own, and shuts it down when
// the test ends.
func newTestHandler(t *testing.T, cfg Config) (*Handler, *audit.DB) {
	t.Helper()
	db, _ := cfg.Reports.(*audit.DB)
	if cfg.Reports == nil {
		db = openReports(t)
		cfg.Reports = db
	}
	if cfg.Decider == nil {
		cfg.Decider = &recorder{}
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff, cfg.MaxBackoff = time.Millisecond, time.Millisecond
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Millisecond
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})
	return h, db
}

func shutdown(t *testing.T, h *Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// eventually polls ok until it holds, failing the test after a generous
// deadline: the machine running the tests may be busy.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settled waits until no report in db is pending.
func settled(t *testing.T, db *audit.DB) {
	t.Helper()
	eventually(t, "every report to be done or dead", func() bool {
		s, err := db.LeakReportStats(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return s.Pending == 0
	})
}

// stored returns the report of the token named raw, found at url.
func stored(t *testing.T, db *audit.DB, raw, typ, source, url string) audit.LeakReport {
	t.Helper()
	key := reportKey(Token{SHA256: hashOf(raw), Type: typ, Source: source, URL: url})
	rs, err := db.LeakReportsByKey(context.Background(), []string{key})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 {
		t.Fatalf("no report stored for token %s", raw)
	}
	return rs[0]
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
