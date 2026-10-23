package secretscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

func TestBatchBecomesKeyLeakEvents(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &resolver{keys: map[string]Key{"acme_live_1": {APIKeyID: "key_1", AccountID: "acct_1"}}}
	var out outcomes
	h := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, OnOutcome: out.add})

	body := batch(t,
		match{Token: "acme_live_1", Type: "acme_api_key", URL: "https://github.com/octo/repo/blob/abc/config.yml", Source: "content"},
		match{Token: "acme_live_unknown", Type: "acme_api_key", Source: "commit"},
	)
	rec := send(t, h, key, body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("body %s, want an empty feedback array", rec.Body)
	}
	shutdown(t, h)

	evs := dec.got()
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	if ev.Type != event.KeyLeak || ev.APIKeyID != "key_1" || ev.AccountID != "acct_1" || ev.Time.IsZero() {
		t.Errorf("event %+v", ev)
	}
	if ev.Leak == nil || ev.Leak.Source != "github:content" || ev.Leak.URL != "https://github.com/octo/repo/blob/abc/config.yml" {
		t.Errorf("leak %+v", ev.Leak)
	}
	if ev.Attributes["secret_type"] != "acme_api_key" {
		t.Errorf("attributes %v", ev.Attributes)
	}
	seen := res.seen()
	if len(seen) != 2 {
		t.Fatalf("resolver saw %d tokens", len(seen))
	}
	for _, tok := range seen {
		if tok.SHA256 != hashOf(tok.Raw) {
			t.Errorf("token %s: sha256 %s, want %s", tok, tok.SHA256, hashOf(tok.Raw))
		}
	}
	if out.count(OutcomeAccepted) != 1 || out.count(OutcomeLeaked) != 1 || out.count(OutcomeNotFound) != 1 {
		t.Errorf("outcomes %v", out.n)
	}
}

// The payload, key and signature come from GitHub's own example:
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program#implement-signature-verification-in-your-secret-alert-service
func TestGitHubDocumentedSignature(t *testing.T) {
	const (
		payload = `[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]`
		keyID   = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c"
		sig     = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg=="
		keys    = `{"public_keys":[{"key_identifier":"bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c",` +
			`"key":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYAGMWO8XgCamYKMJS6jc/qgvSlAd\n` +
			`AjPuDPRcXU22YxgBrz+zoN19MzuRyW87qEt9/AmtoNP5GrobzUvQSyJFVw==\n-----END PUBLIC KEY-----\n","is_current":true}]}`
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(keys))
	}))
	defer srv.Close()
	res := &resolver{}
	h := newTestHandler(t, Config{Resolver: res, KeysURL: srv.URL})

	if rec := sendWith(t, h, []byte(payload), keyID, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	shutdown(t, h)
	seen := res.seen()
	if len(seen) != 1 || seen[0].Raw != "some_token" || seen[0].Type != "some_type" || seen[0].Source != "commit" || seen[0].URL != "https://example.com/base-repo-url/" {
		t.Fatalf("resolver saw %+v", seen)
	}

	h2 := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: srv.URL})
	if rec := sendWith(t, h2, []byte(payload+"\n"), keyID, sig); rec.Code != http.StatusUnauthorized {
		t.Errorf("re-serialized payload: status %d, want 401", rec.Code)
	}
}

func TestRejectsInvalidSignatures(t *testing.T) {
	key := newTestKey(t, "k1")
	other := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	body := batch(t, match{Token: "acme_live_1", Type: "acme_api_key", Source: "commit"})

	tests := []struct {
		name  string
		body  []byte
		keyID string
		sig   string
	}{
		{"no headers", body, "", ""},
		{"no signature", body, "k1", ""},
		{"no key id", body, "", key.sign(t, body)},
		{"signed by another key", body, "k1", other.sign(t, body)},
		{"tampered body", bytes.Replace(body, []byte("acme_live_1"), []byte("acme_live_2"), 1), "k1", key.sign(t, body)},
		{"not base64", body, "k1", "%%%"},
		{"not DER", body, "k1", "aGVsbG8="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &resolver{}
			var out outcomes
			h := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, OnOutcome: out.add})
			rec := sendWith(t, h, tt.body, tt.keyID, tt.sig)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
			shutdown(t, h)
			if len(res.seen()) != 0 || out.count(OutcomeInvalidSignature) != 1 {
				t.Error("a forged batch was processed")
			}
		})
	}
}

func TestRefreshesKeysOnUnknownKeyID(t *testing.T) {
	old := newTestKey(t, "old")
	rotated := newTestKey(t, "rotated")
	keys := newKeysServer(t, old)
	h := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL})
	body := batch(t, match{Token: "t", Type: "acme_api_key"})

	if rec := send(t, h, old, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	if n := keys.requests.Load(); n != 1 {
		t.Fatalf("%d key fetches, want 1", n)
	}
	if rec := send(t, h, old, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	if n := keys.requests.Load(); n != 1 {
		t.Fatalf("known key: %d key fetches, want the cached 1", n)
	}

	// GitHub rotates: a batch signed with a key Catraca has not seen yet.
	keys.set(t, old, rotated)
	h.keys.minRefresh = 0
	if rec := send(t, h, rotated, body); rec.Code != http.StatusAccepted {
		t.Fatalf("rotated key: status %d", rec.Code)
	}
	if n := keys.requests.Load(); n != 2 {
		t.Fatalf("%d key fetches, want 2", n)
	}
}

func TestUnknownKeyRefreshIsRateLimited(t *testing.T) {
	known := newTestKey(t, "known")
	keys := newKeysServer(t, known)
	h := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL})
	body := batch(t, match{Token: "t", Type: "acme_api_key"})
	if rec := send(t, h, known, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	for i := range 20 {
		forged := newTestKey(t, "forged-"+strconv.Itoa(i))
		if rec := send(t, h, forged, body); rec.Code != http.StatusUnauthorized {
			t.Fatalf("forged key %d: status %d, want 401", i, rec.Code)
		}
	}
	if n := keys.requests.Load(); n != 1 {
		t.Errorf("%d key fetches for 20 unknown key ids within the refresh interval, want 1", n)
	}
}

func TestKeysUnavailable(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	keys.setStatus(http.StatusInternalServerError)
	var out outcomes
	h := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL, OnOutcome: out.add})
	rec := send(t, h, key, batch(t, match{Token: "t"}))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	if strings.Contains(rec.Body.String(), "500") {
		t.Errorf("response leaks the upstream error: %s", rec.Body)
	}
	if out.count(OutcomeKeysUnavailable) != 1 {
		t.Errorf("outcomes %v", out.n)
	}
}

func TestMalformedBatch(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	for _, body := range []string{`not json`, `{"token":"t"}`, `[{"token":{"nested":true}}]`} {
		res := &resolver{}
		h := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL})
		if rec := send(t, h, key, []byte(body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
		shutdown(t, h)
		if len(res.seen()) != 0 {
			t.Errorf("%s: resolver called", body)
		}
	}
}

func TestBatchEdgeCases(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{}
	h := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL})

	if rec := send(t, h, key, []byte(`[]`)); rec.Code != http.StatusAccepted {
		t.Errorf("empty batch: status %d", rec.Code)
	}
	// A numeric token is kept; an empty one is skipped.
	if rec := send(t, h, key, []byte(`[{"token":12345,"type":"pin"},{"token":"","type":"x"}]`)); rec.Code != http.StatusAccepted {
		t.Errorf("status %d", rec.Code)
	}
	shutdown(t, h)
	if seen := res.seen(); len(seen) != 1 || seen[0].Raw != "12345" {
		t.Errorf("resolver saw %+v", seen)
	}
}

func TestRequestLimits(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	h := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL, MaxBodyBytes: 64})

	if rec := send(t, h, key, batch(t, match{Token: strings.Repeat("x", 100)})); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: status %d, want 413", rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET: status %d", rec.Code)
	}
}

type feedbackJSON struct {
	TokenHash string  `json:"token_hash"`
	TokenRaw  *string `json:"token_raw"`
	TokenType string  `json:"token_type"`
	Label     string  `json:"label"`
}

func TestFeedback(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{
		keys:     map[string]Key{"real": {APIKeyID: "key_1", AccountID: "acct_1"}},
		failures: map[string]int{"flaky": attempts},
	}
	h := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, Feedback: true})

	body := batch(t,
		match{Token: "real", Type: "acme_api_key", Source: "commit"},
		match{Token: "fake", Type: "acme_api_key", Source: "content"},
		match{Token: "flaky", Type: "acme_api_key", Source: "content"},
	)
	rec := send(t, h, key, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"real"`) || strings.Contains(rec.Body.String(), "token_raw") {
		t.Errorf("feedback carries a raw token: %s", rec.Body)
	}
	var got []feedbackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []feedbackJSON{
		{TokenHash: hashOf("real"), TokenType: "acme_api_key", Label: "true_positive"},
		{TokenHash: hashOf("fake"), TokenType: "acme_api_key", Label: "false_positive"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("feedback\n%+v\nwant\n%+v", got, want)
	}
}

func TestFeedbackDeadline(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &slowResolver{
		resolver: resolver{keys: map[string]Key{"fast": {APIKeyID: "key_fast"}, "slow": {APIKeyID: "key_slow"}}},
		slow:     "slow",
		release:  make(chan struct{}),
	}
	h := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, Feedback: true, FeedbackTimeout: 200 * time.Millisecond})

	start := time.Now()
	rec := send(t, h, key, batch(t, match{Token: "fast", Type: "t"}, match{Token: "slow", Type: "t"}))
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("answered after %v, want about the feedback timeout", elapsed)
	}
	var got []feedbackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TokenHash != hashOf("fast") {
		t.Fatalf("feedback %+v, want only the token resolved in time", got)
	}

	// The slow token still finishes after the answer.
	close(res.release)
	shutdown(t, h)
	if n := len(dec.got()); n != 2 {
		t.Errorf("decided %d leaks, want 2", n)
	}
}

// slowResolver blocks one token until release is closed.
type slowResolver struct {
	resolver
	slow    string
	release chan struct{}
}

func (r *slowResolver) Resolve(ctx context.Context, t Token) (Key, error) {
	if t.Raw == r.slow {
		select {
		case <-r.release:
		case <-ctx.Done():
			return Key{}, ctx.Err()
		}
	}
	return r.resolver.Resolve(ctx, t)
}

func TestLargeBatchAnswersBeforeProcessing(t *testing.T) {
	const n = 5000
	const workers = 4
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &resolver{keys: map[string]Key{}, gate: make(chan struct{})}
	matches := make([]match, n)
	for i := range matches {
		tok := "acme_live_" + strconv.Itoa(i)
		matches[i] = match{Token: tok, Type: "acme_api_key", Source: "content"}
		if i%10 == 0 {
			res.keys[tok] = Key{APIKeyID: "key_" + strconv.Itoa(i), AccountID: "acct"}
		}
	}
	var out outcomes
	h := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, Workers: workers, ResolveTimeout: time.Minute, OnOutcome: out.add})

	// The resolver is blocked, so the answer cannot wait for it.
	rec := send(t, h, key, batch(t, matches...))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	close(res.gate)
	shutdown(t, h)

	if got := len(res.seen()); got != n {
		t.Errorf("resolved %d tokens, want %d", got, n)
	}
	if got := len(dec.got()); got != n/10 {
		t.Errorf("decided %d leaks, want %d", got, n/10)
	}
	if res.maxAlive > workers {
		t.Errorf("%d resolves ran at once, want at most %d", res.maxAlive, workers)
	}
	if out.count(OutcomeLeaked)+out.count(OutcomeNotFound) != n {
		t.Errorf("outcomes %v", out.n)
	}
}

func TestOverloadedQueue(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{gate: make(chan struct{})}
	var out outcomes
	h := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, Workers: 1, MaxPending: 10, ResolveTimeout: time.Minute, OnOutcome: out.add})
	tokens := func(prefix string, n int) []byte {
		ms := make([]match, n)
		for i := range ms {
			ms[i] = match{Token: prefix + strconv.Itoa(i), Type: "t"}
		}
		return batch(t, ms...)
	}

	if rec := send(t, h, key, tokens("a", 8)); rec.Code != http.StatusAccepted {
		t.Fatalf("first batch: status %d", rec.Code)
	}
	rec := send(t, h, key, tokens("b", 5))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("batch over the limit: status %d, want 503 with Retry-After", rec.Code)
	}
	if rec := send(t, h, key, tokens("c", 2)); rec.Code != http.StatusAccepted {
		t.Fatalf("batch within the limit: status %d", rec.Code)
	}
	close(res.gate)
	shutdown(t, h)
	if out.count(OutcomeOverloaded) != 1 || len(res.seen()) != 10 {
		t.Errorf("outcomes %v, resolved %d", out.n, len(res.seen()))
	}

	// With nothing pending, a batch larger than the limit is still taken:
	// refusing it would refuse it forever.
	h2 := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL, MaxPending: 10})
	if rec := send(t, h2, key, tokens("d", 25)); rec.Code != http.StatusAccepted {
		t.Errorf("large batch on an idle handler: status %d", rec.Code)
	}
}

func TestShutdown(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)

	t.Run("refuses new batches", func(t *testing.T) {
		h := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL})
		shutdown(t, h)
		if rec := send(t, h, key, batch(t, match{Token: "t"})); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status %d, want 503", rec.Code)
		}
	})

	t.Run("aborts work when its context ends", func(t *testing.T) {
		res := &resolver{gate: make(chan struct{})}
		h := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, Workers: 1, ResolveTimeout: time.Minute})
		if rec := send(t, h, key, batch(t, match{Token: "a"}, match{Token: "b"}, match{Token: "c"})); rec.Code != http.StatusAccepted {
			t.Fatalf("status %d", rec.Code)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := h.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown = %v, want deadline exceeded", err)
		}
		// Work in flight is cancelled, queued tokens are dropped.
		deadline := time.Now().Add(5 * time.Second)
		for h.pending.Load() != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%d tokens still pending after the abort", h.pending.Load())
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func TestRetriesTransientResolverErrors(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &resolver{
		keys:     map[string]Key{"recovers": {APIKeyID: "key_1"}, "broken": {APIKeyID: "key_2"}},
		failures: map[string]int{"recovers": attempts - 1, "broken": attempts},
	}
	var out outcomes
	h := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, OnOutcome: out.add})
	send(t, h, key, batch(t, match{Token: "recovers"}, match{Token: "broken"}))
	shutdown(t, h)
	if evs := dec.got(); len(evs) != 1 || evs[0].APIKeyID != "key_1" {
		t.Errorf("events %+v", evs)
	}
	if res.calls["broken"] != attempts || out.count(OutcomeResolveFailed) != 1 {
		t.Errorf("broken token: %d calls, outcomes %v", res.calls["broken"], out.n)
	}
}

func TestDecideFailure(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	var out outcomes
	h := newTestHandler(t, Config{
		Decider:  &recorder{fail: true},
		Resolver: &resolver{keys: map[string]Key{"real": {APIKeyID: "key_1"}}},
		KeysURL:  keys.URL, Feedback: true, OnOutcome: out.add,
	})
	rec := send(t, h, key, batch(t, match{Token: "real", Type: "t"}))
	// The key is real even though the decision failed.
	if !strings.Contains(rec.Body.String(), "true_positive") {
		t.Errorf("feedback %s, want true_positive", rec.Body)
	}
	shutdown(t, h)
	if out.count(OutcomeDecideFailed) != 1 {
		t.Errorf("outcomes %v", out.n)
	}
}

// validatingDecider refuses invalid events as the engine does, and counts
// its calls.
type validatingDecider struct{ calls atomic.Int32 }

func (d *validatingDecider) Decide(_ context.Context, ev event.Event) (decision.Decision, error) {
	d.calls.Add(1)
	if err := ev.Validate(); err != nil {
		return decision.Decision{}, err
	}
	return decision.Decision{ID: "dec", Action: decision.Block}, nil
}

func TestRefusedEventIsNotRetried(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &validatingDecider{}
	var out outcomes
	h := newTestHandler(t, Config{
		Decider:  dec,
		Resolver: &resolver{keys: map[string]Key{"real": {APIKeyID: "key\x00one"}}},
		KeysURL:  keys.URL, OnOutcome: out.add,
	})
	send(t, h, key, batch(t, match{Token: "real", Type: "t"}))
	shutdown(t, h)
	if n := dec.calls.Load(); n != 1 {
		t.Errorf("Decide called %d times, want 1: a refused event is refused again", n)
	}
	if out.count(OutcomeDecideFailed) != 1 {
		t.Errorf("outcomes %v", out.n)
	}
}

func TestTokenNeverPrinted(t *testing.T) {
	tok := Token{Raw: "acme_live_SECRET", SHA256: hashOf("acme_live_SECRET"), Type: "acme_api_key", URL: "https://github.com/x", Source: "commit"}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("leak", "token", tok)
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %s %#v", tok, tok, tok, tok), logs.String()} {
		if strings.Contains(s, "SECRET") {
			t.Errorf("raw token printed: %s", s)
		}
	}
	if !strings.Contains(logs.String(), "acme_api_key") {
		t.Errorf("log lost the token type: %s", logs.String())
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{Resolver: &resolver{}}); err == nil {
		t.Error("no decider: want an error")
	}
	if _, err := New(Config{Decider: &recorder{}}); err == nil {
		t.Error("no resolver: want an error")
	}
}
