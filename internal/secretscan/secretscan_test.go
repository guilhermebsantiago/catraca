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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

func TestBatchBecomesKeyLeakEvents(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &resolver{keys: map[string]Key{"acme_live_1": {APIKeyID: "key_1", AccountID: "acct_1"}}}
	var out outcomes
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, OnOutcome: out.add})

	const url = "https://github.com/octo/repo/blob/abc/config.yml"
	body := batch(t,
		match{Token: "acme_live_1", Type: "acme_api_key", URL: url, Source: "content"},
		match{Token: "acme_live_unknown", Type: "acme_api_key", Source: "commit"},
	)
	rec := send(t, h, key, body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("body %s, want an empty feedback array", rec.Body)
	}
	settled(t, db)

	evs := dec.got()
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	leaked := stored(t, db, "acme_live_1", "acme_api_key", "content", url)
	if ev.Type != event.KeyLeak || ev.APIKeyID != "key_1" || ev.AccountID != "acct_1" || !ev.Time.Equal(leaked.ReceivedAt) ||
		ev.ID != "ghss_"+leaked.Key[:32] {
		t.Errorf("event %+v", ev)
	}
	if ev.Leak == nil || ev.Leak.Source != "github:content" || ev.Leak.URL != url {
		t.Errorf("leak %+v", ev.Leak)
	}
	if ev.Attributes["secret_type"] != "acme_api_key" {
		t.Errorf("attributes %v", ev.Attributes)
	}
	if leaked.Status != audit.LeakReportDone || leaked.Outcome != "leaked" || leaked.DecisionID != "dec_"+ev.ID ||
		leaked.APIKeyID != "key_1" || leaked.SealedToken != "" {
		t.Errorf("leaked report %+v", leaked)
	}
	if r := stored(t, db, "acme_live_unknown", "acme_api_key", "commit", ""); r.Status != audit.LeakReportDone || r.Outcome != "not_found" {
		t.Errorf("unknown report %+v", r)
	}
	seen := res.seen()
	if len(seen) != 2 {
		t.Fatalf("resolver saw %d tokens", len(seen))
	}
	for _, tok := range seen {
		if tok.Raw != "" {
			t.Errorf("token %s: the resolver got the raw token without RawTokenSecret", tok)
		}
	}
	if out.count(OutcomeAccepted) != 1 || out.count(OutcomeLeaked) != 1 || out.count(OutcomeNotFound) != 1 {
		t.Errorf("outcomes %v", &out)
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
	h, db := newTestHandler(t, Config{Resolver: res, KeysURL: srv.URL})

	if rec := sendWith(t, h, []byte(payload), keyID, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	settled(t, db)
	seen := res.seen()
	if len(seen) != 1 || seen[0].SHA256 != hashOf("some_token") || seen[0].Type != "some_type" || seen[0].Source != "commit" ||
		seen[0].URL != "https://example.com/base-repo-url/" {
		t.Fatalf("resolver saw %+v", seen)
	}

	h2, _ := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: srv.URL})
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
			h, db := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, OnOutcome: out.add})
			rec := sendWith(t, h, tt.body, tt.keyID, tt.sig)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
			shutdown(t, h)
			if len(res.seen()) != 0 || out.count(OutcomeInvalidSignature) != 1 {
				t.Error("a forged batch was processed")
			}
			if rs, _ := db.ListLeakReports(context.Background(), audit.LeakReportFilter{}); len(rs) != 0 {
				t.Errorf("a forged batch was stored: %+v", rs)
			}
		})
	}
}

func TestRefreshesKeysOnUnknownKeyID(t *testing.T) {
	old := newTestKey(t, "old")
	rotated := newTestKey(t, "rotated")
	keys := newKeysServer(t, old)
	h, _ := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL})
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
	h, _ := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL})
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
	h, _ := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL, OnOutcome: out.add})
	rec := send(t, h, key, batch(t, match{Token: "t"}))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	if strings.Contains(rec.Body.String(), "500") {
		t.Errorf("response leaks the upstream error: %s", rec.Body)
	}
	if out.count(OutcomeKeysUnavailable) != 1 {
		t.Errorf("outcomes %v", &out)
	}
}

func TestMalformedBatch(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	for _, body := range []string{`not json`, `{"token":"t"}`, `[{"token":{"nested":true}}]`} {
		res := &resolver{}
		h, _ := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL})
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
	res := &resolver{keys: map[string]Key{"odd": {APIKeyID: "key_odd"}}}
	dec := &recorder{}
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL})

	if rec := send(t, h, key, []byte(`[]`)); rec.Code != http.StatusAccepted {
		t.Errorf("empty batch: status %d", rec.Code)
	}
	// A numeric token is kept; an empty one is skipped.
	if rec := send(t, h, key, []byte(`[{"token":12345,"type":"pin"},{"token":"","type":"x"}]`)); rec.Code != http.StatusAccepted {
		t.Errorf("status %d", rec.Code)
	}
	// A NUL byte or an oversized value would make the event invalid, and
	// refuse its report at every attempt.
	odd := fmt.Sprintf(`[{"token":"odd","type":%q,"url":"https://github.com/\u0000octo","source":"commit"}]`, strings.Repeat("t", 300))
	if rec := send(t, h, key, []byte(odd)); rec.Code != http.StatusAccepted {
		t.Errorf("status %d", rec.Code)
	}
	settled(t, db)
	if seen := res.seen(); len(seen) != 2 || res.callsFor("12345") != 1 {
		t.Errorf("resolver saw %+v, want the numeric token and the odd one", seen)
	}
	evs := dec.got()
	if len(evs) != 1 || evs[0].Leak.URL != "https://github.com/octo" || len(evs[0].Attributes["secret_type"]) != event.MaxIDBytes {
		t.Fatalf("events %+v", evs)
	}
	if err := evs[0].Validate(); err != nil {
		t.Error(err)
	}
}

func TestRequestLimits(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	h, _ := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL, MaxBodyBytes: 64})

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

func feedbackOf(t *testing.T, rec *httptest.ResponseRecorder) []feedbackJSON {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var got []feedbackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestFeedback(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{
		keys:     map[string]Key{"real": {APIKeyID: "key_1", AccountID: "acct_1"}},
		failures: map[string]int{"flaky": 1000},
	}
	// The flaky token dies at its second attempt, which ends the wait for
	// it well before the feedback timeout.
	h, _ := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, Feedback: true, MaxAttempts: 2, FeedbackTimeout: time.Minute})

	body := batch(t,
		match{Token: "real", Type: "acme_api_key", Source: "commit"},
		match{Token: "fake", Type: "acme_api_key", Source: "content"},
		match{Token: "flaky", Type: "acme_api_key", Source: "content"},
	)
	rec := send(t, h, key, body)
	if strings.Contains(rec.Body.String(), `"real"`) || strings.Contains(rec.Body.String(), "token_raw") {
		t.Errorf("feedback carries a raw token: %s", rec.Body)
	}
	want := []feedbackJSON{
		{TokenHash: hashOf("real"), TokenType: "acme_api_key", Label: "true_positive"},
		{TokenHash: hashOf("fake"), TokenType: "acme_api_key", Label: "false_positive"},
	}
	if got := feedbackOf(t, rec); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("feedback\n%+v\nwant\n%+v", got, want)
	}
}

func TestFeedbackDeadline(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &slowResolver{
		resolver: resolver{keys: map[string]Key{"fast": {APIKeyID: "key_fast"}, "slow": {APIKeyID: "key_slow"}}},
		slow:     hashOf("slow"),
		release:  make(chan struct{}),
	}
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, Feedback: true,
		FeedbackTimeout: 2 * time.Second, ResolveTimeout: time.Minute})

	got := feedbackOf(t, send(t, h, key, batch(t, match{Token: "fast", Type: "t"}, match{Token: "slow", Type: "t"})))
	if len(got) != 1 || got[0].TokenHash != hashOf("fast") {
		t.Fatalf("feedback %+v, want only the token resolved in time", got)
	}

	// The slow token still finishes after the answer.
	close(res.release)
	settled(t, db)
	if n := len(dec.got()); n != 2 {
		t.Errorf("decided %d leaks, want 2", n)
	}
}

// slowResolver blocks the token with hash slow until release is closed.
type slowResolver struct {
	resolver
	slow    string
	release chan struct{}
}

func (r *slowResolver) Resolve(ctx context.Context, t Token) (Key, error) {
	if t.SHA256 == r.slow {
		select {
		case <-r.release:
		case <-ctx.Done():
			return Key{}, ctx.Err()
		}
	}
	return r.resolver.Resolve(ctx, t)
}

func TestLargeBatchIsStoredBeforeTheAnswer(t *testing.T) {
	const n = 1000
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
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, Workers: workers,
		ResolveTimeout: time.Minute, OnOutcome: out.add})

	// The resolver is blocked, so the answer cannot wait for it, and every
	// report is stored by the time it comes.
	rec := send(t, h, key, batch(t, matches...))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	if s, err := db.LeakReportStats(context.Background()); err != nil || s.Pending != n {
		t.Fatalf("stats after the answer = %+v, %v; want %d pending", s, err, n)
	}
	close(res.gate)
	settled(t, db)

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
		t.Errorf("outcomes %v", &out)
	}
}

// failingReports is a queue that cannot store anything, like an audit
// database that is not open yet.
type failingReports struct{ audit.LeakReports }

func (failingReports) AddLeakReports(context.Context, []audit.LeakReport) (int, error) {
	return 0, errors.New("the audit database is not open yet")
}

func (failingReports) ClaimLeakReports(ctx context.Context, _ time.Time, _ int, _ time.Duration) ([]audit.LeakReport, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestAnswers503WhenReportsCannotBeStored checks that a batch is never
// acknowledged before its reports are stored: GitHub must send it again.
func TestAnswers503WhenReportsCannotBeStored(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{}
	var out outcomes
	for _, feedback := range []bool{false, true} {
		h, _ := newTestHandler(t, Config{Resolver: res, Reports: failingReports{}, KeysURL: keys.URL, Feedback: feedback, OnOutcome: out.add})
		rec := send(t, h, key, batch(t, match{Token: "t", Type: "acme_api_key"}))
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Errorf("feedback %t: status %d, Retry-After %q; want 503 with Retry-After", feedback, rec.Code, rec.Header().Get("Retry-After"))
		}
		if strings.Contains(rec.Body.String(), "not open") {
			t.Errorf("response leaks the error: %s", rec.Body)
		}
	}
	if out.count(OutcomeUnavailable) != 2 || out.count(OutcomeAccepted) != 0 || len(res.seen()) != 0 {
		t.Errorf("outcomes %v, resolver saw %d tokens", &out, len(res.seen()))
	}
}

func TestShutdown(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)

	t.Run("refuses new batches", func(t *testing.T) {
		h, _ := newTestHandler(t, Config{Resolver: &resolver{}, KeysURL: keys.URL})
		shutdown(t, h)
		if rec := send(t, h, key, batch(t, match{Token: "t"})); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status %d, want 503", rec.Code)
		}
	})

	t.Run("aborts work when its context ends", func(t *testing.T) {
		res := &resolver{gate: make(chan struct{})}
		h, db := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, Workers: 1, ResolveTimeout: time.Minute})
		if rec := send(t, h, key, batch(t, match{Token: "a"}, match{Token: "b"}, match{Token: "c"})); rec.Code != http.StatusAccepted {
			t.Fatalf("status %d", rec.Code)
		}
		eventually(t, "a resolve to start", func() bool { return res.running() == 1 })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := h.Shutdown(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Shutdown = %v, want canceled", err)
		}
		eventually(t, "the attempt to be aborted", func() bool { return res.running() == 0 })
		// Every report is still pending: the one in flight under its lease,
		// the others not yet tried.
		rs, err := db.ListLeakReports(context.Background(), audit.LeakReportFilter{})
		if err != nil {
			t.Fatal(err)
		}
		attempted := 0
		for _, r := range rs {
			if r.Status != audit.LeakReportPending {
				t.Errorf("report %+v, want pending", r)
			}
			attempted += r.Attempts
		}
		if len(rs) != 3 || attempted != 1 {
			t.Errorf("reports %+v, want 3 with one attempt among them", rs)
		}
	})
}

// TestRestartResumesPendingReports stops a handler in the middle of a batch
// and starts another on the same queue, as a restart or a second instance
// would: every report is processed exactly once.
func TestRestartResumesPendingReports(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	db := openReports(t)
	known := map[string]Key{"real": {APIKeyID: "key_1", AccountID: "acct_1"}}

	first := &resolver{keys: known, gate: make(chan struct{})}
	firstDec := &recorder{}
	h1, _ := newTestHandler(t, Config{Decider: firstDec, Resolver: first, Reports: db, KeysURL: keys.URL, Workers: 1, ResolveTimeout: time.Minute})
	body := batch(t, match{Token: "real", Type: "acme_api_key", Source: "commit"}, match{Token: "fake", Type: "acme_api_key", Source: "commit"})
	if rec := send(t, h1, key, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	// The first handler dies in the middle of an attempt, with the other
	// report not yet claimed.
	eventually(t, "a resolve to start", func() bool { return first.running() == 1 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = h1.Shutdown(ctx)
	eventually(t, "the attempt to be aborted", func() bool { return first.running() == 0 })

	// The second starts after the first one's lease has ended.
	later := time.Now().Add(time.Hour)
	second := &resolver{keys: known}
	secondDec := &recorder{}
	newTestHandler(t, Config{Decider: secondDec, Resolver: second, Reports: db, KeysURL: keys.URL,
		now: func() time.Time { return later }})
	settled(t, db)

	if second.callsFor("real") != 1 || second.callsFor("fake") != 1 {
		t.Errorf("the second handler resolved real %d and fake %d times, want once each", second.callsFor("real"), second.callsFor("fake"))
	}
	if n := len(firstDec.tried()); n != 0 {
		t.Errorf("the first handler decided %d events after it stopped", n)
	}
	if evs := secondDec.got(); len(evs) != 1 || evs[0].APIKeyID != "key_1" {
		t.Errorf("events %+v, want the one leak", evs)
	}
	if r := stored(t, db, "real", "acme_api_key", "commit", ""); r.Status != audit.LeakReportDone || r.Outcome != "leaked" {
		t.Errorf("real %+v", r)
	}
	if r := stored(t, db, "fake", "acme_api_key", "commit", ""); r.Status != audit.LeakReportDone || r.Outcome != "not_found" {
		t.Errorf("fake %+v", r)
	}
}

// TestDuplicateDeliveries sends the same batch several times, at once and
// after it was processed: each report is resolved and decided once, and a
// batch sent again is answered with the labels its reports earned.
func TestDuplicateDeliveries(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{keys: map[string]Key{"real": {APIKeyID: "key_1"}}}
	dec := &recorder{}
	var out outcomes
	// A delivery that arrives between a token's resolve and its decision
	// may miss the label until the timeout; keep it short.
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, Feedback: true,
		FeedbackTimeout: 2 * time.Second, OnOutcome: out.add})
	body := batch(t,
		match{Token: "real", Type: "acme_api_key", Source: "commit", URL: "https://github.com/a"},
		match{Token: "fake", Type: "acme_api_key", Source: "commit", URL: "https://github.com/a"},
	)

	const deliveries = 4
	var wg sync.WaitGroup
	for range deliveries {
		wg.Go(func() {
			if rec := send(t, h, key, body); rec.Code != http.StatusOK {
				t.Errorf("status %d", rec.Code)
			}
		})
	}
	wg.Wait()
	settled(t, db)
	// Once processed, a batch sent again is labeled from the queue alone.
	want := []feedbackJSON{
		{TokenHash: hashOf("real"), TokenType: "acme_api_key", Label: "true_positive"},
		{TokenHash: hashOf("fake"), TokenType: "acme_api_key", Label: "false_positive"},
	}
	if got := feedbackOf(t, send(t, h, key, body)); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("feedback for a batch sent again\n%+v\nwant\n%+v", got, want)
	}

	if res.callsFor("real") != 1 || res.callsFor("fake") != 1 {
		t.Errorf("resolved real %d and fake %d times, want once each", res.callsFor("real"), res.callsFor("fake"))
	}
	if n := len(dec.tried()); n != 1 {
		t.Errorf("decided %d times, want once", n)
	}
	if out.count(OutcomeAccepted) != deliveries+1 || out.count(OutcomeDuplicate) != 2*deliveries {
		t.Errorf("outcomes %v, want %d accepted batches and %d duplicate reports", &out, deliveries+1, 2*deliveries)
	}

	// The same token found somewhere else is another report.
	moved := batch(t, match{Token: "real", Type: "acme_api_key", Source: "commit", URL: "https://github.com/b"})
	send(t, h, key, moved)
	settled(t, db)
	if evs := dec.got(); len(evs) != 2 || evs[0].ID == evs[1].ID {
		t.Errorf("events %+v, want a second leak with its own id", evs)
	}
}

func TestRetriesTransientResolverErrors(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	dec := &recorder{}
	res := &resolver{
		keys:     map[string]Key{"recovers": {APIKeyID: "key_1"}, "broken": {APIKeyID: "key_2"}},
		failures: map[string]int{"recovers": 2, "broken": 1000},
	}
	var out outcomes
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, MaxAttempts: 3, OnOutcome: out.add})
	send(t, h, key, batch(t, match{Token: "recovers"}, match{Token: "broken"}))
	settled(t, db)
	if evs := dec.got(); len(evs) != 1 || evs[0].APIKeyID != "key_1" {
		t.Errorf("events %+v", evs)
	}
	if res.callsFor("recovers") != 3 || res.callsFor("broken") != 3 {
		t.Errorf("resolved recovers %d and broken %d times, want 3 each", res.callsFor("recovers"), res.callsFor("broken"))
	}
	if out.count(OutcomeRetry) != 4 || out.count(OutcomeResolveFailed) != 1 || out.count(OutcomeLeaked) != 1 {
		t.Errorf("outcomes %v", &out)
	}
	if r := stored(t, db, "broken", "", "", ""); r.Status != audit.LeakReportDead || r.Outcome != "resolve_failed" ||
		r.Attempts != 3 || r.LastError != "platform unavailable" {
		t.Errorf("broken %+v, want it dead with its error", r)
	}

	// Once the resolver is fixed, a dead report requeued by hand goes
	// through.
	res.setFailures("broken", 0)
	r := stored(t, db, "broken", "", "", "")
	if n, err := db.RequeueLeakReports(context.Background(), time.Now(), []int64{r.ID}); err != nil || n != 1 {
		t.Fatalf("RequeueLeakReports = %d, %v", n, err)
	}
	eventually(t, "the requeued report to be done", func() bool {
		return stored(t, db, "broken", "", "", "").Status == audit.LeakReportDone
	})
	if evs := dec.got(); len(evs) != 2 || evs[1].APIKeyID != "key_2" {
		t.Errorf("events %+v, want the requeued leak", evs)
	}
}

// TestRetriesDecideFailures checks that a report whose decision fails, as
// when the store misses MarkLeaked's deadline, is retried with the same
// event id and without resolving its token again.
func TestRetriesDecideFailures(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{keys: map[string]Key{"real": {APIKeyID: "key_1", AccountID: "acct_1"}}}
	dec := &recorder{failures: 2}
	var out outcomes
	h, db := newTestHandler(t, Config{Decider: dec, Resolver: res, KeysURL: keys.URL, OnOutcome: out.add})
	send(t, h, key, batch(t, match{Token: "real", Type: "t"}))
	settled(t, db)

	tried := dec.tried()
	if len(tried) != 3 || tried[0].ID != tried[1].ID || tried[1].ID != tried[2].ID || !strings.HasPrefix(tried[0].ID, "ghss_") {
		t.Errorf("Decide calls %+v, want 3 with one fixed event id", tried)
	}
	if res.callsFor("real") != 1 {
		t.Errorf("resolved %d times, want once: the key was kept", res.callsFor("real"))
	}
	if out.count(OutcomeRetry) != 2 || out.count(OutcomeLeaked) != 1 {
		t.Errorf("outcomes %v", &out)
	}
}

func TestDecideFailureFeedback(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	var out outcomes
	h, db := newTestHandler(t, Config{
		Decider:  &recorder{fail: true},
		Resolver: &resolver{keys: map[string]Key{"real": {APIKeyID: "key_1"}}},
		KeysURL:  keys.URL, Feedback: true, MaxAttempts: 2, OnOutcome: out.add,
	})
	rec := send(t, h, key, batch(t, match{Token: "real", Type: "t"}))
	// The key is real even though the decision failed.
	if !strings.Contains(rec.Body.String(), "true_positive") {
		t.Errorf("feedback %s, want true_positive", rec.Body)
	}
	settled(t, db)
	if out.count(OutcomeDecideFailed) != 1 {
		t.Errorf("outcomes %v", &out)
	}
	if r := stored(t, db, "real", "t", "", ""); r.Status != audit.LeakReportDead || r.APIKeyID != "key_1" {
		t.Errorf("report %+v, want it dead with its key", r)
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
	h, db := newTestHandler(t, Config{
		Decider:  dec,
		Resolver: &resolver{keys: map[string]Key{"real": {APIKeyID: "key\x00one"}}},
		KeysURL:  keys.URL, OnOutcome: out.add,
	})
	send(t, h, key, batch(t, match{Token: "real", Type: "t"}))
	settled(t, db)
	if n := dec.calls.Load(); n != 1 {
		t.Errorf("Decide called %d times, want 1: a refused event is refused again", n)
	}
	if out.count(OutcomeDecideFailed) != 1 || out.count(OutcomeRetry) != 0 {
		t.Errorf("outcomes %v", &out)
	}
}

func TestReportAgeBoundsRetries(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	res := &resolver{failures: map[string]int{"t": 1000}}
	var out outcomes
	h, db := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, MaxAge: time.Nanosecond, OnOutcome: out.add})
	send(t, h, key, batch(t, match{Token: "t"}))
	settled(t, db)
	if res.callsFor("t") != 1 || out.count(OutcomeResolveFailed) != 1 || out.count(OutcomeRetry) != 0 {
		t.Errorf("resolved %d times, outcomes %v; want one attempt past the age", res.callsFor("t"), &out)
	}
}

// TestRawTokens checks the raw token's life with RawTokenSecret: sealed in
// the queue, handed to the resolver, forgotten once processed, and useless
// to a handler with another secret.
func TestRawTokens(t *testing.T) {
	key := newTestKey(t, "k1")
	keys := newKeysServer(t, key)
	const secret = "resolver-secret-0123456789abcdef"
	const raw = "acme_live_SECRET"

	res := &resolver{keys: map[string]Key{raw: {APIKeyID: "key_1"}}, gate: make(chan struct{})}
	h, db := newTestHandler(t, Config{Resolver: res, KeysURL: keys.URL, RawTokenSecret: secret, ResolveTimeout: time.Minute})
	send(t, h, key, batch(t, match{Token: raw, Type: "t"}))
	waiting := stored(t, db, raw, "t", "", "")
	if waiting.SealedToken == "" || strings.Contains(waiting.SealedToken, "SECRET") {
		t.Fatalf("sealed token %q, want it encrypted", waiting.SealedToken)
	}
	close(res.gate)
	settled(t, db)
	if seen := res.seen(); len(seen) != 1 || seen[0].Raw != raw {
		t.Errorf("resolver saw %+v, want the raw token", seen)
	}
	if r := stored(t, db, raw, "t", "", ""); r.Status != audit.LeakReportDone || r.SealedToken != "" {
		t.Errorf("report %+v, want it done and its token gone", r)
	}

	// The secret changed while a report was pending: its token is lost,
	// and the report says so instead of resolving the hash alone.
	other := openReports(t)
	h1, _ := newTestHandler(t, Config{Resolver: &resolver{gate: make(chan struct{})}, Reports: other, KeysURL: keys.URL,
		RawTokenSecret: secret, Workers: 1, ResolveTimeout: time.Minute})
	send(t, h1, key, batch(t, match{Token: raw, Type: "t"}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = h1.Shutdown(ctx)
	rotated := &resolver{keys: map[string]Key{raw: {APIKeyID: "key_1"}}}
	var out outcomes
	newTestHandler(t, Config{Resolver: rotated, Reports: other, KeysURL: keys.URL, RawTokenSecret: "another-secret-0123456789abcdef",
		OnOutcome: out.add, now: func() time.Time { return time.Now().Add(time.Hour) }})
	settled(t, other)
	if r := stored(t, other, raw, "t", "", ""); r.Status != audit.LeakReportDead || !strings.Contains(r.LastError, "cannot be decrypted") {
		t.Errorf("report %+v, want it dead because its token cannot be decrypted", r)
	}
	if len(rotated.seen()) != 0 || out.count(OutcomeResolveFailed) != 1 {
		t.Errorf("resolver saw %+v, outcomes %v", rotated.seen(), &out)
	}
}

func TestSealer(t *testing.T) {
	s, err := newSealer("resolver-secret-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.seal("acme_live_SECRET", "report-1")
	if strings.Contains(sealed, "SECRET") || !strings.HasPrefix(sealed, "v1:") || sealed == s.seal("acme_live_SECRET", "report-1") {
		t.Errorf("sealed %q, want an encrypted, randomized v1 token", sealed)
	}
	if raw, err := s.open(sealed, "report-1"); err != nil || raw != "acme_live_SECRET" {
		t.Errorf("open = %q, %v", raw, err)
	}
	other, _ := newSealer("another-secret-0123456789abcdef")
	tampered := sealed[:len(sealed)-2] + "AA"
	for name, open := range map[string]func() (string, error){
		"another secret":     func() (string, error) { return other.open(sealed, "report-1") },
		"another report":     func() (string, error) { return s.open(sealed, "report-2") },
		"tampered":           func() (string, error) { return s.open(tampered, "report-1") },
		"unknown version":    func() (string, error) { return s.open("v2:"+sealed[3:], "report-1") },
		"not base64":         func() (string, error) { return s.open("v1:%%%", "report-1") },
		"shorter than nonce": func() (string, error) { return s.open("v1:AAAA", "report-1") },
	} {
		if raw, err := open(); !errors.Is(err, errUnseal) || raw != "" {
			t.Errorf("%s: open = %q, %v; want errUnseal", name, raw, err)
		}
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
	reports := openReports(t)
	if _, err := New(Config{Resolver: &resolver{}, Reports: reports}); err == nil {
		t.Error("no decider: want an error")
	}
	if _, err := New(Config{Decider: &recorder{}, Reports: reports}); err == nil {
		t.Error("no resolver: want an error")
	}
	if _, err := New(Config{Decider: &recorder{}, Resolver: &resolver{}}); err == nil {
		t.Error("no reports: want an error")
	}
}
