package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// postLeaks posts a batch of matches to the secret scanning endpoint,
// signed with h's GitHub key.
func (h *harness) postLeaks(batch string) response {
	h.t.Helper()
	digest := sha256.Sum256([]byte(batch))
	sig, err := ecdsa.SignASN1(rand.Reader, h.github, digest[:])
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do("POST", "/v1/secret-scanning/github", "", batch,
		"Github-Public-Key-Identifier", "test-key",
		"Github-Public-Key-Signature", base64.StdEncoding.EncodeToString(sig))
}

// metrics returns the harness's /metrics page.
func (h *harness) metrics() string {
	h.t.Helper()
	return string(h.do("GET", "/metrics", "", nil).body)
}

const leakBatch = `[{"token":"` + leakedToken + `","type":"acme_api_key","url":"https://github.com/octo/repo/blob/main/.env","source":"content"},` +
	`{"token":"acme_live_somebody_else","type":"acme_api_key","url":"https://github.com/octo/repo","source":"commit"}]`

// TestSecretScanningAnswers503UntilTheAuditDatabaseOpens checks that a
// batch is not acknowledged while it cannot be stored: GitHub sends it
// again once the database is up.
func TestSecretScanningAnswers503UntilTheAuditDatabaseOpens(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // nothing listens there now
	h := newHarness(t, options{auditDSN: "postgres://catraca:pw@" + ln.Addr().String() + "/catraca?sslmode=disable"})

	r := h.postLeaks(leakBatch)
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("batch while the audit database is not open: %d %s, Retry-After %q", r.status, r.body, r.header.Get("Retry-After"))
	}
	if m := h.metrics(); !strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="unavailable"} 1`) ||
		!strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="accepted"} 0`) {
		t.Errorf("metrics do not count the refused batch:\n%s", m)
	}
	if strings.Contains(h.metrics(), "catraca_secret_scanning_reports") {
		t.Error("report counts are exported while the audit database is not open")
	}
}

// switchableResolver is a platform resolver that answers 503 while down is
// set, and otherwise knows leakedToken.
type switchableResolver struct {
	*httptest.Server
	down  atomic.Bool
	calls atomic.Int32
}

func newSwitchableResolver(t *testing.T) *switchableResolver {
	t.Helper()
	want := sha256.Sum256([]byte(leakedToken))
	s := &switchableResolver{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if s.down.Load() {
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			TokenSHA256 string `json:"token_sha256"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil || req.TokenSHA256 != hex.EncodeToString(want[:]) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"api_key_id":"key_leaked","account_id":"acct_leak"}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// TestSecretScanningSurvivesARestart accepts a batch while the platform's
// resolver is down, restarts the server, and checks that the next process
// acts on the leak once the resolver is back, and only once, however many
// times GitHub sends the batch.
func TestSecretScanningSurvivesARestart(t *testing.T) {
	t.Parallel()
	dsn := "sqlite:" + filepath.ToSlash(filepath.Join(t.TempDir(), "audit.db"))
	resolver := newSwitchableResolver(t)
	resolver.down.Store(true)

	first := newHarness(t, options{auditDSN: dsn, resolverURL: resolver.URL})
	if r := first.postLeaks(leakBatch); r.status != http.StatusAccepted {
		t.Fatalf("batch: %d %s", r.status, r.body)
	}
	eventually(t, 10*time.Second, func() bool { return resolver.calls.Load() > 0 })
	eventually(t, 10*time.Second, func() bool {
		return strings.Contains(first.metrics(), `catraca_secret_scanning_reports{status="pending"} 2`)
	})
	first.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := first.app.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	resolver.down.Store(false)
	second := newHarness(t, options{auditDSN: dsn, resolverURL: resolver.URL})
	var (
		d        decision.Decision
		attempts int
	)
	eventually(t, 15*time.Second, func() bool {
		attempts++
		// Each attempt sends from its own account, so the burst rule of a
		// busy account cannot block it first.
		d, _ = second.decide(send(fmt.Sprintf("acct_restart_%d", attempts), "app@leak.example", "api_key_id", "key_leaked"))
		return d.Action == decision.Block
	})
	eventually(t, 10*time.Second, func() bool { return len(second.hook.calls()) == 1 })

	// GitHub sends the batch again, as it would after a timeout: nothing
	// is processed twice.
	if r := second.postLeaks(leakBatch); r.status != http.StatusAccepted {
		t.Fatalf("batch sent again: %d %s", r.status, r.body)
	}
	eventually(t, 10*time.Second, func() bool {
		m := second.metrics()
		return strings.Contains(m, `catraca_secret_scanning_reports{status="pending"} 0`) &&
			strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="leaked"} 1`) &&
			strings.Contains(m, `catraca_secret_scanning_outcomes_total{outcome="not_found"} 1`)
	})
	m := second.metrics()
	for _, want := range []string{
		`catraca_secret_scanning_outcomes_total{outcome="duplicate"} 2`,
		`catraca_secret_scanning_reports{status="dead"} 0`,
		`catraca_secret_scanning_oldest_pending_seconds 0`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if n := len(first.hook.calls()); n != 0 {
		t.Errorf("the first process called the revoke_key hook %d times without a resolved key", n)
	}
	if n := len(second.hook.calls()); n != 1 {
		t.Errorf("revoke_key was called %d times, want once", n)
	}
}
