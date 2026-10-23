package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

// leakReportsDB makes an audit database with a pending, a dead and a done
// leaked-key report, and returns its path and the ids of the pending and
// dead ones.
func leakReportsDB(t *testing.T) (path string, pending, dead int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	db, err := audit.Open(ctx, "sqlite:"+path, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	now := time.Now()
	var reports []audit.LeakReport
	for _, key := range []string{"pending", "dead", "done"} {
		reports = append(reports, audit.LeakReport{Key: key, TokenSHA256: "sha-" + key, SealedToken: "v1:secret-" + key,
			Type: "acme_api_key", Source: "commit", URL: "https://github.com/octo/" + key + "\x1b[31m", ReceivedAt: now.Add(-time.Hour)})
	}
	if _, err := db.AddLeakReports(ctx, reports); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimLeakReports(ctx, now, 3, time.Minute)
	if err != nil || len(claimed) != 3 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	ids := map[string]int64{}
	for _, r := range claimed {
		ids[r.Key] = r.ID
	}
	settle := []error{
		db.RetryLeakReport(ctx, ids["pending"], audit.LeakAttempt{At: now, Attempt: 1, Error: "platform down"}, now.Add(time.Minute)),
		db.MarkLeakReportDead(ctx, ids["dead"], audit.LeakAttempt{At: now, Attempt: 1, Outcome: "resolve_failed",
			Error: "secretscan: resolver returned 503 Service Unavailable"}),
		db.FinishLeakReport(ctx, ids["done"], audit.LeakAttempt{At: now, Attempt: 1, Outcome: "leaked", APIKeyID: "key_1", DecisionID: "dec_1"}),
	}
	for _, err := range settle {
		if err != nil {
			t.Fatal(err)
		}
	}
	return path, ids["pending"], ids["dead"]
}

func TestSecretscanList(t *testing.T) {
	db, _, _ := leakReportsDB(t)

	r := runCLI(t, nil, "secretscan", "list", "--audit", db)
	expect(t, r, exitOK, "1 pending (the oldest arrived 1h", "1 dead", "LAST ERROR", "resolve_failed", "leaked", "key_1",
		"resolver returned 503", "https://github.com/octo/done")
	if strings.Contains(r.stdout, "\x1b") || strings.Contains(r.stdout, "secret-") {
		t.Errorf("list printed a control character or a sealed token:\n%s", r.stdout)
	}

	r = runCLI(t, map[string]string{"CATRACA_AUDIT_DSN": "sqlite:" + db}, "secretscan", "list", "--status", "dead")
	expect(t, r, exitOK, "resolve_failed")
	if strings.Contains(r.stdout, "leaked") || strings.Contains(r.stdout, "platform down") {
		t.Errorf("list --status dead shows other reports:\n%s", r.stdout)
	}

	r = runCLI(t, nil, "secretscan", "list", "--audit", db, "--json", "--limit", "2")
	expect(t, r, exitOK)
	var out struct {
		Pending       int64      `json:"pending"`
		Dead          int64      `json:"dead"`
		OldestPending *time.Time `json:"oldest_pending"`
		Reports       []struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
			URL    string `json:"url"`
		} `json:"reports"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("list --json is not JSON: %v\n%s", err, r.stdout)
	}
	if out.Pending != 1 || out.Dead != 1 || out.OldestPending == nil || len(out.Reports) != 2 || out.Reports[0].Status != "done" {
		t.Errorf("list --json = %+v", out)
	}
	if strings.Contains(r.stdout, "secret-") {
		t.Errorf("list --json printed a sealed token:\n%s", r.stdout)
	}

	expect(t, runCLI(t, nil, "secretscan"), exitUsage, "Usage: catraca secretscan <list|retry>")
	expect(t, runCLI(t, nil, "secretscan", "list"), exitUsage, "--audit is required")
	expect(t, runCLI(t, nil, "secretscan", "list", "--audit", db, "--status", "stuck"), exitUsage, "--status must be")
	expect(t, runCLI(t, nil, "secretscan", "list", "--audit", db, "--limit", "0"), exitUsage, "--limit")
	expect(t, runCLI(t, nil, "secretscan", "list", "--audit", db, "extra"), exitUsage)
	expect(t, runCLI(t, nil, "secretscan", "list", "--audit", filepath.Join(t.TempDir(), "nope.db")), exitError, "does not exist")
}

func TestSecretscanRetry(t *testing.T) {
	db, pending, dead := leakReportsDB(t)

	expect(t, runCLI(t, nil, "secretscan", "retry", "--audit", db), exitUsage, "or pass --dead")
	expect(t, runCLI(t, nil, "secretscan", "retry", "--audit", db, "--dead", "1"), exitUsage, "or pass --dead")
	expect(t, runCLI(t, nil, "secretscan", "retry", "--audit", db, "first"), exitUsage, `"first" is not a report id`)

	// A pending report may be in the middle of an attempt: it is left alone.
	expect(t, runCLI(t, nil, "secretscan", "retry", "--audit", db, strconv.FormatInt(pending, 10)), exitFailed,
		"requeued 0 dead report(s)", "1 of the 1 reports named are not dead")
	expect(t, runCLI(t, nil, "secretscan", "retry", "--audit", db, strconv.FormatInt(dead, 10)), exitOK, "requeued 1 dead report(s)")
	expect(t, runCLI(t, nil, "secretscan", "list", "--audit", db), exitOK, "2 pending", "0 dead")
	expect(t, runCLI(t, nil, "secretscan", "retry", "--audit", db, "--dead"), exitOK, "requeued 0 dead report(s)")
}
