package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/replay"
)

const bulkRules = `version: 1
rules:
  - id: bulk
    when: event.type == "send" && event.recipients > 10
    action: block
    mode: enforce
    on_error: open
    reason: too many recipients
`

// labeledDB creates a SQLite audit database in the given event mode with
// sends that rule bulk decided: three abusive bulk sends labeled true
// positive, a legit bulk send reversed, two small sends labeled legit and
// one unlabeled small send.
func labeledDB(t *testing.T, mode audit.EventMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	db, err := audit.Open(ctx, "sqlite:"+path, audit.Options{EventMode: mode})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	start := time.Now().Add(-time.Hour)
	to := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("r%d@example.com", i))
		}
		return out
	}
	sends := []struct {
		account    string
		recipients int
		label      *audit.Label
	}{
		{"spammer", 20, &audit.Label{Verdict: audit.TruePositive, By: "ana"}},
		{"spammer", 20, &audit.Label{RuleID: "bulk", Verdict: audit.TruePositive, By: "ana"}},
		{"newsletter", 20, ptr(audit.Reversal("appeals", "a real newsletter"))},
		{"spammer", 30, &audit.Label{Verdict: audit.TruePositive, By: "ana"}},
		{"shop", 1, &audit.Label{Verdict: audit.FalsePositive, By: "ana"}},
		{"shop", 2, nil},
		{"shop", 1, &audit.Label{Verdict: audit.FalsePositive, By: "ana"}},
	}
	for i, s := range sends {
		id := fmt.Sprintf("dec_%d", i)
		at := start.Add(time.Duration(i) * time.Second)
		ev := event.Event{ID: "ev_" + id, Type: event.Send, Time: at, AccountID: s.account, From: "news@" + s.account + ".example", To: to(s.recipients)}
		d := decision.Decision{ID: id, Time: at, Action: decision.Allow, RulesetVersion: "v"}
		if s.recipients > 10 {
			d.Action = decision.Block
			d.Matches = []decision.Match{{RuleID: "bulk", Reason: "r", Action: decision.Block, Mode: decision.Enforce}}
		}
		db.Record(ctx, ev, d)
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for i, s := range sends {
		if s.label != nil {
			if err := db.Label(ctx, fmt.Sprintf("dec_%d", i), *s.label); err != nil {
				t.Fatal(err)
			}
		}
	}
	return path
}

func ptr[T any](v T) *T { return &v }

func readExamples(t *testing.T, data string) []replay.Example {
	t.Helper()
	var out []replay.Example
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var ex replay.Example
		if err := json.Unmarshal(sc.Bytes(), &ex); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		out = append(out, ex)
	}
	return out
}

// TestAuditExportReplay labels decisions, exports them and replays the
// export: the backtest gets the precision the labels give.
func TestAuditExportReplay(t *testing.T) {
	dir := t.TempDir()
	db := labeledDB(t, audit.EventFull)
	rules := writeFile(t, dir, "rules.yaml", bulkRules)

	r := runCLI(t, nil, "audit", "export", "--audit", db)
	expect(t, r, exitOK, "exported 7 decisions: 3 abusive, 3 legit, 1 unlabeled")
	if strings.Contains(r.stderr, "minimal") {
		t.Errorf("a full-mode export warned about minimal events\n%s", r)
	}
	var labels []string
	for _, ex := range readExamples(t, r.stdout) {
		labels = append(labels, string(ex.Label))
	}
	if got := strings.Join(labels, ","); got != "abusive,abusive,legit,abusive,legit,,legit" {
		t.Errorf("labels = %s", got)
	}

	out := filepath.Join(dir, "labeled.jsonl")
	expect(t, runCLI(t, nil, "audit", "export", "--audit", db, "--since", "all", "--labeled-only", "--out", out), exitOK, "exported 6 decisions")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(readExamples(t, string(data))); n != 6 {
		t.Fatalf("--out has %d lines, want 6", n)
	}

	r = runCLI(t, nil, "replay", "--json", rules, out)
	expect(t, r, exitOK)
	var rep struct {
		Labeled int `json:"labeled"`
		Rules   []struct {
			ID        string   `json:"id"`
			TP        int      `json:"tp"`
			FP        int      `json:"fp"`
			Precision *float64 `json:"precision"`
			Recall    *float64 `json:"recall"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("replay --json: %v\n%s", err, r.stdout)
	}
	if rep.Labeled != 6 || len(rep.Rules) != 1 {
		t.Fatalf("replay = %+v", rep)
	}
	b := rep.Rules[0]
	if b.TP != 3 || b.FP != 1 || b.Precision == nil || *b.Precision != 0.75 || b.Recall == nil || *b.Recall != 1 {
		t.Errorf("bulk: tp %d fp %d precision %v recall %v; want 3, 1, 0.75, 1", b.TP, b.FP, b.Precision, b.Recall)
	}

	expect(t, runCLI(t, nil, "audit", "export", "--audit", db, "--since", "later"), exitUsage, "--since")
	expect(t, runCLI(t, nil, "audit", "export"), exitUsage, "--audit is required")
	expect(t, runCLI(t, nil, "audit"), exitUsage, "export")
}

// TestAuditExportMinimal warns that minimal events lack what recipient
// rules read, and the export still replays.
func TestAuditExportMinimal(t *testing.T) {
	dir := t.TempDir()
	db := labeledDB(t, audit.EventMinimal)
	out := filepath.Join(dir, "minimal.jsonl")
	r := runCLI(t, nil, "audit", "export", "--audit", db, "--out", out)
	expect(t, r, exitOK, "warning: 7 of the events were stored with audit.event_detail: minimal")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	exs := readExamples(t, string(data))
	if ev := exs[0].Event; ev.From != "@spammer.example" || ev.To != nil {
		t.Errorf("minimal event = %+v", ev)
	}
	expect(t, runCLI(t, nil, "replay", writeFile(t, dir, "rules.yaml", bulkRules), out), exitOK, "7 events, 6 labeled")
}

func TestDecisions(t *testing.T) {
	db := labeledDB(t, audit.EventMinimal)
	r := runCLI(t, nil, "decisions", "--audit", db, "--account", "spammer")
	expect(t, r, exitOK, "dec_3", "dec_1", "dec_0", "bulk")
	if strings.Contains(r.stdout, "dec_2") || strings.Index(r.stdout, "dec_3") > strings.Index(r.stdout, "dec_0") {
		t.Errorf("want spammer's decisions newest first\n%s", r)
	}

	r = runCLI(t, nil, "decisions", "--audit", db, "--action", "allow", "--limit", "2")
	expect(t, r, exitOK, "dec_6", "dec_5", "more decisions: pass --cursor ")
	cursor := strings.TrimSpace(r.stdout[strings.LastIndex(r.stdout, "--cursor ")+len("--cursor "):])
	r = runCLI(t, nil, "decisions", "--audit", db, "--action", "allow", "--limit", "2", "--cursor", cursor, "--json")
	expect(t, r, exitOK)
	var page audit.DecisionPage
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil {
		t.Fatalf("decisions --json: %v\n%s", err, r)
	}
	if len(page.Decisions) != 1 || page.Decisions[0].Decision.ID != "dec_4" || page.Next != "" {
		t.Errorf("second page = %+v", page)
	}

	expect(t, runCLI(t, nil, "decisions", "--audit", db, "--account", "nobody"), exitOK, "no decisions")
	expect(t, runCLI(t, nil, "decisions", "--audit", db, "--action", "explode"), exitUsage, "--action")
	expect(t, runCLI(t, nil, "decisions", "--audit", db, "--limit", "0"), exitUsage, "--limit")
	expect(t, runCLI(t, nil, "decisions", "--audit", db, "--cursor", "!!"), exitUsage, "--cursor")
	expect(t, runCLI(t, nil, "decisions", "--audit", db, "--until", "soon"), exitUsage, "--until")
}
