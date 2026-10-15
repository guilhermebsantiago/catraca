// Package replay_test backtests the default ruleset on the synthetic dataset
// in this directory. The data is made up and the rules were not tuned on
// it: the run shows how a backtest works, not how precise the rules are.
package replay_test

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/replay"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

const (
	dataset = "events.jsonl"
	ruleset = "../../rules/default.yaml"
)

func memoryCatalog() (signal.Catalog, error) {
	return signal.NewCatalog(store.NewMemory(), signal.Options{}), nil
}

// TestDefaultRuleset replays the dataset through the default ruleset, as
// `catraca replay rules/default.yaml examples/replay/events.jsonl` does. Run
// it with -v to see the report.
func TestDefaultRuleset(t *testing.T) {
	rs, err := rules.LoadFile(ruleset)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := replay.RunFile(context.Background(), rs, memoryCatalog, dataset)
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", text.String())

	if lines := countLines(t, dataset); rep.Events != lines {
		t.Errorf("replayed %d events, the file has %d lines", rep.Events, lines)
	}
	if rep.Abusive == 0 || rep.Legit == 0 {
		t.Errorf("labeled %d abusive and %d legit events; the dataset needs both", rep.Abusive, rep.Legit)
	}
	if rep.Degraded != 0 {
		t.Errorf("%d decisions were degraded: the memory catalog should never fail", rep.Degraded)
	}
	if len(rep.Rules) != len(rs.Rules()) {
		t.Fatalf("report has %d rules, the ruleset %d", len(rep.Rules), len(rs.Rules()))
	}
	matched := 0
	for i, rr := range rep.Rules {
		if rr.ID != rs.Rules()[i].ID {
			t.Errorf("rule %d is %s in the report and %s in the ruleset", i, rr.ID, rs.Rules()[i].ID)
		}
		if n := rr.TP + rr.FP + rr.FN + rr.TN; n != rep.Labeled {
			t.Errorf("%s scored %d events, want the %d labeled ones", rr.ID, n, rep.Labeled)
		}
		if rr.Errors != 0 {
			t.Errorf("%s could not be evaluated on %d events: the dataset lacks a signal it reads", rr.ID, rr.Errors)
		}
		if rr.TP+rr.FP > 0 {
			matched++
		}
	}
	if matched < len(rep.Rules)/2 {
		t.Errorf("only %d of %d rules matched anything: the dataset no longer exercises the ruleset", matched, len(rep.Rules))
	}
	// The dataset includes legitimate traffic that looks like abuse and
	// abuse the rules miss, so neither precision nor recall is perfect.
	if all := rep.AllRules; all.FP == 0 || all.FN == 0 || all.TP == 0 {
		t.Errorf("all rules together: %+v; want true positives, false positives and misses", all)
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}
