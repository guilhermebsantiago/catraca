package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/replay"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

func (c *cli) replay(ctx context.Context, args []string) int {
	fs := c.flagSet("replay", `Usage: catraca replay <ruleset> <events.jsonl> [--json]

Backtests a ruleset on labeled events, one JSON object per line in time
order: {"event": {...}, "label": "abusive" | "legit"}. Events run through a
fresh in-memory signal catalog and the production engine; the report gives
precision, recall and F1 per rule.
`)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, code := parse(fs, args, 2, 2)
	if code >= 0 {
		return code
	}
	rs, code := c.loadRuleset(pos[0])
	if rs == nil {
		return code
	}
	newCatalog := func() (signal.Catalog, error) {
		return signal.NewCatalog(store.NewMemory(), signal.Options{}), nil
	}
	report, err := replay.RunFile(ctx, rs, newCatalog, pos[1])
	if err != nil {
		c.errorf("%v", err)
		return failure(err)
	}
	if *asJSON {
		err = report.WriteJSON(c.stdout)
	} else {
		err = report.WriteText(c.stdout)
	}
	if err != nil {
		return exitError
	}
	return exitOK
}

func (c *cli) report(ctx context.Context, args []string) int {
	fs := c.flagSet("report", `Usage: catraca report --rules <ruleset> --audit <dsn> [--since 720h] [--json]

Prints the precision of every rule in a ruleset over a window, from the
labels in the audit database, with the shadow rules that pass the gate
(promote candidates) and the enforced rules below it (retire candidates).
`)
	rulesPath := fs.String("rules", "", "the ruleset (required)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	g := c.addGateFlags(fs, "720h", `the window: a duration such as 720h or 30d, an RFC 3339 time, or "all"`)
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	if *rulesPath == "" {
		c.errorf("--rules is required")
		return exitUsage
	}
	gate, code := c.gate(g)
	if code >= 0 {
		return code
	}
	since, code := c.since(*g.since)
	if code >= 0 {
		return code
	}
	rs, code := c.loadRuleset(*rulesPath)
	if rs == nil {
		return code
	}
	db, code := c.openAudit(ctx, *g.dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)
	stats, err := db.RuleStats(ctx, since)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	report := precision.NewReport(gate, api.RuleInfos(rs), stats)
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(api.StatsResponse{Since: since.UTC(), RulesetVersion: rs.Version(), Report: report})
	} else {
		window := "all time"
		if !since.IsZero() {
			window = "since " + since.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(c.stdout, "Ruleset %s, matches %s\n", rs.Version(), window)
		err = report.WriteText(c.stdout)
	}
	if err != nil {
		return exitError
	}
	return exitOK
}
