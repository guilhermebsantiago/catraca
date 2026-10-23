package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// loadRuleset loads a ruleset, printing every problem in it.
func (c *cli) loadRuleset(path string) (*rules.Ruleset, int) {
	rs, err := rules.LoadFile(path)
	if err != nil {
		c.printRulesError(path, err)
		return nil, failure(err)
	}
	return rs, -1
}

func (c *cli) printRulesError(path string, err error) {
	var list rules.ErrorList
	if errors.As(err, &list) {
		for _, e := range list {
			fmt.Fprintln(c.stderr, e)
		}
		c.errorf("%s: %d error(s)", path, len(list))
		return
	}
	c.errorf("%v", err)
}

// formatWarning writes a lint warning the way compilers do,
// "file:line: warning: ...", so editors can jump to it.
func formatWarning(path string, w rules.Warning) string {
	var b strings.Builder
	b.WriteString(path)
	if w.Line > 0 {
		fmt.Fprintf(&b, ":%d", w.Line)
	}
	b.WriteString(": warning: ")
	if w.Where != "" {
		b.WriteString(w.Where + ": ")
	}
	b.WriteString(w.Msg)
	return b.String()
}

func (c *cli) rulesCheck(_ context.Context, args []string) int {
	fs := c.flagSet("rules check", `Usage: catraca rules check <ruleset> [--strict]

Parses and compiles a ruleset and prints its lint warnings. Errors fail the
check; warnings fail it only with --strict.
`)
	strict := fs.Bool("strict", false, "fail when there are lint warnings")
	pos, code := parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	path := pos[0]
	rs, code := c.loadRuleset(path)
	if rs == nil {
		return code
	}
	warnings := rs.Lint()
	for _, w := range warnings {
		fmt.Fprintln(c.stderr, formatWarning(path, w))
	}
	enforced := 0
	for _, r := range rs.Rules() {
		if r.Mode == decision.Enforce {
			enforced++
		}
	}
	summary := fmt.Sprintf("%s: %d rules (%d enforced, %d shadow), version %s, %d warning(s)",
		path, len(rs.Rules()), enforced, len(rs.Rules())-enforced, rs.Version(), len(warnings))
	if *strict && len(warnings) > 0 {
		fmt.Fprintf(c.stdout, "FAIL %s (--strict)\n", summary)
		return exitFailed
	}
	fmt.Fprintf(c.stdout, "ok %s\n", summary)
	return exitOK
}

func (c *cli) rulesTest(_ context.Context, args []string) int {
	fs := c.flagSet("rules test", `Usage: catraca rules test <ruleset> <fixtures>...

Runs fixture files against a ruleset and fails when a case does not hold.
See docs/rules.md for the fixture format.
`)
	pos, code := parse(fs, args, 2, -1)
	if code >= 0 {
		return code
	}
	rs, code := c.loadRuleset(pos[0])
	if rs == nil {
		return code
	}
	result := exitOK
	for _, path := range pos[1:] {
		cases, err := rules.LoadFixtures(path)
		if err != nil {
			c.printRulesError(path, err)
			if failure(err) == exitError {
				return exitError
			}
			result = exitFailed
			continue
		}
		if len(pos) > 2 {
			fmt.Fprintf(c.stdout, "== %s\n", path)
		}
		report := rules.RunFixtures(rs, cases)
		if err := report.WriteText(c.stdout); err != nil {
			return exitError
		}
		if len(report.Failed()) > 0 {
			result = exitFailed
		}
	}
	return result
}

// gateFlags are the flags shared by rules gate and report.
type gateFlags struct {
	dsn          *string
	since        *string
	minLabeled   *int
	minPrecision *float64
}

func (c *cli) addGateFlags(set *flag.FlagSet, defaultSince, sinceHelp string) gateFlags {
	return gateFlags{
		dsn:          set.String("audit", c.getenv("CATRACA_AUDIT_DSN"), "the audit database DSN, as in catraca.yaml (default from $CATRACA_AUDIT_DSN)"),
		since:        set.String("since", defaultSince, sinceHelp),
		minLabeled:   set.Int("min-labeled", precision.DefaultMinLabeled, "labeled matches a rule needs to pass the gate"),
		minPrecision: set.Float64("min-precision", precision.DefaultMinPrecision, "precision lower bound a rule needs to pass the gate"),
	}
}

// gate returns the gate the flags describe, or the exit code for invalid
// values.
func (c *cli) gate(g gateFlags) (precision.Gate, int) {
	gate := precision.Gate{MinLabeled: *g.minLabeled, MinPrecision: *g.minPrecision}
	if err := gate.Validate(); err != nil || gate.MinLabeled < 1 || gate.MinPrecision <= 0 {
		c.errorf("--min-labeled must be at least 1 and --min-precision in (0, 1]")
		return gate, exitUsage
	}
	return gate, -1
}

// openAudit opens the audit database, applying its migrations. A SQLite
// file must exist already: opening creates missing files, and an empty new
// database would make every rule look unlabeled and the outbox empty.
func (c *cli) openAudit(ctx context.Context, dsn string) (*audit.DB, int) {
	if dsn == "" {
		c.errorf("--audit is required (or set CATRACA_AUDIT_DSN)")
		return nil, exitUsage
	}
	a := config.Audit{DSN: config.Secret(dsn)}
	if path := a.SQLitePath(); a.IsSQLite() && !strings.HasPrefix(path, ":memory:") {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			c.errorf("the audit database %s does not exist", path)
			return nil, exitError
		} else if err != nil {
			c.errorf("%v", err)
			return nil, exitError
		}
	}
	log := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	db, err := audit.Open(ctx, dsn, audit.Options{Logger: log})
	if err != nil {
		c.errorf("%v", err)
		return nil, exitError
	}
	return db, -1
}

// since parses --since. Empty means all time.
func (c *cli) since(s string) (time.Time, int) {
	if s == "" || s == "all" {
		return time.Time{}, -1
	}
	t, err := api.ParseSince(s, time.Now())
	if err != nil {
		c.errorf("--since: %v", err)
		return t, exitUsage
	}
	return t, -1
}

func (c *cli) rulesGate(ctx context.Context, args []string) int {
	fs := c.flagSet("rules gate", `Usage: catraca rules gate <ruleset> --audit <dsn> [--since 720h]

Checks every enforced rule of a ruleset against the precision gate, using
the labels in the audit database. It fails when an enforced rule does not
pass the gate and has no override. Run it in CI so no rule enforces without
evidence.
`)
	g := c.addGateFlags(fs, "", `only count matches decided since then: a duration such as 720h or 30d, or an RFC 3339 time (default all time)`)
	pos, code := parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	gate, code := c.gate(g)
	if code >= 0 {
		return code
	}
	since, code := c.since(*g.since)
	if code >= 0 {
		return code
	}
	rs, code := c.loadRuleset(pos[0])
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

	results, err := gate.CheckRuleset(api.RuleInfos(rs), stats)
	if len(results) == 0 {
		fmt.Fprintln(c.stdout, "ok: the ruleset has no enforced rules")
		return exitOK
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tLABELED\tTP\tFP\tPRECISION\t95% CI\tSTATUS")
	for _, r := range results {
		prec, ci := "-", "-"
		if r.Labeled > 0 {
			prec = fmt.Sprintf("%.3f", r.Precision)
			ci = fmt.Sprintf("[%.3f, %.3f]", r.Lower, r.Upper)
		}
		status := string(r.Status)
		if r.Override {
			status += " (override)"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\t%s\n", r.RuleID, r.Labeled, r.TruePositives, r.FalsePositives, prec, ci, status)
	}
	_ = tw.Flush()
	var gateErr *precision.GateError
	if errors.As(err, &gateErr) {
		fmt.Fprintf(c.stdout, "\nFAIL %v\n", gateErr)
		return exitFailed
	}
	fmt.Fprintf(c.stdout, "\nok: %d enforced rule(s) pass the gate or have an override\n", len(results))
	return exitOK
}
