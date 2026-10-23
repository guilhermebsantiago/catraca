package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

// maxRequeue bounds how many dead reports one retry --dead requeues.
const maxRequeue = 100_000

func (c *cli) secretscanList(ctx context.Context, args []string) int {
	fs := c.flagSet("secretscan list", `Usage: catraca secretscan list --audit <dsn> [--status pending|dead|done|all] [--limit 50] [--json]

Lists the leaked-key reports from GitHub secret scanning in the audit
database, newest first, after how many are pending and dead. A dead report
is a leaked key that may not have been acted on: fix what its last error
says, then requeue it with catraca secretscan retry. Raw tokens are never
shown.
`)
	dsn := fs.String("audit", c.getenv("CATRACA_AUDIT_DSN"), "the audit database DSN, as in catraca.yaml (default from $CATRACA_AUDIT_DSN)")
	status := fs.String("status", "all", "list only reports that are pending, dead or done")
	limit := fs.Int("limit", 50, "the most reports listed")
	asJSON := fs.Bool("json", false, "print JSON instead of a table")
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	var filter audit.LeakReportFilter
	if *status != "all" {
		st, err := audit.ParseLeakReportStatus(*status)
		if err != nil {
			c.errorf("--status must be pending, dead, done or all, got %q", *status)
			return exitUsage
		}
		filter.Status = st
	}
	if *limit < 1 {
		c.errorf("--limit must be at least 1")
		return exitUsage
	}
	filter.Limit = *limit
	db, code := c.openAudit(ctx, *dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)
	stats, err := db.LeakReportStats(ctx)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	reports, err := db.ListLeakReports(ctx, filter)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}

	if *asJSON {
		out := struct {
			Pending       int64              `json:"pending"`
			Dead          int64              `json:"dead"`
			OldestPending *time.Time         `json:"oldest_pending,omitempty"`
			Reports       []audit.LeakReport `json:"reports"`
		}{Pending: stats.Pending, Dead: stats.Dead, Reports: reports}
		if !stats.OldestPending.IsZero() {
			out.OldestPending = &stats.OldestPending
		}
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return exitError
		}
		return exitOK
	}

	summary := fmt.Sprintf("%d pending", stats.Pending)
	if stats.Pending > 0 {
		summary += fmt.Sprintf(" (the oldest arrived %s ago)", time.Since(stats.OldestPending).Round(time.Second))
	}
	fmt.Fprintf(c.stdout, "%s, %d dead\n", summary, stats.Dead)
	if len(reports) == 0 {
		return exitOK
	}
	fmt.Fprintln(c.stdout)
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tOUTCOME\tATTEMPTS\tTYPE\tSOURCE\tAPI KEY\tRECEIVED\tNEXT ATTEMPT\tURL\tLAST ERROR")
	for _, r := range reports {
		next := "-"
		if r.Status == audit.LeakReportPending {
			next = r.NextAttemptAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Status, dash(r.Outcome), r.Attempts,
			dash(printable(r.Type, 40)), dash(printable(r.Source, 20)), dash(printable(r.APIKeyID, 40)),
			r.ReceivedAt.Format(time.RFC3339), next, dash(printable(r.URL, 80)), dash(printable(r.LastError, 80)))
	}
	_ = tw.Flush()
	return exitOK
}

func (c *cli) secretscanRetry(ctx context.Context, args []string) int {
	fs := c.flagSet("secretscan retry", `Usage: catraca secretscan retry --audit <dsn> (<report-id>... | --dead)

Requeues dead leaked-key reports: each is due at once, with its attempts and
age counted afresh, and a running server picks it up within seconds. Fix
what made them fail first; catraca secretscan list --status dead shows each
one's last error. Reports that are not dead are left alone.
`)
	dsn := fs.String("audit", c.getenv("CATRACA_AUDIT_DSN"), "the audit database DSN, as in catraca.yaml (default from $CATRACA_AUDIT_DSN)")
	all := fs.Bool("dead", false, "requeue every dead report")
	pos, code := parse(fs, args, 0, -1)
	if code >= 0 {
		return code
	}
	if *all == (len(pos) > 0) {
		c.errorf("name the reports to requeue by id, or pass --dead for every dead report")
		return exitUsage
	}
	ids := make([]int64, 0, len(pos))
	for _, p := range pos {
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil || id < 1 {
			c.errorf("%q is not a report id: ids are the numbers catraca secretscan list prints", p)
			return exitUsage
		}
		ids = append(ids, id)
	}
	db, code := c.openAudit(ctx, *dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)
	if *all {
		dead, err := db.ListLeakReports(ctx, audit.LeakReportFilter{Status: audit.LeakReportDead, Limit: maxRequeue})
		if err != nil {
			c.errorf("%v", err)
			return exitError
		}
		for _, r := range dead {
			ids = append(ids, r.ID)
		}
	}
	n, err := db.RequeueLeakReports(ctx, time.Now(), ids)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	fmt.Fprintf(c.stdout, "requeued %d dead report(s)\n", n)
	if !*all && n < len(ids) {
		c.errorf("%d of the %d reports named are not dead, or do not exist, and were left alone", len(ids)-n, len(ids))
		return exitFailed
	}
	return exitOK
}

// printable makes a value read from the database safe for a terminal, and
// cuts it to max runes: URLs, types and errors come from GitHub and the
// platform, and may carry control characters.
func printable(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) {
			r = '�'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// dash stands in for an empty cell.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
