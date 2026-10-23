package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

// The outbox commands work on the audit database directly, like rules gate:
// the server need not be running, and a running one picks requeued
// deliveries up on its next poll.

func (c *cli) auditFlag(fs *flag.FlagSet) *string {
	return fs.String("audit", c.getenv("CATRACA_AUDIT_DSN"), "the audit database DSN, as in catraca.yaml (default from $CATRACA_AUDIT_DSN)")
}

func (c *cli) outboxList(ctx context.Context, args []string) int {
	fs := c.flagSet("outbox list", `Usage: catraca outbox list --audit <dsn> [--status pending|dead|delivered] [--hook <name>] [--since 24h] [--limit 50] [--json]

Lists the webhook deliveries in the outbox: pending ones in the order they
are due, the others most recently updated first.
`)
	dsn := c.auditFlag(fs)
	status := fs.String("status", "", "only deliveries in this state: pending, dead or delivered")
	hook := fs.String("hook", "", "only the deliveries for this hook")
	since := fs.String("since", "", "only deliveries last updated since then, which for dead ones is when they died: a duration such as 24h or 7d, or an RFC 3339 time")
	limit := fs.Int("limit", 50, "the most deliveries to list")
	asJSON := fs.Bool("json", false, "print the deliveries as JSON")
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	st, code := c.deliveryStatus(*status)
	if code >= 0 {
		return code
	}
	if *limit < 1 {
		c.errorf("--limit must be at least 1")
		return exitUsage
	}
	from, code := c.since(*since)
	if code >= 0 {
		return code
	}
	db, code := c.openAudit(ctx, *dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)
	ds, err := db.ListDeliveries(ctx, audit.DeliveryFilter{Status: st, Effect: *hook, Since: from}, *limit)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ds); err != nil {
			return exitError
		}
		return exitOK
	}
	if len(ds) == 0 {
		fmt.Fprintln(c.stdout, "no deliveries")
		return exitOK
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDECISION\tHOOK\tSTATUS\tATTEMPTS\tCREATED\tREQUEUED\tUPDATED\tNEXT\tLAST")
	for _, d := range ds {
		next := "-"
		if d.Status == audit.DeliveryPending {
			next = stamp(d.NextAttemptAt)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.DecisionID, d.Effect, d.Status, d.Attempts,
			stamp(d.CreatedAt), stamp(d.RequeuedAt), stamp(d.UpdatedAt), next, lastOutcome(d))
	}
	_ = tw.Flush()
	if len(ds) == *limit {
		fmt.Fprintf(c.stdout, "\nshowing the first %d; raise --limit to see more\n", *limit)
	}
	return exitOK
}

func (c *cli) outboxRetry(ctx context.Context, args []string) int {
	fs := c.flagSet("outbox retry", `Usage: catraca outbox retry --audit <dsn> <id>...
       catraca outbox retry --audit <dsn> --dead [--hook <name>] [--since 24h]

Requeues dead webhook deliveries once their receiver is fixed: the ones
named by id, or with --dead every dead one, of one hook or that died since
a time. A requeued delivery is due at once, with the same body and
idempotency key; its attempts and its max_age start over. A running server
sends it within its poll interval. Deliveries that are not dead are left
alone.
`)
	dsn := c.auditFlag(fs)
	dead := fs.Bool("dead", false, "requeue every dead delivery, or those --hook and --since select")
	hook := fs.String("hook", "", "with --dead, only the deliveries for this hook")
	since := fs.String("since", "", "with --dead, only the deliveries that died since then: a duration such as 24h or 7d, or an RFC 3339 time")
	pos, code := parse(fs, args, 0, -1)
	if code >= 0 {
		return code
	}
	switch {
	case *dead && len(pos) > 0:
		c.errorf("pass delivery ids or --dead, not both")
		return exitUsage
	case !*dead && len(pos) == 0:
		c.errorf("name the deliveries to requeue by id, or pass --dead")
		return exitUsage
	case !*dead && (*hook != "" || *since != ""):
		c.errorf("--hook and --since select dead deliveries: pass --dead with them")
		return exitUsage
	}
	var ids []int64
	for _, p := range pos {
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil || id <= 0 {
			c.errorf("%q is not a delivery id: ids are positive integers, as outbox list prints them", p)
			return exitUsage
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	from, code := c.since(*since)
	if code >= 0 {
		return code
	}
	db, code := c.openAudit(ctx, *dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)

	requeued, err := db.Requeue(ctx, audit.DeliveryFilter{IDs: ids, Effect: *hook, Since: from}, time.Now())
	if err != nil {
		c.errorf("%v", err)
		if len(requeued) > 0 {
			c.errorf("requeued %d deliveries before the error", len(requeued))
		}
		return exitError
	}
	if *dead {
		what := "dead deliveries"
		if *hook != "" {
			what += " for " + *hook
		}
		if !from.IsZero() {
			what += " that died since " + stamp(from)
		}
		fmt.Fprintf(c.stdout, "requeued %d %s\n", len(requeued), what)
		return exitOK
	}

	// Say why each delivery that was named but not requeued was left alone.
	var missed []int64
	for _, id := range ids {
		if !slices.Contains(requeued, id) {
			missed = append(missed, id)
		}
	}
	if len(missed) > 0 {
		found, err := db.ListDeliveries(ctx, audit.DeliveryFilter{IDs: missed}, len(missed))
		if err != nil {
			c.errorf("%v", err)
			return exitError
		}
		for _, id := range missed {
			i := slices.IndexFunc(found, func(d audit.Delivery) bool { return d.ID == id })
			if i < 0 {
				fmt.Fprintf(c.stderr, "delivery %d does not exist\n", id)
				continue
			}
			fmt.Fprintf(c.stderr, "delivery %d is %s, not dead: left alone\n", id, found[i].Status)
		}
	}
	var list []string
	for _, id := range requeued {
		list = append(list, strconv.FormatInt(id, 10))
	}
	fmt.Fprintf(c.stdout, "requeued %d of %d deliveries", len(requeued), len(ids))
	if len(list) > 0 {
		fmt.Fprintf(c.stdout, ": %s", strings.Join(list, ", "))
	}
	fmt.Fprintln(c.stdout)
	if len(missed) > 0 {
		return exitFailed
	}
	return exitOK
}

func (c *cli) outboxStats(ctx context.Context, args []string) int {
	fs := c.flagSet("outbox stats", `Usage: catraca outbox stats --audit <dsn> [--json]

Counts the webhook deliveries in the outbox for each hook: pending, due now,
how long the oldest pending one has waited, dead and delivered. It reads
the whole outbox.
`)
	dsn := c.auditFlag(fs)
	asJSON := fs.Bool("json", false, "print the counts as JSON")
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	db, code := c.openAudit(ctx, *dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)
	now := time.Now()
	stats, err := db.OutboxStats(ctx, now)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(stats); err != nil {
			return exitError
		}
		return exitOK
	}
	if len(stats) == 0 {
		fmt.Fprintln(c.stdout, "the outbox is empty")
		return exitOK
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOOK\tPENDING\tDUE\tOLDEST PENDING\tDEAD\tDELIVERED")
	for _, s := range stats {
		oldest := "-"
		if s.Pending > 0 {
			oldest = max(0, now.Sub(s.Oldest)).Round(time.Second).String()
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%d\t%d\n", s.Effect, s.Pending, s.Due, oldest, s.Dead, s.Delivered)
	}
	_ = tw.Flush()
	return exitOK
}

// deliveryStatus parses --status. Empty means any.
func (c *cli) deliveryStatus(s string) (audit.DeliveryStatus, int) {
	switch st := audit.DeliveryStatus(s); st {
	case "", audit.DeliveryPending, audit.DeliveryDead, audit.DeliveryDelivered:
		return st, -1
	}
	c.errorf("--status must be pending, dead or delivered, got %q", s)
	return "", exitUsage
}

// stamp prints a time to the second in UTC, or "-" for none.
func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// maxLast bounds the last outcome in a listing, which may quote a response.
const maxLast = 80

// lastOutcome is a delivery's last status code and error on one line.
func lastOutcome(d audit.Delivery) string {
	s := strings.Join(strings.Fields(d.LastError), " ")
	if d.LastStatusCode > 0 && !strings.HasPrefix(s, "HTTP ") {
		s = strings.TrimSpace(fmt.Sprintf("%d %s", d.LastStatusCode, s))
	}
	if utf8.RuneCountInString(s) > maxLast {
		s = string([]rune(s)[:maxLast]) + "..."
	}
	if s == "" {
		return "-"
	}
	return s
}
