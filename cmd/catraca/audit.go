package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/replay"
)

// replayLabel maps what the labels of a decision say about its event to a
// replay label: abusive when a label that applies says a rule was right,
// legit when every one says it was wrong. See audit.Entry.Verdict.
func replayLabel(e audit.Entry) replay.Label {
	v, ok := e.Verdict()
	switch {
	case !ok:
		return replay.Unlabeled
	case v == audit.TruePositive:
		return replay.Abusive
	}
	return replay.Legit
}

func (c *cli) auditExport(ctx context.Context, args []string) int {
	fs := c.flagSet("audit export", `Usage: catraca audit export --audit <dsn> [--since 30d] [--labeled-only] [--out file]

Writes the decisions in the audit database as a replay file, oldest first:
one {"event": {...}, "label": "abusive" | "legit"} per line, ready for
catraca replay. A decision whose labels say any rule was right (a
true_positive that applies) is abusive; one whose labels all say the rules
were wrong (false_positive) is legit; an unlabeled one has no label, and
--labeled-only leaves it out.

With audit.event_detail: minimal, the log keeps no recipients, subject,
links or attributes, and only the sender's domain: rules that read them
cannot match the export as they did in production. It says so on stderr.
`)
	dsn := c.auditFlag(fs)
	since := fs.String("since", "30d", `only decisions made since then: a duration such as 720h or 30d, an RFC 3339 time, or "all"`)
	labeledOnly := fs.Bool("labeled-only", false, "leave out decisions without a label")
	out := fs.String("out", "", "write to this file instead of stdout")
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
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

	var w io.Writer = c.stdout
	var f *os.File
	if *out != "" {
		var err error
		if f, err = os.Create(*out); err != nil {
			c.errorf("%v", err)
			return exitError
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	var (
		n, abusive, legit, minimal, reordered int
		last                                  time.Time
	)
	err := db.Export(ctx, from, *labeledOnly, func(e audit.Entry) error {
		ev, full := e.Event.ReplayEvent()
		if !full {
			minimal++
		}
		if ev.Time.IsZero() {
			ev.Time = e.Decision.Time
		}
		// Replay wants events in time order; the log is in decision order,
		// and an event can carry a time a little before the one decided
		// before it.
		if ev.Time.Before(last) {
			ev.Time = last
			reordered++
		}
		last = ev.Time
		ex := replay.Example{Event: ev, Label: replayLabel(e)}
		switch ex.Label {
		case replay.Abusive:
			abusive++
		case replay.Legit:
			legit++
		}
		n++
		return enc.Encode(ex)
	})
	if err == nil {
		err = bw.Flush()
	}
	if err == nil && f != nil {
		err = f.Close()
	}
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	fmt.Fprintf(c.stderr, "exported %d decisions: %d abusive, %d legit, %d unlabeled\n", n, abusive, legit, n-abusive-legit)
	if minimal > 0 {
		fmt.Fprintf(c.stderr, "warning: %d of the events were stored with audit.event_detail: minimal, without recipients, subject, links or attributes and with only the sender's domain; rules that read them cannot match as they did in production\n", minimal)
	}
	if reordered > 0 {
		fmt.Fprintf(c.stderr, "warning: %d events were older than the event decided before them; their times were raised to keep the file in time order\n", reordered)
	}
	return exitOK
}

func (c *cli) decisions(ctx context.Context, args []string) int {
	fs := c.flagSet("decisions", `Usage: catraca decisions --audit <dsn> [--account <id>] [--api-key <id>] [--ip <ip>] [--action <action>] [--since 24h] [--until <time>] [--limit 50] [--cursor <c>] [--json]

Lists decisions in the audit database, newest first, filtered by account,
API key, client IP, action and time. When there are more, it prints the
cursor that continues the list. GET /v1/decisions answers the same query
on a running server.
`)
	dsn := c.auditFlag(fs)
	account := fs.String("account", "", "only this account's decisions")
	key := fs.String("api-key", "", "only the decisions on events sent with this API key")
	ip := fs.String("ip", "", "only the decisions on events from this client IP")
	action := fs.String("action", "", "only decisions with this action: allow, flag, throttle, hold or block")
	since := fs.String("since", "", "only decisions made since then: a duration such as 24h or 7d, or an RFC 3339 time")
	until := fs.String("until", "", "only decisions made before then: an RFC 3339 time or a date")
	limit := fs.Int("limit", 50, "the most decisions to list, up to 1000")
	cursor := fs.String("cursor", "", "continue a list where the cursor it printed says")
	asJSON := fs.Bool("json", false, "print the page as JSON")
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	if *limit < 1 || *limit > 1000 {
		c.errorf("--limit must be from 1 to 1000")
		return exitUsage
	}
	if *action != "" {
		if _, err := decision.ParseAction(*action); err != nil {
			c.errorf("--action: %v", err)
			return exitUsage
		}
	}
	from, code := c.since(*since)
	if code >= 0 {
		return code
	}
	var to time.Time
	if *until != "" {
		var err error
		if to, err = parseTime(*until); err != nil {
			c.errorf("--until: want an RFC 3339 time or a date, got %q", *until)
			return exitUsage
		}
	}
	db, code := c.openAudit(ctx, *dsn)
	if db == nil {
		return code
	}
	defer db.Close(ctx)

	page, err := db.ListDecisions(ctx, audit.DecisionFilter{AccountID: *account, APIKeyID: *key, IP: *ip,
		Action: decision.Action(*action), Since: from, Until: to, Cursor: *cursor}, *limit)
	if errors.Is(err, audit.ErrInvalidCursor) {
		c.errorf("--cursor: %v", err)
		return exitUsage
	}
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(page); err != nil {
			return exitError
		}
		return exitOK
	}
	if len(page.Decisions) == 0 {
		fmt.Fprintln(c.stdout, "no decisions")
		return exitOK
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DECISION\tTIME\tACTION\tTYPE\tACCOUNT\tAPI KEY\tIP\tRULES")
	for _, it := range page.Decisions {
		rules := ""
		for _, m := range it.Decision.Matches {
			rules += sep(rules) + m.RuleID
		}
		for _, m := range it.Decision.Shadow {
			rules += sep(rules) + m.RuleID + " (shadow)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", it.Decision.ID, stamp(it.Decision.Time), it.Decision.Action,
			it.Event.Type, dash(it.Event.AccountID), dash(it.Event.APIKeyID), dash(it.Event.IP), dash(rules))
	}
	_ = tw.Flush()
	if page.Next != "" {
		fmt.Fprintf(c.stdout, "\nmore decisions: pass --cursor %s\n", page.Next)
	}
	return exitOK
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse(time.DateOnly, s)
}

func sep(s string) string {
	if s == "" {
		return ""
	}
	return ", "
}
