package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

func (c *cli) label(ctx context.Context, args []string) int {
	fs := c.flagSet("label", `Usage: catraca label <decision-id> --verdict true_positive|false_positive --by <who> [--reason <why>] [--rule <id>]

Labels a decision on a running server. A false positive on an enforced
decision is a reversal: it counts against every rule that matched it, or
only against --rule. The token comes from --token or $CATRACA_TOKEN.
`)
	verdict := fs.String("verdict", "", "true_positive (the rule was right) or false_positive (it was wrong)")
	by := fs.String("by", "", "who gives the label, such as a reviewer's email (required)")
	reason := fs.String("reason", "", "why, such as an appeal or ticket number")
	rule := fs.String("rule", "", "label only this rule's match instead of the whole decision")
	server := fs.String("server", or(c.getenv("CATRACA_SERVER"), "http://localhost:8080"), "the server's base URL (default from $CATRACA_SERVER)")
	token := fs.String("token", "", "the API token (default $CATRACA_TOKEN)")
	pos, code := parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	tok := or(*token, c.getenv("CATRACA_TOKEN"))
	switch {
	case tok == "":
		c.errorf("an API token is required: pass --token or set CATRACA_TOKEN")
		return exitUsage
	case *verdict != string(audit.TruePositive) && *verdict != string(audit.FalsePositive):
		c.errorf("--verdict must be true_positive or false_positive")
		return exitUsage
	case *by == "":
		c.errorf("--by is required: who gives the label")
		return exitUsage
	}
	base, err := url.Parse(*server)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		c.errorf("--server must be an http or https URL, got %q", *server)
		return exitUsage
	}

	id := pos[0]
	body, err := json.Marshal(audit.Label{RuleID: *rule, Verdict: audit.Verdict(*verdict), By: *by, Reason: *reason})
	if err != nil {
		return exitError
	}
	endpoint := strings.TrimSuffix(base.String(), "/") + "/v1/decisions/" + url.PathEscape(id) + "/labels"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "catraca-cli/"+version)
	resp, err := c.client.Do(req)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		c.errorf("reading the answer: %v", err)
		return exitError
	}

	if resp.StatusCode != http.StatusCreated {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Code + ": " + e.Error.Message
		}
		c.errorf("the server answered %s: %s", resp.Status, msg)
		if resp.StatusCode >= 500 {
			return exitError
		}
		return exitFailed
	}
	var entry audit.Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		c.errorf("decoding the answer: %v", err)
		return exitError
	}
	target := "every rule that matched"
	if *rule != "" {
		target = "rule " + *rule
	}
	fmt.Fprintf(c.stdout, "labeled decision %s %s for %s; it has %d label(s)\n", id, *verdict, target, len(entry.Labels))
	return exitOK
}

// or returns a, or b when a is empty.
func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
