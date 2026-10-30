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
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
)

func (c *cli) accountState(ctx context.Context, args []string) int {
	fs := c.flagSet("account state", `Usage: catraca account state <account-id> [--set review|suspended|trusted|active [--until <duration or time>] [--reason <why>]] [--reset]

Prints the state of an account on a running server, or sets it with --set
and resets it to active with --reset. Rules read it as account.state. The
token comes from --token or $CATRACA_TOKEN.
`)
	set := fs.String("set", "", "the state to set: review, suspended, trusted, or active to reset")
	until := fs.String("until", "", "when the state expires: a duration from now, such as 72h, or an RFC 3339 time")
	reason := fs.String("reason", "", "why, such as a ticket number")
	reset := fs.Bool("reset", false, "reset the account to active")
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
	case *reset && *set != "":
		c.errorf("--reset and --set cannot be used together")
		return exitUsage
	case *set == "" && (*until != "" || *reason != ""):
		c.errorf("--until and --reason go with --set")
		return exitUsage
	}
	base, err := url.Parse(*server)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		c.errorf("--server must be an http or https URL, got %q", *server)
		return exitUsage
	}

	method, body := http.MethodGet, []byte(nil)
	switch {
	case *reset:
		method = http.MethodDelete
	case *set != "":
		req := api.AccountStateRequest{State: *set, Reason: *reason}
		if *until != "" {
			if req.Until, err = parseUntil(*until, time.Now()); err != nil {
				c.errorf("--until: %v", err)
				return exitUsage
			}
		}
		if body, err = json.Marshal(req); err != nil {
			return exitError
		}
		method = http.MethodPut
	}
	endpoint := strings.TrimSuffix(base.String(), "/") + "/v1/accounts/" + url.PathEscape(pos[0]) + "/state"
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "catraca-cli/"+version)
	resp, err := c.client.Do(req)
	if err != nil {
		c.errorf("%v", err)
		return exitError
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.errorf("reading the answer: %v", err)
		return exitError
	}
	if resp.StatusCode != http.StatusOK {
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
	var st api.AccountStateResponse
	if err := json.Unmarshal(data, &st); err != nil {
		c.errorf("decoding the answer: %v", err)
		return exitError
	}
	line := fmt.Sprintf("account %s is %s", st.AccountID, st.State)
	if !st.Until.IsZero() {
		line += " until " + st.Until.Format(time.RFC3339)
	}
	if !st.SetAt.IsZero() {
		line += ", set " + st.SetAt.Format(time.RFC3339)
		if st.SetBy != "" {
			line += " by " + st.SetBy
		}
	}
	if st.Reason != "" {
		line += ": " + st.Reason
	}
	fmt.Fprintln(c.stdout, line)
	return exitOK
}

// parseUntil reads --until: a duration from now, such as 72h, or an RFC
// 3339 time.
func parseUntil(s string, now time.Time) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("%s is not in the future", s)
		}
		return now.Add(d).UTC().Truncate(time.Second), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("want a duration such as 72h or an RFC 3339 time such as 2026-11-01T18:00:00Z, got %q", s)
	}
	return t, nil
}
