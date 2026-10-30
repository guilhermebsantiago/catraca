package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

type noDecider struct{}

func (noDecider) Decide(context.Context, event.Event) (decision.Decision, error) {
	return decision.Decision{}, errors.New("not used")
}

func (noDecider) DecideWithoutStore(context.Context, event.Event) (decision.Decision, error) {
	return decision.Decision{}, errors.New("not used")
}

type noRules struct{}

func (noRules) Current() *rules.Ruleset { return nil }

type noAudit struct{}

func (noAudit) Get(context.Context, string) (audit.Entry, error) {
	return audit.Entry{}, audit.ErrNotFound
}
func (noAudit) Label(context.Context, string, audit.Label) error { return audit.ErrNotFound }
func (noAudit) RuleStats(context.Context, time.Time) ([]precision.RuleStats, error) {
	return nil, nil
}
func (noAudit) ReviewQueue(context.Context, string, decision.Mode, int) ([]audit.ReviewItem, error) {
	return nil, nil
}
func (noAudit) ListDecisions(context.Context, audit.DecisionFilter, int) (audit.DecisionPage, error) {
	return audit.DecisionPage{}, nil
}
func (noAudit) Flush(context.Context) error { return nil }

// TestAccountState runs the command against the API's account state routes
// on a memory store.
func TestAccountState(t *testing.T) {
	s, err := api.New(api.Options{
		Decider:       noDecider{},
		Rules:         noRules{},
		Audit:         noAudit{},
		AccountStates: signal.NewAccountStates(store.NewMemory()),
		Tokens:        []api.Token{{Name: "ops", Value: testToken}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	defer srv.Close()
	env := map[string]string{"CATRACA_TOKEN": testToken, "CATRACA_SERVER": srv.URL}

	expect(t, runCLI(t, env, "account", "state", "acct_1"), exitOK, "account acct_1 is active\n")
	r := runCLI(t, env, "account", "state", "acct_1", "--set", "suspended", "--until", "72h", "--reason", "ticket 4411")
	expect(t, r, exitOK, "account acct_1 is suspended until ", " by ops: ticket 4411")
	expect(t, runCLI(t, env, "account", "state", "acct_1"), exitOK, "account acct_1 is suspended until ", "ticket 4411")
	expect(t, runCLI(t, env, "account", "state", "acct_1", "--set", "trusted", "--until", "2099-01-01T00:00:00Z"), exitOK,
		"account acct_1 is trusted until 2099-01-01T00:00:00Z")
	expect(t, runCLI(t, env, "account", "state", "acct_1", "--reset"), exitOK, "account acct_1 is active\n")
	expect(t, runCLI(t, env, "account", "state", "acct_1"), exitOK, "account acct_1 is active\n")

	expect(t, runCLI(t, env, "account", "state", "acct_1", "--set", "banned"), exitFailed, "400", "invalid_state")
	expect(t, runCLI(t, env, "account", "state", "acct_1", "--set", "review", "--until", "friday"), exitUsage, "--until")
	expect(t, runCLI(t, env, "account", "state", "acct_1", "--set", "review", "--until", "-1h"), exitUsage, "not in the future")
	expect(t, runCLI(t, env, "account", "state", "acct_1", "--reset", "--set", "review"), exitUsage, "cannot be used together")
	expect(t, runCLI(t, env, "account", "state", "acct_1", "--reason", "x"), exitUsage, "go with --set")
	expect(t, runCLI(t, map[string]string{"CATRACA_SERVER": srv.URL}, "account", "state", "acct_1"), exitUsage, "token is required")
	expect(t, runCLI(t, map[string]string{"CATRACA_TOKEN": "wrong-token-0123456789"}, "account", "state", "acct_1", "--server", srv.URL), exitFailed, "401")
	expect(t, runCLI(t, env, "account"), exitUsage, "catraca account <state>")
}
