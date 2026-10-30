package api

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// docErrorRow is a row of the error table in docs/api.md:
// "| 400 | `invalid_json` | ...".
var docErrorRow = regexp.MustCompile("^\\| (\\d{3}) \\| `([a-z_]+)` \\|")

// documentedErrors returns the status of every error code docs/api.md
// lists.
func documentedErrors(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open("../../docs/api.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := docErrorRow.FindStringSubmatch(sc.Text()); m != nil {
			status, _ := strconv.Atoi(m[1])
			out[m[2]] = status
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no error table found in docs/api.md; did its format change?")
	}
	return out
}

// TestEveryDocumentedErrorIsProduced sends, for each error code in the
// docs/api.md table, a request that gets it, with the status the table
// gives. A code added to the table needs a request here, and a code a
// route answers needs a row there.
func TestEveryDocumentedErrorIsProduced(t *testing.T) {
	failing := func(err error) Decider {
		return deciderFunc(func(context.Context, event.Event) (decision.Decision, error) { return decision.Decision{}, err })
	}
	ok := failing(nil)
	withAudit := func(err error) func(*Options) { return func(o *Options) { o.Audit = fakeAudit{err: err} } }
	const ev = `{"type":"send","account_id":"a"}`
	const label = `{"verdict":"true_positive","by":"ana"}`

	cases := map[string]func(t *testing.T) *httptest.ResponseRecorder{
		"invalid_json": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil), "POST", "/v1/decide", "{")
		},
		"invalid_event": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, failing(fmt.Errorf("%w: no account", engine.ErrInvalidEvent)), nil), "POST", "/v1/decide", ev)
		},
		"invalid_label": func(t *testing.T) *httptest.ResponseRecorder {
			s := newTestServer(t, ok, nil, withAudit(fmt.Errorf("%w: by is required", audit.ErrInvalidLabel)))
			return serve(s, "POST", "/v1/decisions/d1/labels", label)
		},
		"invalid_parameter": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil), "GET", "/v1/stats/rules?since=yesterday", "")
		},
		"invalid_state": func(t *testing.T) *httptest.ResponseRecorder {
			s := newTestServer(t, ok, nil, withStates(signal.NewAccountStates(store.NewMemory())))
			return serve(s, "PUT", "/v1/accounts/a/state", `{"state":"banned"}`)
		},
		"invalid_account_id": func(t *testing.T) *httptest.ResponseRecorder {
			s := newTestServer(t, ok, nil, withStates(signal.NewAccountStates(store.NewMemory())))
			return serve(s, "PUT", "/v1/accounts/"+strings.Repeat("a", 300)+"/state", `{"state":"review"}`)
		},
		"unauthorized": func(t *testing.T) *httptest.ResponseRecorder {
			return send(newTestServer(t, ok, nil), "GET", "/v1/rules", "", "")
		},
		"insufficient_scope": func(t *testing.T) *httptest.ResponseRecorder {
			var logs bytes.Buffer
			return send(newScopedServer(t, &logs, nil), "POST", "/v1/rules/reload", "", "tok-read-0123456789")
		},
		"not_found": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil, withAudit(audit.ErrNotFound)), "GET", "/v1/decisions/d1", "")
		},
		"not_configured": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil), "POST", "/v1/feedback", "{}")
		},
		"method_not_allowed": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil), "GET", "/v1/decide", "")
		},
		"body_too_large": func(t *testing.T) *httptest.ResponseRecorder {
			s := newTestServer(t, ok, nil, func(o *Options) { o.MaxBodyBytes = 8 })
			return serve(s, "POST", "/v1/decide", ev)
		},
		"rule_not_matched": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil, withAudit(audit.ErrRuleNotMatched)), "POST", "/v1/decisions/d1/labels", label)
		},
		"invalid_ruleset": func(t *testing.T) *httptest.ResponseRecorder {
			s := newTestServer(t, ok, nil, func(o *Options) {
				o.Reload = func() (*rules.Ruleset, error) { return nil, errors.New("rules.yaml: version is required") }
			})
			return serve(s, "POST", "/v1/rules/reload", "")
		},
		"internal": func(t *testing.T) *httptest.ResponseRecorder {
			panics := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) { panic("boom") })
			return serve(newTestServer(t, panics, nil), "POST", "/v1/decide", ev)
		},
		"no_ruleset": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil), "GET", "/v1/rules", "")
		},
		"unavailable": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, failing(errors.New("store down")), nil), "POST", "/v1/decide", ev)
		},
		"overloaded": func(t *testing.T) *httptest.ResponseRecorder {
			shed := failing(fmt.Errorf("engine: mark key k leaked: %w", engine.ErrWithoutStore))
			return serve(newTestServer(t, shed, nil), "POST", "/v1/events", `{"type":"key_leak","api_key_id":"k"}`)
		},
		"store_unavailable": func(t *testing.T) *httptest.ResponseRecorder {
			return serve(newTestServer(t, ok, nil, withStates(failingStates{})), "GET", "/v1/accounts/a/state", "")
		},
		"audit_unavailable": func(t *testing.T) *httptest.ResponseRecorder {
			err := fmt.Errorf("opening: %w", ErrAuditUnavailable)
			return serve(newTestServer(t, ok, nil, withAudit(err)), "GET", "/v1/decisions/d1", "")
		},
	}

	documented := documentedErrors(t)
	for code, status := range documented {
		req, ok := cases[code]
		if !ok {
			t.Errorf("docs/api.md lists %s, which no case here produces: add a request that gets it", code)
			continue
		}
		t.Run(code, func(t *testing.T) {
			rec := req(t)
			if rec.Code != status || !strings.Contains(rec.Body.String(), `"code":"`+code+`"`) {
				t.Errorf("%d %s, want %d %s", rec.Code, rec.Body, status, code)
			}
			if rec.Code == http.StatusServiceUnavailable && code != "no_ruleset" && code != "store_unavailable" && rec.Header().Get("Retry-After") == "" {
				t.Errorf("%s answered without Retry-After", code)
			}
		})
	}
	for code := range cases {
		if _, ok := documented[code]; !ok {
			t.Errorf("%s is produced but not in the error table of docs/api.md", code)
		}
	}
}
