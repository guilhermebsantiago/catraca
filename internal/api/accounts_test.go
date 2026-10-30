package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

func withStates(states AccountStates) func(*Options) {
	return func(o *Options) { o.AccountStates = states }
}

func decodeState(t *testing.T, body *bytes.Buffer) AccountStateResponse {
	t.Helper()
	var got AccountStateResponse
	if err := json.Unmarshal(body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return got
}

func TestAccountStateRoutes(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, deciderFunc(nil), slog.New(slog.NewJSONHandler(&logs, nil)),
		withStates(signal.NewAccountStates(store.NewMemory())),
		func(o *Options) { o.Now = func() time.Time { return now } })

	rec := serve(s, "GET", "/v1/accounts/acct_1/state", "")
	if rec.Code != 200 {
		t.Fatalf("GET before any state: %d %s", rec.Code, rec.Body)
	}
	if got := decodeState(t, rec.Body); got.AccountID != "acct_1" || got.State != "active" || !got.SetAt.IsZero() {
		t.Errorf("GET before any state = %+v, want active", got)
	}

	until := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	rec = serve(s, "PUT", "/v1/accounts/acct_1/state",
		`{"state": "suspended", "until": "`+until.Format(time.RFC3339)+`", "reason": "chargeback fraud, ticket 4411"}`)
	if rec.Code != 200 {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	want := AccountStateResponse{AccountID: "acct_1", AccountState: signal.AccountState{
		State: "suspended", Until: until, Reason: "chargeback fraud, ticket 4411", SetAt: now, SetBy: "b",
	}}
	if got := decodeState(t, rec.Body); got != want {
		t.Errorf("PUT = %+v, want %+v", got, want)
	}
	if rec = serve(s, "GET", "/v1/accounts/acct_1/state", ""); rec.Code != 200 {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	if got := decodeState(t, rec.Body); got != want {
		t.Errorf("GET after PUT = %+v, want %+v", got, want)
	}
	for _, line := range []string{`"msg":"account state changed"`, `"account_id":"acct_1"`, `"state":"suspended"`, `"set_by":"b"`, `"reason":"chargeback fraud, ticket 4411"`, `"route":"PUT /v1/accounts/{id}/state"`} {
		if !strings.Contains(logs.String(), line) {
			t.Errorf("logs lack %s:\n%s", line, logs.String())
		}
	}

	rec = serve(s, "DELETE", "/v1/accounts/acct_1/state", "")
	if rec.Code != 200 {
		t.Fatalf("DELETE: %d %s", rec.Code, rec.Body)
	}
	if got := decodeState(t, rec.Body); got.State != "active" || got.Reason != "" {
		t.Errorf("DELETE = %+v, want active", got)
	}
	if got := decodeState(t, serve(s, "GET", "/v1/accounts/acct_1/state", "").Body); got.State != "active" {
		t.Errorf("GET after DELETE = %+v, want active", got)
	}

	// Setting active is a reset too.
	serve(s, "PUT", "/v1/accounts/acct_1/state", `{"state": "review"}`)
	if rec = serve(s, "PUT", "/v1/accounts/acct_1/state", `{"state": "active"}`); rec.Code != 200 {
		t.Fatalf("PUT active: %d %s", rec.Code, rec.Body)
	}
	if got := decodeState(t, serve(s, "GET", "/v1/accounts/acct_1/state", "").Body); got.State != "active" {
		t.Errorf("GET after PUT active = %+v, want active", got)
	}
}

func TestAccountStateErrors(t *testing.T) {
	s := newTestServer(t, deciderFunc(nil), nil, withStates(signal.NewAccountStates(store.NewMemory())))
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"unknown state", "PUT", "/v1/accounts/a/state", `{"state": "banned"}`, 400, "invalid_state"},
		{"no state", "PUT", "/v1/accounts/a/state", `{"reason": "x"}`, 400, "invalid_state"},
		{"past until", "PUT", "/v1/accounts/a/state", `{"state": "review", "until": "2020-01-01T00:00:00Z"}`, 400, "invalid_state"},
		{"bad until", "PUT", "/v1/accounts/a/state", `{"state": "review", "until": "friday"}`, 400, "invalid_json"},
		{"unknown field", "PUT", "/v1/accounts/a/state", `{"state": "review", "ttl": "72h"}`, 400, "invalid_json"},
		{"long id", "GET", "/v1/accounts/" + strings.Repeat("a", 257) + "/state", "", 400, "invalid_account_id"},
		{"other method", "POST", "/v1/accounts/a/state", "{}", 405, "method_not_allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(s, tc.method, tc.path, tc.body)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) {
				t.Errorf("%d %s, want %d %s", rec.Code, rec.Body, tc.status, tc.code)
			}
		})
	}
	if allow := serve(s, "POST", "/v1/accounts/a/state", "{}").Header().Get("Allow"); allow != "GET, PUT, DELETE" {
		t.Errorf("Allow = %q, want GET, PUT, DELETE", allow)
	}
}

func TestAccountStateUnreadable(t *testing.T) {
	m := store.NewMemory()
	var b store.Batch
	b.Set("account:state:a", "{", 0)
	if err := m.Do(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, deciderFunc(nil), nil, withStates(signal.NewAccountStates(m)))
	if rec := serve(s, "GET", "/v1/accounts/a/state", ""); rec.Code != 500 || !strings.Contains(rec.Body.String(), `"code":"internal"`) {
		t.Errorf("GET of an unreadable state: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(s, "DELETE", "/v1/accounts/a/state", ""); rec.Code != 200 {
		t.Errorf("DELETE of an unreadable state: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(s, "GET", "/v1/accounts/a/state", ""); rec.Code != 200 {
		t.Errorf("GET after DELETE: %d %s", rec.Code, rec.Body)
	}
}

type failingStates struct{}

func (failingStates) Get(context.Context, string) (signal.AccountState, error) {
	return signal.AccountState{}, errors.New("redis: connection refused")
}
func (failingStates) Set(context.Context, string, signal.AccountState) error {
	return errors.New("redis: connection refused")
}
func (failingStates) Reset(context.Context, string) error {
	return errors.New("redis: connection refused")
}

func TestAccountStateStoreDown(t *testing.T) {
	s := newTestServer(t, deciderFunc(nil), nil, withStates(failingStates{}))
	for _, req := range [][3]string{
		{"GET", "/v1/accounts/a/state", ""},
		{"PUT", "/v1/accounts/a/state", `{"state": "suspended"}`},
		{"DELETE", "/v1/accounts/a/state", ""},
	} {
		rec := serve(s, req[0], req[1], req[2])
		if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"code":"store_unavailable"`) || strings.Contains(rec.Body.String(), "refused") {
			t.Errorf("%s: %d %s, want 503 store_unavailable without the cause", req[0], rec.Code, rec.Body)
		}
	}
}

func TestAccountStateNotConfigured(t *testing.T) {
	s := newTestServer(t, deciderFunc(nil), nil)
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		rec := serve(s, m, "/v1/accounts/a/state", `{"state": "review"}`)
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"code":"not_configured"`) {
			t.Errorf("%s: %d %s", m, rec.Code, rec.Body)
		}
	}
}

func TestAccountStateNeedsToken(t *testing.T) {
	s := newTestServer(t, deciderFunc(nil), nil, withStates(signal.NewAccountStates(store.NewMemory())))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("PUT", "/v1/accounts/a/state", strings.NewReader(`{"state": "trusted"}`)))
	if rec.Code != 401 {
		t.Errorf("PUT without a token: %d %s", rec.Code, rec.Body)
	}
}
