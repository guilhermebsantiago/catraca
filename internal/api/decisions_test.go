package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// listAudit answers ListDecisions from the real SQLite log, so the route is
// tested with the filters and cursors the database applies.
type listAudit struct {
	fakeAudit
	db *audit.DB
}

func (l listAudit) ListDecisions(ctx context.Context, f audit.DecisionFilter, limit int) (audit.DecisionPage, error) {
	return l.db.ListDecisions(ctx, f, limit)
}
func (l listAudit) Flush(ctx context.Context) error { return l.db.Flush(ctx) }

func TestListDecisions(t *testing.T) {
	ctx := context.Background()
	db, err := audit.Open(ctx, "sqlite::memory:", audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(ctx) })
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		at := now.Add(time.Duration(i-5) * time.Hour)
		d := decision.Decision{ID: fmt.Sprintf("d%d", i), Time: at, Action: decision.Allow, RulesetVersion: "v"}
		if i%2 == 1 {
			d.Action = decision.Block
		}
		ev := event.Event{ID: "ev-" + d.ID, Type: event.Send, Time: at, AccountID: []string{"a", "b"}[i%2],
			APIKeyID: "key-1", IP: fmt.Sprintf("203.0.113.%d", i)}
		db.Record(ctx, ev, d)
	}
	allow := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		return decision.Decision{Action: decision.Allow}, nil
	})
	s := newTestServer(t, allow, slog.New(slog.DiscardHandler), func(o *Options) {
		o.Audit = listAudit{db: db}
		o.Now = func() time.Time { return now }
	})

	ids := func(rec *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var page audit.DecisionPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, it := range page.Decisions {
			out = append(out, it.Decision.ID)
		}
		return strings.Join(out, ","), page.Next
	}
	for _, tt := range []struct{ query, want string }{
		{"", "d4,d3,d2,d1,d0"},
		{"?account_id=a", "d4,d2,d0"},
		{"?api_key_id=nope", ""},
		{"?ip=203.0.113.3", "d3"},
		{"?action=block", "d3,d1"},
		{"?since=3h", "d4,d3,d2"},
		{"?until=3h", "d1,d0"},
		{"?since=2026-10-01T08:00:00Z&until=2026-10-01T10:00:00Z", "d2,d1"},
	} {
		if got, _ := ids(serve(s, "GET", "/v1/decisions"+tt.query, "")); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.query, got, tt.want)
		}
	}

	var pages []string
	path := "/v1/decisions?limit=2"
	for range 5 {
		got, next := ids(serve(s, "GET", path, ""))
		pages = append(pages, got)
		if next == "" {
			break
		}
		path = "/v1/decisions?limit=2&cursor=" + next
	}
	if got := strings.Join(pages, "|"); got != "d4,d3|d2,d1|d0" {
		t.Errorf("pages = %s", got)
	}

	for _, q := range []string{"?action=explode", "?limit=0", "?limit=1001", "?since=later", "?until=-1h", "?cursor=!!"} {
		if rec := serve(s, "GET", "/v1/decisions"+q, ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_parameter") {
			t.Errorf("%s: status %d %s, want 400 invalid_parameter", q, rec.Code, rec.Body)
		}
	}

	// A database that fails answers 503 like the other audit routes.
	down := newTestServer(t, allow, slog.New(slog.DiscardHandler))
	if rec := serve(down, "GET", "/v1/decisions", ""); rec.Code < 500 {
		t.Errorf("failing database: status %d", rec.Code)
	}
}
