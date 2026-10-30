package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// recordAs records d with a send event from the given account, key and IP.
func recordAs(t *testing.T, db *DB, d decision.Decision, account, key, ip string) {
	t.Helper()
	ev := sendEvent(d.ID)
	ev.Time = d.Time
	ev.AccountID, ev.APIKeyID, ev.IP = account, key, ip
	db.Record(context.Background(), ev, d)
}

func pageIDs(p DecisionPage) string {
	var out []string
	for _, it := range p.Decisions {
		out = append(out, it.Decision.ID)
	}
	return strings.Join(out, ",")
}

func testListDecisions(t *testing.T, db *DB) {
	ctx := context.Background()
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Minute) }
	recordAs(t, db, newDecision("d0", at(0), nil, nil), "acct-a", "key-1", "203.0.113.1")
	recordAs(t, db, newDecision("d1", at(1), []string{"r1"}, nil), "acct-a", "key-2", "203.0.113.2")
	recordAs(t, db, newDecision("d2", at(2), nil, []string{"r2"}), "acct-b", "key-1", "203.0.113.1")
	recordAs(t, db, newDecision("d3", at(3), []string{"r1"}, nil), "acct-b", "key-3", "")
	// d4 and d5 share a time: the id breaks the tie.
	recordAs(t, db, newDecision("d4", at(4), nil, nil), "acct-a", "key-1", "203.0.113.1")
	recordAs(t, db, newDecision("d5", at(4), nil, nil), "acct-a", "key-1", "203.0.113.1")
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		f     DecisionFilter
		limit int
		want  string
	}{
		{"all", DecisionFilter{}, 0, "d5,d4,d3,d2,d1,d0"},
		{"account", DecisionFilter{AccountID: "acct-a"}, 0, "d5,d4,d1,d0"},
		{"api key", DecisionFilter{APIKeyID: "key-1"}, 0, "d5,d4,d2,d0"},
		{"ip", DecisionFilter{IP: "203.0.113.1"}, 0, "d5,d4,d2,d0"},
		{"action", DecisionFilter{Action: decision.Block}, 0, "d3,d1"},
		{"account and action", DecisionFilter{AccountID: "acct-b", Action: decision.Allow}, 0, "d2"},
		{"window", DecisionFilter{Since: at(1), Until: at(4)}, 0, "d3,d2,d1"},
		{"no match", DecisionFilter{AccountID: "acct-z"}, 0, ""},
		{"limit", DecisionFilter{}, 2, "d5,d4"},
	}
	for _, tt := range tests {
		p, err := db.ListDecisions(ctx, tt.f, tt.limit)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got := pageIDs(p); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}

	// Walking the pages lists every decision once, newest first, even when
	// newer decisions are recorded between pages.
	var walked []string
	f := DecisionFilter{AccountID: "acct-a"}
	for range 10 {
		p, err := db.ListDecisions(ctx, f, 1)
		if err != nil {
			t.Fatal(err)
		}
		walked = append(walked, pageIDs(p))
		if len(walked) == 1 {
			recordAs(t, db, newDecision("d6", at(9), nil, nil), "acct-a", "key-1", "")
			if err := db.Flush(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if p.Next == "" {
			break
		}
		f.Cursor = p.Next
	}
	if got := strings.Join(walked, ","); got != "d5,d4,d1,d0" {
		t.Errorf("pages = %q, want d5,d4,d1,d0", got)
	}
	p, err := db.ListDecisions(ctx, DecisionFilter{AccountID: "acct-a"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := pageIDs(p); got != "d6,d5,d4,d1" || p.Next == "" {
		t.Errorf("first page of 4 = %q, next %q; want d6,d5,d4,d1 and a cursor", got, p.Next)
	}
	if it := p.Decisions[0]; it.Event.AccountID != "acct-a" || it.Event.FromDomain != "sender.example" {
		t.Errorf("stored event = %+v", it.Event)
	}

	for _, c := range []string{"!!", "bm8tZG90", "eC5k"} {
		if _, err := db.ListDecisions(ctx, DecisionFilter{Cursor: c}, 0); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("cursor %q: err = %v, want ErrInvalidCursor", c, err)
		}
	}
	if _, err := db.ListDecisions(ctx, DecisionFilter{Action: "explode"}, 0); err == nil {
		t.Error("an unknown action was accepted")
	}
}

func testExport(t *testing.T, db *DB) {
	ctx := context.Background()
	// More decisions than one export page, so the pages are stitched.
	n := exportPage + 7
	for i := range n {
		db.Record(ctx, sendEvent(fmt.Sprintf("d%04d", i)), newDecision(fmt.Sprintf("d%04d", i), t0.Add(time.Duration(i)*time.Second), []string{"r1"}, nil))
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	label(t, db, "d0003", Label{Verdict: TruePositive, By: "ana"})
	label(t, db, "d0003", Label{RuleID: "r1", Verdict: FalsePositive, By: "bo", Time: time.Now().Add(time.Minute)})
	label(t, db, "d0505", Label{Verdict: FalsePositive, By: "appeals"})

	export := func(since time.Time, labeledOnly bool) []Entry {
		t.Helper()
		var out []Entry
		if err := db.Export(ctx, since, labeledOnly, func(e Entry) error {
			out = append(out, e)
			return nil
		}); err != nil {
			t.Fatalf("Export: %v", err)
		}
		return out
	}
	all := export(time.Time{}, false)
	if len(all) != n {
		t.Fatalf("exported %d decisions, want %d", len(all), n)
	}
	for i, e := range all {
		if want := fmt.Sprintf("d%04d", i); e.Decision.ID != want {
			t.Fatalf("decision %d is %s, want %s: oldest first", i, e.Decision.ID, want)
		}
	}
	if got := len(all[3].Labels); got != 2 {
		t.Errorf("d0003 has %d labels, want 2", got)
	}
	if v, ok := all[3].Verdict(); !ok || v != FalsePositive {
		t.Errorf("d0003 verdict = %q, %v; want the newer rule label, false_positive", v, ok)
	}
	if _, ok := all[4].Verdict(); ok {
		t.Error("an unlabeled decision has a verdict")
	}

	labeled := export(time.Time{}, true)
	if len(labeled) != 2 || labeled[0].Decision.ID != "d0003" || labeled[1].Decision.ID != "d0505" {
		t.Fatalf("labeled only = %d decisions, want d0003 and d0505", len(labeled))
	}
	if got := export(t0.Add(500*time.Second), false); len(got) != 7 || got[0].Decision.ID != "d0500" {
		t.Errorf("since d0500: %d decisions", len(got))
	}

	stop := errors.New("stop")
	calls := 0
	err := db.Export(ctx, time.Time{}, false, func(Entry) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Errorf("Export stopped with %v after %d calls, want stop after 1", err, calls)
	}
}

func TestEntryVerdict(t *testing.T) {
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	two := newDecision("d", t0, []string{"a"}, []string{"b"})
	none := newDecision("d", t0, nil, nil)
	tests := []struct {
		name   string
		d      decision.Decision
		labels []Label
		want   Verdict
		ok     bool
	}{
		{"unlabeled", two, nil, "", false},
		{"whole true", two, []Label{{Verdict: TruePositive, Time: at(1)}}, TruePositive, true},
		{"whole false", two, []Label{{Verdict: FalsePositive, Time: at(1)}}, FalsePositive, true},
		{"any true", two, []Label{{RuleID: "a", Verdict: FalsePositive, Time: at(1)}, {RuleID: "b", Verdict: TruePositive, Time: at(1)}}, TruePositive, true},
		{"all false", two, []Label{{RuleID: "a", Verdict: FalsePositive, Time: at(1)}, {RuleID: "b", Verdict: FalsePositive, Time: at(2)}}, FalsePositive, true},
		{"one rule only", two, []Label{{RuleID: "a", Verdict: FalsePositive, Time: at(1)}}, FalsePositive, true},
		{"reversal wins", two, []Label{{RuleID: "a", Verdict: TruePositive, Time: at(1)}, {Verdict: FalsePositive, Time: at(2)}}, FalsePositive, true},
		{"older whole loses", two, []Label{{Verdict: FalsePositive, Time: at(1)}, {RuleID: "a", Verdict: TruePositive, Time: at(2)}}, TruePositive, true},
		{"tie goes to the later", two, []Label{{Verdict: TruePositive, Time: at(1)}, {RuleID: "a", Verdict: FalsePositive, Time: at(1)}, {RuleID: "b", Verdict: FalsePositive, Time: at(1)}}, FalsePositive, true},
		{"relabeled rule", two, []Label{{RuleID: "a", Verdict: TruePositive, Time: at(1)}, {RuleID: "a", Verdict: FalsePositive, Time: at(3)}}, FalsePositive, true},
		{"no rule matched", none, []Label{{Verdict: TruePositive, Time: at(1)}}, TruePositive, true},
		{"no rule matched, relabeled", none, []Label{{Verdict: TruePositive, Time: at(2)}, {Verdict: FalsePositive, Time: at(1)}}, TruePositive, true},
	}
	for _, tt := range tests {
		v, ok := Entry{Decision: tt.d, Labels: tt.labels}.Verdict()
		if v != tt.want || ok != tt.ok {
			t.Errorf("%s: got %q, %v; want %q, %v", tt.name, v, ok, tt.want, tt.ok)
		}
	}
}

// TestListDecisionsPlan checks, on SQLite, that each filter reads its index
// in order instead of scanning and sorting the decisions.
func TestListDecisionsPlan(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	for _, tt := range []struct{ where, index string }{
		{"account_id = ?", "decisions_account"},
		{"api_key_id = ?", "decisions_api_key"},
		{"event_json->>'ip' = ?", "decisions_ip"},
		{"action = ?", "decisions_action"},
	} {
		q := "EXPLAIN QUERY PLAN SELECT decided_at_us, id, decision_json, event_json FROM decisions WHERE " + tt.where +
			" AND (decided_at_us, id) < (?, ?) ORDER BY decided_at_us DESC, id DESC LIMIT ?"
		rows, err := db.SQL().QueryContext(ctx, q, "x", 1, "d", 10)
		if err != nil {
			t.Fatalf("%s: %v", tt.where, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		got := strings.Join(plan, "; ")
		if !strings.Contains(got, tt.index) || strings.Contains(got, "TEMP B-TREE") {
			t.Errorf("%s: plan %q, want %s without a sort", tt.where, got, tt.index)
		}
	}
}

// TestRuleStatsPlan checks, on SQLite, that RuleStats counts from the
// covering matches_stats index and finds duplicates through the
// decisions_duplicate partial index, reading no decision's JSON.
func TestRuleStatsPlan(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	rows, err := db.SQL().QueryContext(ctx, "EXPLAIN QUERY PLAN "+ruleStatsQuery, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	got := strings.Join(plan, "; ")
	if !strings.Contains(got, "COVERING INDEX matches_stats") || !strings.Contains(got, "INDEX decisions_duplicate") {
		t.Errorf("plan %q, want matches_stats, covering, and decisions_duplicate", got)
	}
}

func TestReplayEvent(t *testing.T) {
	ev := sendEvent("d1")
	got, full := NewStoredEvent(ev, EventFull).ReplayEvent()
	if !full || got.Subject != ev.Subject || len(got.To) != 3 || len(got.Links) != 1 {
		t.Errorf("full mode: %+v, %v; want the whole event", got, full)
	}

	got, full = NewStoredEvent(ev, EventMinimal).ReplayEvent()
	if full {
		t.Error("minimal mode reported a whole event")
	}
	if got.ID != ev.ID || got.Type != event.Send || !got.Time.Equal(ev.Time) || got.AccountID != ev.AccountID ||
		got.APIKeyID != ev.APIKeyID || got.IP != ev.IP || got.From != "@sender.example" ||
		got.To != nil || got.Subject != "" || got.Links != nil {
		t.Errorf("minimal mode: %+v", got)
	}
	if event.DomainOf(got.From) != "sender.example" {
		t.Errorf("the rebuilt sender's domain is %q", event.DomainOf(got.From))
	}
	if err := got.Validate(); err != nil {
		t.Errorf("rebuilt event is invalid: %v", err)
	}

	fb := event.Event{Type: event.Feedback, Time: t0, AccountID: "a",
		Feedback: &event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent", Recipient: "x@y.example"}}
	got, _ = NewStoredEvent(fb, EventMinimal).ReplayEvent()
	if got.Feedback == nil || got.Feedback.Kind != event.Bounce || got.Feedback.BounceType != "permanent" {
		t.Errorf("feedback: %+v", got.Feedback)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("rebuilt feedback event is invalid: %v", err)
	}
}
