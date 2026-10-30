package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

const (
	defaultDecisionLimit = 50
	maxDecisionLimit     = 1000
	// exportPage is how many decisions Export reads per query, so a long
	// export holds no query open while it writes.
	exportPage = 500
)

// ErrInvalidCursor is returned when a cursor was not made by ListDecisions.
var ErrInvalidCursor = errors.New("audit: invalid cursor")

// DecisionFilter selects the decisions ListDecisions returns. Empty fields
// match any decision.
type DecisionFilter struct {
	AccountID string
	APIKeyID  string
	// IP is the client IP the event carried, compared as stored.
	IP     string
	Action decision.Action
	// Since and Until bound when the decision was made: at or after Since,
	// before Until. Zero leaves that side open.
	Since, Until time.Time
	// Cursor continues a listing where the page that returned it ended.
	Cursor string
}

// DecisionItem is a decision in a listing, with its stored event.
type DecisionItem struct {
	Decision decision.Decision `json:"decision"`
	Event    StoredEvent       `json:"event"`
}

// DecisionPage is one page of a listing. Next is empty on the last page.
type DecisionPage struct {
	Decisions []DecisionItem `json:"decisions"`
	Next      string         `json:"next_cursor,omitempty"`
}

// ListDecisions returns up to limit decisions that match f, newest first,
// and a cursor for the next page. limit defaults to 50 and is capped at
// 1000. Decisions still queued are not listed; call Flush first if that
// matters. It returns an error wrapping ErrInvalidCursor when f.Cursor is
// malformed.
func (db *DB) ListDecisions(ctx context.Context, f DecisionFilter, limit int) (DecisionPage, error) {
	if limit <= 0 {
		limit = defaultDecisionLimit
	}
	limit = min(limit, maxDecisionLimit)
	if f.Action != "" {
		if _, err := decision.ParseAction(string(f.Action)); err != nil {
			return DecisionPage{}, fmt.Errorf("audit: list decisions: %w", err)
		}
	}

	q := "SELECT decided_at_us, id, decision_json, event_json FROM decisions WHERE 1 = 1"
	var args []any
	if f.AccountID != "" {
		q += " AND account_id = ?"
		args = append(args, f.AccountID)
	}
	if f.APIKeyID != "" {
		q += " AND api_key_id = ?"
		args = append(args, f.APIKeyID)
	}
	if f.IP != "" {
		// The same expression as the decisions_ip index, so it is used.
		q += " AND event_json->>'ip' = ?"
		args = append(args, f.IP)
	}
	if f.Action != "" {
		q += " AND action = ?"
		args = append(args, string(f.Action))
	}
	if !f.Since.IsZero() {
		q += " AND decided_at_us >= ?"
		args = append(args, toMicros(f.Since))
	}
	if !f.Until.IsZero() {
		q += " AND decided_at_us < ?"
		args = append(args, toMicros(f.Until))
	}
	if f.Cursor != "" {
		at, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return DecisionPage{}, err
		}
		q += " AND (decided_at_us, id) < (?, ?)"
		args = append(args, at, id)
	}
	q += " ORDER BY decided_at_us DESC, id DESC LIMIT ?"
	args = append(args, limit+1)

	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), args...)
	if err != nil {
		return DecisionPage{}, fmt.Errorf("audit: list decisions: %w", err)
	}
	defer rows.Close()
	page := DecisionPage{Decisions: []DecisionItem{}}
	var lastAt int64
	var lastID string
	for rows.Next() {
		if len(page.Decisions) == limit {
			page.Next = encodeCursor(lastAt, lastID)
			break
		}
		var decisionJSON, eventJSON []byte
		if err := rows.Scan(&lastAt, &lastID, &decisionJSON, &eventJSON); err != nil {
			return DecisionPage{}, fmt.Errorf("audit: list decisions: %w", err)
		}
		var it DecisionItem
		if err := json.Unmarshal(decisionJSON, &it.Decision); err != nil {
			return DecisionPage{}, fmt.Errorf("audit: decode decision %q: %w", lastID, err)
		}
		if err := json.Unmarshal(eventJSON, &it.Event); err != nil {
			return DecisionPage{}, fmt.Errorf("audit: decode event of decision %q: %w", lastID, err)
		}
		page.Decisions = append(page.Decisions, it)
	}
	if err := rows.Err(); err != nil {
		return DecisionPage{}, fmt.Errorf("audit: list decisions: %w", err)
	}
	return page, nil
}

// A cursor is the time and id of the last decision on a page, so the next
// page starts after it whatever was recorded since.
func encodeCursor(at int64, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at, 10) + "." + id))
}

func decodeCursor(s string) (int64, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %q", ErrInvalidCursor, s)
	}
	at, id, ok := strings.Cut(string(raw), ".")
	n, err := strconv.ParseInt(at, 10, 64)
	if !ok || err != nil || id == "" {
		return 0, "", fmt.Errorf("%w: %q", ErrInvalidCursor, s)
	}
	return n, id, nil
}

// Export calls fn with every decision made at or after since, oldest
// first, with its stored event and labels; with labeledOnly, only the
// decisions that have a label. It reads the log in pages, so fn may be
// slow, and stops at the first error fn returns. Decisions still queued
// are not exported; call Flush first if that matters.
func (db *DB) Export(ctx context.Context, since time.Time, labeledOnly bool, fn func(Entry) error) error {
	var after []any
	for {
		q := "SELECT decided_at_us, id, decision_json, event_json FROM decisions d WHERE "
		args := after
		if after == nil {
			q += "decided_at_us >= ?"
			args = []any{toMicros(since)}
		} else {
			q += "(decided_at_us, id) > (?, ?)"
		}
		if labeledOnly {
			q += " AND EXISTS (SELECT 1 FROM labels l WHERE l.decision_id = d.id)"
		}
		q += " ORDER BY decided_at_us, id LIMIT ?"
		entries, ids, lastAt, err := db.exportPage(ctx, q, append(args, exportPage))
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		if err := db.attachLabels(ctx, entries, ids); err != nil {
			return err
		}
		for _, e := range entries {
			if err := fn(e); err != nil {
				return err
			}
		}
		if len(entries) < exportPage {
			return nil
		}
		after = []any{lastAt, ids[len(ids)-1]}
	}
}

func (db *DB) exportPage(ctx context.Context, q string, args []any) ([]Entry, []string, int64, error) {
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), args...)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("audit: export: %w", err)
	}
	defer rows.Close()
	var entries []Entry
	var ids []string
	var lastAt int64
	for rows.Next() {
		var rowID string
		var decisionJSON, eventJSON []byte
		if err := rows.Scan(&lastAt, &rowID, &decisionJSON, &eventJSON); err != nil {
			return nil, nil, 0, fmt.Errorf("audit: export: %w", err)
		}
		e := Entry{Labels: []Label{}}
		if err := json.Unmarshal(decisionJSON, &e.Decision); err != nil {
			return nil, nil, 0, fmt.Errorf("audit: decode decision %q: %w", rowID, err)
		}
		if err := json.Unmarshal(eventJSON, &e.Event); err != nil {
			return nil, nil, 0, fmt.Errorf("audit: decode event of decision %q: %w", rowID, err)
		}
		entries = append(entries, e)
		ids = append(ids, rowID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, 0, fmt.Errorf("audit: export: %w", err)
	}
	return entries, ids, lastAt, nil
}

// attachLabels reads the labels of a page of decisions, ids[i] being the id
// of entries[i], in one query.
func (db *DB) attachLabels(ctx context.Context, entries []Entry, ids []string) error {
	index := make(map[string]int, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		index[id] = i
		args[i] = id
	}
	q := "SELECT decision_id, rule_id, verdict, labeled_by, reason, client, labeled_at_us FROM labels WHERE decision_id IN (?" +
		strings.Repeat(", ?", len(ids)-1) + ") ORDER BY decision_id, id"
	rows, err := db.db.QueryContext(ctx, db.dialect.rebind(q), args...)
	if err != nil {
		return fmt.Errorf("audit: export labels: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var l Label
		var at int64
		if err := rows.Scan(&id, &l.RuleID, &l.Verdict, &l.By, &l.Reason, &l.Client, &at); err != nil {
			return fmt.Errorf("audit: export labels: %w", err)
		}
		l.Time = fromMicros(at)
		if i, ok := index[id]; ok {
			entries[i].Labels = append(entries[i].Labels, l)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: export labels: %w", err)
	}
	return nil
}

// Verdict returns what the labels of e say about its event, the way the
// rule counts read them: for each rule that matched, the latest label that
// applies to it, whether it names the rule or covers the whole decision;
// for a decision no rule matched, its latest whole-decision label. The
// event was abuse when any of those is a true positive, and was not when
// all are false positives. ok is false when no label applies.
func (e Entry) Verdict() (v Verdict, ok bool) {
	// Labels are oldest first, so on equal times the later one wins, as
	// it does in the counts.
	beats := func(a, b int) bool {
		ta, tb := e.Labels[a].Time, e.Labels[b].Time
		return ta.After(tb) || (ta.Equal(tb) && a > b)
	}
	latest := func(rule string) int {
		best := -1
		for i, l := range e.Labels {
			if l.RuleID == rule && (best < 0 || beats(i, best)) {
				best = i
			}
		}
		return best
	}
	whole := latest("")
	var verdicts []Verdict
	rules := 0
	for _, ms := range [][]decision.Match{e.Decision.Matches, e.Decision.Shadow} {
		for _, m := range ms {
			rules++
			switch r := latest(m.RuleID); {
			case r >= 0 && (whole < 0 || beats(r, whole)):
				verdicts = append(verdicts, e.Labels[r].Verdict)
			case whole >= 0:
				verdicts = append(verdicts, e.Labels[whole].Verdict)
			}
		}
	}
	if rules == 0 && whole >= 0 {
		verdicts = append(verdicts, e.Labels[whole].Verdict)
	}
	if len(verdicts) == 0 {
		return "", false
	}
	for _, v := range verdicts {
		if v == TruePositive {
			return TruePositive, true
		}
	}
	return FalsePositive, true
}

// ReplayEvent returns the event to replay for s: the whole event when the
// log kept it (EventFull), otherwise the event rebuilt from what the log
// kept. A rebuilt event has no recipients, subject, links or attributes,
// its sender is only its domain ("@example.com"), and a feedback event
// has no recipient or message id, so rules that read those cannot match
// it as they did. full reports whether the event is whole.
func (s StoredEvent) ReplayEvent() (ev event.Event, full bool) {
	if s.Full != nil {
		return *s.Full, true
	}
	ev = event.Event{
		ID:        s.ID,
		Type:      s.Type,
		Time:      s.Time,
		AccountID: s.AccountID,
		APIKeyID:  s.APIKeyID,
		IP:        s.IP,
	}
	if s.FromDomain != "" {
		ev.From = "@" + s.FromDomain
	}
	if s.Type == event.Feedback || s.FeedbackKind != "" {
		ev.Feedback = &event.FeedbackInfo{Kind: s.FeedbackKind, BounceType: s.BounceType}
	}
	if s.AccountAction != "" {
		ev.Account = &event.AccountInfo{Action: s.AccountAction}
	}
	return ev, false
}
