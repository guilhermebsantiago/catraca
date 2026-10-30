package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// listDecisions answers GET /v1/decisions?account_id=&api_key_id=&ip=
// &action=&since=&until=&limit=&cursor=: the decisions that match, newest
// first, a page at a time. next_cursor, when set, continues the list.
func (s *Server) listDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.DecisionFilter{
		AccountID: q.Get("account_id"),
		APIKeyID:  q.Get("api_key_id"),
		IP:        q.Get("ip"),
		Action:    decision.Action(q.Get("action")),
		Cursor:    q.Get("cursor"),
	}
	if f.Action != "" {
		if _, err := decision.ParseAction(string(f.Action)); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_parameter", "action: "+err.Error())
			return
		}
	}
	now := s.now()
	for _, p := range []struct {
		name string
		to   *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(p.name); v != "" {
			t, err := ParseSince(v, now)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_parameter", p.name+": "+err.Error())
				return
			}
			*p.to = t
		}
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_parameter", "limit: want an integer from 1 to 1000")
			return
		}
		limit = n
	}
	s.flush(r)
	page, err := s.audit.ListDecisions(r.Context(), f, limit)
	if errors.Is(err, audit.ErrInvalidCursor) {
		writeError(w, http.StatusBadRequest, "invalid_parameter", "cursor: not a cursor this route returned")
		return
	}
	if err != nil {
		s.auditFailed(w, r, "listing decisions failed", err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
