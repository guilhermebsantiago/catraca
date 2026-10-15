package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// DecisionResponse is the body of POST /v1/decide and POST /v1/events.
type DecisionResponse struct {
	Decision decision.Decision `json:"decision"`
}

// decide answers POST /v1/decide (status 200) and POST /v1/events (202).
// Any valid event gets its decision; the caller acts on its action.
func (s *Server) decide(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ev event.Event
		if !s.readJSON(w, r, &ev) {
			return
		}
		d, err := s.decider.Decide(r.Context(), ev)
		switch {
		case errors.Is(err, engine.ErrInvalidEvent):
			writeError(w, http.StatusBadRequest, "invalid_event", strings.TrimPrefix(err.Error(), engine.ErrInvalidEvent.Error()+": "))
			return
		case errors.Is(err, engine.ErrNoRuleset):
			writeError(w, http.StatusServiceUnavailable, "no_ruleset", "no ruleset is loaded; fix the ruleset file and reload it")
			return
		case err != nil:
			s.log.ErrorContext(r.Context(), "decide failed", "event_type", ev.Type, "error", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "the event could not be decided; retry it")
			return
		}
		annotate(r, slog.String("decision_id", d.ID), slog.String("action", string(d.Action)))
		if d.Action == decision.Throttle {
			w.Header().Set("Retry-After", retryAfterSeconds(d.RetryAfter))
		}
		writeJSON(w, status, DecisionResponse{Decision: d})
	}
}

// retryAfterSeconds rounds up to whole seconds, at least 1, the unit of the
// Retry-After header.
func retryAfterSeconds(d time.Duration) string {
	secs := int64((d + time.Second - 1) / time.Second)
	return strconv.FormatInt(max(secs, 1), 10)
}

func (s *Server) getDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entry, err := s.audit.Get(r.Context(), id)
	if err != nil {
		s.auditError(w, r, id, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// label answers POST /v1/decisions/{id}/labels with the decision and all its
// labels.
func (s *Server) label(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var l audit.Label
	if !s.readJSON(w, r, &l) {
		return
	}
	if err := s.audit.Label(r.Context(), id, l); err != nil {
		s.auditError(w, r, id, err)
		return
	}
	annotate(r, slog.String("decision_id", id), slog.String("verdict", string(l.Verdict)))
	entry, err := s.audit.Get(r.Context(), id)
	if err != nil {
		s.auditError(w, r, id, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) auditError(w http.ResponseWriter, r *http.Request, id string, err error) {
	switch {
	case errors.Is(err, audit.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("decision %q is not in the audit log", id))
	case errors.Is(err, audit.ErrInvalidLabel):
		writeError(w, http.StatusBadRequest, "invalid_label", strings.TrimPrefix(err.Error(), audit.ErrInvalidLabel.Error()+": "))
	case errors.Is(err, audit.ErrRuleNotMatched):
		writeError(w, http.StatusUnprocessableEntity, "rule_not_matched", "the label names a rule that did not match the decision")
	default:
		s.log.ErrorContext(r.Context(), "audit log request failed", "decision_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "the audit log could not be read")
	}
}

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	rs := s.rules.Current()
	if rs == nil {
		writeError(w, http.StatusServiceUnavailable, "no_ruleset", "no ruleset is loaded")
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

// ReloadResponse is the body of a successful POST /v1/rules/reload.
type ReloadResponse struct {
	Version string `json:"version"`
	// PreviousVersion is the version served before the reload, or "" when
	// none was loaded.
	PreviousVersion string `json:"previous_version"`
	// Changed is false when the file had no change that matters.
	Changed  bool     `json:"changed"`
	Rules    int      `json:"rules"`
	Warnings []string `json:"warnings"`
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if s.reloadFn == nil {
		writeError(w, http.StatusNotFound, "not_configured", "this server cannot reload its ruleset")
		return
	}
	var prev string
	if cur := s.rules.Current(); cur != nil {
		prev = cur.Version()
	}
	rs, err := s.reloadFn()
	if err != nil {
		var details []string
		var list rules.ErrorList
		if errors.As(err, &list) {
			for _, e := range list {
				details = append(details, e.Error())
			}
		} else {
			details = []string{err.Error()}
		}
		msg := "the ruleset did not load; no ruleset is loaded"
		if prev != "" {
			msg = "the ruleset did not load; still serving version " + prev
		}
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{apiError{Code: "invalid_ruleset", Message: msg, Details: details}})
		return
	}
	warnings := []string{}
	for _, wn := range rs.Lint() {
		warnings = append(warnings, wn.String())
	}
	annotate(r, slog.String("ruleset_version", rs.Version()))
	writeJSON(w, http.StatusOK, ReloadResponse{
		Version:         rs.Version(),
		PreviousVersion: prev,
		Changed:         rs.Version() != prev,
		Rules:           len(rs.Rules()),
		Warnings:        warnings,
	})
}

// ReviewResponse is the body of GET /v1/rules/{id}/review.
type ReviewResponse struct {
	RuleID string             `json:"rule_id"`
	Mode   decision.Mode      `json:"mode,omitempty"`
	Items  []audit.ReviewItem `json:"items"`
}

// review answers GET /v1/rules/{id}/review?mode=&limit=: the rule's most
// recent unlabeled matches, newest first. The rule need not be in the
// current ruleset, so matches of a retired rule can still be reviewed.
func (s *Server) review(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q := r.URL.Query()
	mode := decision.Mode(q.Get("mode"))
	if mode != "" {
		if _, err := decision.ParseMode(string(mode)); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_parameter", "mode: "+err.Error())
			return
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
	items, err := s.audit.ReviewQueue(r.Context(), id, mode, limit)
	if err != nil {
		s.log.ErrorContext(r.Context(), "review queue failed", "rule_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "the audit log could not be read")
		return
	}
	writeJSON(w, http.StatusOK, ReviewResponse{RuleID: id, Mode: mode, Items: items})
}

// StatsResponse is the body of GET /v1/stats/rules: the precision of every
// rule in the current ruleset over the window, against the gate.
type StatsResponse struct {
	Since          time.Time `json:"since"`
	RulesetVersion string    `json:"ruleset_version"`
	precision.Report
}

// DefaultStatsWindow is the window of GET /v1/stats/rules without since.
const DefaultStatsWindow = 720 * time.Hour

func (s *Server) ruleStats(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	since := now.Add(-DefaultStatsWindow)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := ParseSince(v, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_parameter", "since: "+err.Error())
			return
		}
		since = t
	}
	rs := s.rules.Current()
	if rs == nil {
		writeError(w, http.StatusServiceUnavailable, "no_ruleset", "no ruleset is loaded")
		return
	}
	s.flush(r)
	stats, err := s.audit.RuleStats(r.Context(), since)
	if err != nil {
		s.log.ErrorContext(r.Context(), "rule stats failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "the audit log could not be read")
		return
	}
	writeJSON(w, http.StatusOK, StatsResponse{
		Since:          since.UTC(),
		RulesetVersion: rs.Version(),
		Report:         precision.NewReport(s.gate, RuleInfos(rs), stats),
	})
}

// flush writes queued decisions, so stats and the review queue include the
// ones just made. A failure only makes the answer slightly stale.
func (s *Server) flush(r *http.Request) {
	if err := s.audit.Flush(r.Context()); err != nil {
		s.log.WarnContext(r.Context(), "audit flush failed; answering without queued decisions", "error", err)
	}
}
