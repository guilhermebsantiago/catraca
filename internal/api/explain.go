package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// Explainer explains how an event would be decided without deciding it.
// *engine.Engine is one. A Decider that is not an Explainer answers
// POST /v1/rules/explain 404 not_configured.
type Explainer interface {
	Explain(ctx context.Context, ev event.Event, observe bool) (engine.Explanation, error)
}

var _ Explainer = (*engine.Engine)(nil)

// explain answers POST /v1/rules/explain?observe=: the event's signals and
// every rule's result. It takes no admission slot: without observe it costs
// no store call, and with it one, as a decision does.
func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	ex, ok := s.decider.(Explainer)
	if !ok {
		writeError(w, http.StatusNotFound, "not_configured", "this server cannot explain decisions")
		return
	}
	var observe bool
	if v := r.URL.Query().Get("observe"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_parameter", "observe: want true or false")
			return
		}
		observe = b
	}
	var ev event.Event
	if !s.readJSON(w, r, &ev) {
		return
	}
	x, err := ex.Explain(r.Context(), ev, observe)
	switch {
	case errors.Is(err, engine.ErrInvalidEvent):
		writeError(w, http.StatusBadRequest, "invalid_event", strings.TrimPrefix(err.Error(), engine.ErrInvalidEvent.Error()+": "))
		return
	case errors.Is(err, engine.ErrNoRuleset):
		writeError(w, http.StatusServiceUnavailable, "no_ruleset", "no ruleset is loaded; fix the ruleset file and reload it")
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "explain failed", "event_type", ev.Type, "error", err)
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the event could not be explained; retry it")
		return
	}
	writeJSON(w, http.StatusOK, x)
}
