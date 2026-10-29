package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// AccountStates reads and sets the states operators give accounts, which
// rules read as account.state. *signal.AccountStates is one.
type AccountStates interface {
	Get(ctx context.Context, id string) (signal.AccountState, error)
	// Set fails with signal.ErrInvalidAccountState, wrapped, for a state
	// it does not accept.
	Set(ctx context.Context, id string, st signal.AccountState) error
	Reset(ctx context.Context, id string) error
}

// withAccountStates returns h, or a handler that answers 404
// not_configured when the server has no AccountStates.
func (s *Server) withAccountStates(h http.HandlerFunc) http.HandlerFunc {
	if s.accountStates != nil {
		return h
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_configured", "account states are not configured")
	}
}

// AccountStateRequest is the body of PUT /v1/accounts/{id}/state.
type AccountStateRequest struct {
	// State is active, review, suspended or trusted. Active resets the
	// account, as DELETE does.
	State string `json:"state"`
	// Until is when the state expires, in RFC 3339; omitted, it lasts
	// until it is changed or reset.
	Until time.Time `json:"until,omitzero"`
	// Reason says why, for whoever reads the state later.
	Reason string `json:"reason,omitempty"`
}

// AccountStateResponse is the body of every account state route: the
// account's state, set_at and set_by saying when and with which API token
// it was set.
type AccountStateResponse struct {
	AccountID string `json:"account_id"`
	signal.AccountState
}

func (s *Server) getAccountState(w http.ResponseWriter, r *http.Request) {
	id, ok := s.accountID(w, r)
	if !ok {
		return
	}
	st, err := s.accountStates.Get(r.Context(), id)
	if err != nil {
		s.accountStateFailed(w, r, "read", err)
		return
	}
	writeJSON(w, http.StatusOK, AccountStateResponse{AccountID: id, AccountState: st})
}

func (s *Server) putAccountState(w http.ResponseWriter, r *http.Request) {
	id, ok := s.accountID(w, r)
	if !ok {
		return
	}
	var req AccountStateRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if req.State == signal.StateActive {
		s.resetAccountState(w, r, id)
		return
	}
	st := signal.AccountState{State: req.State, Until: req.Until, Reason: req.Reason, SetAt: s.now().UTC()}
	if ri := infoFrom(r.Context()); ri != nil {
		st.SetBy = ri.client
	}
	if err := s.accountStates.Set(r.Context(), id, st); err != nil {
		if errors.Is(err, signal.ErrInvalidAccountState) {
			writeError(w, http.StatusBadRequest, "invalid_state", strings.TrimPrefix(err.Error(), signal.ErrInvalidAccountState.Error()+": "))
			return
		}
		s.accountStateFailed(w, r, "written", err)
		return
	}
	if !st.Until.IsZero() {
		st.Until = st.Until.UTC()
	}
	s.accountStateChanged(r, id, st)
	writeJSON(w, http.StatusOK, AccountStateResponse{AccountID: id, AccountState: st})
}

func (s *Server) deleteAccountState(w http.ResponseWriter, r *http.Request) {
	id, ok := s.accountID(w, r)
	if !ok {
		return
	}
	s.resetAccountState(w, r, id)
}

// resetAccountState makes the account active and answers with its state.
func (s *Server) resetAccountState(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.accountStates.Reset(r.Context(), id); err != nil {
		s.accountStateFailed(w, r, "reset", err)
		return
	}
	changed := signal.AccountState{State: signal.StateActive}
	if ri := infoFrom(r.Context()); ri != nil {
		changed.SetBy = ri.client
	}
	s.accountStateChanged(r, id, changed)
	writeJSON(w, http.StatusOK, AccountStateResponse{AccountID: id, AccountState: signal.AccountState{State: signal.StateActive}})
}

// accountID returns the account id of the request's path, or answers 400
// when it is longer than an event's account_id can be.
func (s *Server) accountID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if len(id) > event.MaxIDBytes {
		writeError(w, http.StatusBadRequest, "invalid_account_id", fmt.Sprintf("the account id is longer than %d bytes", event.MaxIDBytes))
		return "", false
	}
	return id, true
}

// accountStateChanged logs a change of state, which the audit log does not
// record: who changed which account, to what, until when and why.
func (s *Server) accountStateChanged(r *http.Request, id string, st signal.AccountState) {
	annotate(r, slog.String("state", st.State))
	attrs := []any{"account_id", id, "state", st.State, "set_by", st.SetBy}
	if !st.Until.IsZero() {
		attrs = append(attrs, "until", st.Until)
	}
	if st.Reason != "" {
		attrs = append(attrs, "reason", st.Reason)
	}
	if ri := infoFrom(r.Context()); ri != nil {
		attrs = append(attrs, "request_id", ri.id)
	}
	s.log.InfoContext(r.Context(), "account state changed", attrs...)
}

// accountStateFailed answers a request the store could not serve with 503,
// and logs why. done says what could not be done to the state: read,
// written or reset.
func (s *Server) accountStateFailed(w http.ResponseWriter, r *http.Request, done string, err error) {
	s.log.ErrorContext(r.Context(), "account state could not be "+done, "error", err)
	writeError(w, http.StatusServiceUnavailable, "store_unavailable", "the account state could not be "+done+": the store did not answer; retry later")
}
