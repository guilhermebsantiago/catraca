package api

import (
	"fmt"
	"log/slog"
	"net/http"
)

// Scope is what a token may do: each /v1 route that takes a token needs one
// scope, and a token is accepted on the routes of the scopes it has. See
// "Authentication" in docs/api.md for the route of each.
//
// To add a scope, add it here and to Scopes, give it to the routes that
// need it in New, and list it in config.TokenScopes and the route table of
// docs/api.md. A token without scopes in the configuration has them all,
// the new one included.
type Scope string

const (
	// ScopeDecide is for the send path: POST /v1/decide and /v1/events.
	ScopeDecide Scope = "decide"
	// ScopeRead reads decisions, the review queue, rule stats and the
	// ruleset. The audit log holds account ids, IPs and recipient domains,
	// and addresses and links with event_detail: full.
	ScopeRead Scope = "read"
	// ScopeLabel labels decisions.
	ScopeLabel Scope = "label"
	// ScopeAdmin changes how Catraca decides: POST /v1/rules/reload.
	ScopeAdmin Scope = "admin"
)

// Scopes are every scope, in the order the docs list them.
var Scopes = []Scope{ScopeDecide, ScopeRead, ScopeLabel, ScopeAdmin}

// scopeSet is a set of scopes, one bit per entry of Scopes.
type scopeSet uint8

// allScopes is the set of a token configured without scopes.
var allScopes = scopeSet(1)<<len(Scopes) - 1

func (s scopeSet) has(sc Scope) bool { return s&scopeBit(sc) != 0 }

func scopeBit(sc Scope) scopeSet {
	for i, known := range Scopes {
		if known == sc {
			return 1 << i
		}
	}
	return 0
}

// newScopeSet returns the set of scopes, or every scope for nil: a token
// configured without scopes keeps the full access tokens had before scopes
// existed. An empty, non-nil list or an unknown scope is an error.
func newScopeSet(scopes []Scope) (scopeSet, error) {
	if scopes == nil {
		return allScopes, nil
	}
	if len(scopes) == 0 {
		return 0, fmt.Errorf("no scopes: list at least one of %v, or none for full access", Scopes)
	}
	var set scopeSet
	for _, sc := range scopes {
		bit := scopeBit(sc)
		if bit == 0 {
			return 0, fmt.Errorf("unknown scope %q: use one of %v", sc, Scopes)
		}
		set |= bit
	}
	return set, nil
}

// v1 registers h on pattern behind a bearer token with scope, and records
// the scope of the route for tests.
func (s *Server) v1(pattern string, scope Scope, h http.HandlerFunc) {
	if scopeBit(scope) == 0 {
		panic(fmt.Sprintf("api: route %s: unknown scope %q", pattern, scope))
	}
	s.routeScopes[pattern] = scope
	s.handle(s.mux, pattern, s.authed(scope, h))
}

// authed requires a valid bearer token that has scope. The access log line
// names the token and says whether it had the scope.
func (s *Server) authed(scope Scope, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, problem := s.authenticate(r.Header.Get("Authorization"))
		if problem != "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="catraca"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", problem)
			return
		}
		if ri := infoFrom(r.Context()); ri != nil {
			ri.client = tok.name
		}
		if tok.previous {
			// Until no request says this, the client has not moved to its
			// new token, and the old one cannot be removed.
			annotate(r, slog.Bool("previous_token", true))
		}
		if !tok.scopes.has(scope) {
			annotate(r, slog.String("scope", string(scope)), slog.String("scope_check", "denied"))
			// RFC 6750 section 3.1: the scope the request needed.
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="catraca", error="insufficient_scope", scope="%s"`, scope))
			writeError(w, http.StatusForbidden, "insufficient_scope",
				fmt.Sprintf("token %q does not have the %s scope this route needs; add it to the token's scopes in catraca.yaml, or use a token that has it", tok.name, scope))
			return
		}
		annotate(r, slog.String("scope", string(scope)), slog.String("scope_check", "allowed"))
		h(w, r)
	})
}
