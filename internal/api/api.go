// Package api is Catraca's HTTP server: the /v1 routes platforms call to
// decide events, read and label decisions and manage the ruleset, the
// feedback and secret scanning endpoints providers call, and health and
// Prometheus metrics. See docs/api.md.
//
// Every /v1 route needs a bearer token, except the feedback and secret
// scanning routes, which authenticate each request by its signature. Every
// response carries an X-Request-Id, every request is logged and measured,
// and errors are JSON: {"error": {"code": "...", "message": "..."}}.
package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// DefaultMaxBodyBytes limits /v1 request bodies when Options.MaxBodyBytes is
// zero.
const DefaultMaxBodyBytes = 1 << 20

// Decider decides events. *engine.Engine is one.
type Decider interface {
	Decide(ctx context.Context, ev event.Event) (decision.Decision, error)
	// DecideWithoutStore decides as Decide does when the store misses the
	// deadline, without waiting for it. It answers the decisions admission
	// control sheds; see Admission.
	DecideWithoutStore(ctx context.Context, ev event.Event) (decision.Decision, error)
}

// RuleSource provides the ruleset decisions are made with. *rules.Holder is
// one.
type RuleSource interface {
	Current() *rules.Ruleset
}

// ErrAuditUnavailable is returned, wrapped, by an AuditLog that cannot be
// used yet, such as an audit database still being opened. The routes that
// need the log answer 503 audit_unavailable.
var ErrAuditUnavailable = errors.New("api: the audit log is not available")

// AuditLog is the part of the decision log the API reads and labels.
// *audit.DB is one.
type AuditLog interface {
	Get(ctx context.Context, decisionID string) (audit.Entry, error)
	Label(ctx context.Context, decisionID string, l audit.Label) error
	RuleStats(ctx context.Context, since time.Time) ([]precision.RuleStats, error)
	ReviewQueue(ctx context.Context, ruleID string, mode decision.Mode, limit int) ([]audit.ReviewItem, error)
	Flush(ctx context.Context) error
}

// Token is an API token the /v1 routes accept.
type Token struct {
	// Name identifies the client in access logs.
	Name string
	// Value is the bearer token.
	Value string
}

// Check is one readiness check. It answers from the server's own state,
// fast, without calling another service: readiness decides whether a load
// balancer sends the server requests, and a check on a service every
// instance shares, such as Redis, would take them all out at once when that
// service fails, turning degraded decisions into no decisions. Report
// shared services with Options.Dependencies instead. Its error message is
// shown on /readyz, which needs no token, so it should say what is wrong
// without details such as hostnames.
type Check struct {
	Name  string
	Check func(context.Context) error
}

// DependencyStatus is the last check of a service the server uses but does
// not need in order to be ready, such as the store or the audit database, as
// GET /readyz?verbose shows it.
type DependencyStatus struct {
	// Status is "ok" or what is wrong, without details such as hostnames.
	Status string `json:"status"`
	// Since is when Status took its current value.
	Since time.Time `json:"since,omitzero"`
	// CheckedAt is when the last check ended, and DurationMS how long it
	// took.
	CheckedAt  time.Time `json:"checked_at,omitzero"`
	DurationMS float64   `json:"duration_ms"`
}

// Options configure a Server. Decider, Rules, Audit and at least one Token
// are required.
type Options struct {
	Decider Decider
	Rules   RuleSource
	// Reload reloads the ruleset from disk for POST /v1/rules/reload. On
	// error the current ruleset must stay in place. Nil disables the route.
	Reload func() (*rules.Ruleset, error)
	Audit  AuditLog
	// Gate is the precision gate GET /v1/stats/rules evaluates rules
	// against. Zero fields take the defaults.
	Gate   precision.Gate
	Tokens []Token

	// Provider endpoints. A nil handler answers 404 not_configured.
	SESFeedback          http.Handler
	UseSendFeedback      http.Handler
	GenericFeedback      http.Handler
	GitHubSecretScanning http.Handler

	// Checks run on GET /readyz: the server is ready when all of them pass.
	Checks []Check
	// Dependencies returns the latest health of the services the server
	// uses, by name, for GET /readyz?verbose. They never make it not ready.
	// Nil leaves them out.
	Dependencies func() map[string]DependencyStatus
	// Gatherer is served on GET /metrics. Nil answers 404.
	Gatherer prometheus.Gatherer
	// SeparateAdmin serves GET /healthz, /readyz and /metrics from Admin
	// only, for a listener of their own; the Server's own handler then
	// answers 404 for them.
	SeparateAdmin bool
	// Registerer receives the HTTP request duration histogram. Nil keeps
	// it unregistered.
	Registerer prometheus.Registerer
	// Logger receives access logs and errors. Nil discards them.
	Logger *slog.Logger
	// MaxBodyBytes limits /v1 JSON bodies. Default DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// Admission bounds the decisions and feedback requests in flight.
	Admission Admission
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// TracerProvider, when set, traces each request, continuing the trace
	// of a W3C traceparent header, adds the trace to its access log line,
	// and serves exemplars on GET /metrics. Nil turns tracing off.
	TracerProvider trace.TracerProvider
}

// Server is the HTTP handler for every route. It is safe for concurrent
// use.
type Server struct {
	mux *http.ServeMux
	// admin serves health and metrics, which mux serves too unless
	// Options.SeparateAdmin is set.
	admin        *http.ServeMux
	decider      Decider
	rules        RuleSource
	reloadFn     func() (*rules.Ruleset, error)
	audit        AuditLog
	gate         precision.Gate
	tokens       []tokenHash
	checks       []Check
	dependencies func() map[string]DependencyStatus
	log          *slog.Logger
	maxBody      int64
	now          func() time.Time
	duration     *prometheus.HistogramVec
	// tracer is nil with tracing off.
	tracer trace.Tracer

	// decisions and feedback hold the admission slots; see Admission.
	decisions, feedback *limiter
	admission           admissionMetrics
	deadline            time.Duration
}

type tokenHash struct {
	name string
	sum  [sha256.Size]byte
}

// New returns a Server with every route registered.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Decider == nil:
		return nil, errors.New("api: Options.Decider is required")
	case opts.Rules == nil:
		return nil, errors.New("api: Options.Rules is required")
	case opts.Audit == nil:
		return nil, errors.New("api: Options.Audit is required")
	case len(opts.Tokens) == 0:
		return nil, errors.New("api: at least one API token is required")
	}
	s := &Server{
		mux:          http.NewServeMux(),
		admin:        http.NewServeMux(),
		decider:      opts.Decider,
		rules:        opts.Rules,
		reloadFn:     opts.Reload,
		audit:        opts.Audit,
		gate:         opts.Gate,
		checks:       opts.Checks,
		dependencies: opts.Dependencies,
		log:          opts.Logger,
		maxBody:      opts.MaxBodyBytes,
		now:          opts.Now,
	}
	for _, t := range opts.Tokens {
		if t.Value == "" {
			return nil, fmt.Errorf("api: token %q is empty", t.Name)
		}
		s.tokens = append(s.tokens, tokenHash{name: t.Name, sum: sha256.Sum256([]byte(t.Value))})
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.maxBody <= 0 {
		s.maxBody = DefaultMaxBodyBytes
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "catraca_http_request_duration_seconds",
		Help:    "Time to serve an HTTP request, by route pattern and status code.",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"route", "status"})
	if opts.Registerer != nil {
		if err := opts.Registerer.Register(s.duration); err != nil {
			return nil, fmt.Errorf("api: register metrics: %w", err)
		}
	}
	if err := s.newAdmission(opts.Admission, opts.Registerer); err != nil {
		return nil, fmt.Errorf("api: admission: %w", err)
	}

	s.handle(s.mux, "POST /v1/decide", s.authed(s.decide(http.StatusOK)))
	s.handle(s.mux, "POST /v1/events", s.authed(s.decide(http.StatusAccepted)))
	s.handle(s.mux, "GET /v1/decisions/{id}", s.authed(s.getDecision))
	s.handle(s.mux, "POST /v1/decisions/{id}/labels", s.authed(s.label))
	s.handle(s.mux, "GET /v1/rules", s.authed(s.getRules))
	s.handle(s.mux, "POST /v1/rules/reload", s.authed(s.reload))
	s.handle(s.mux, "GET /v1/rules/{id}/review", s.authed(s.review))
	s.handle(s.mux, "GET /v1/stats/rules", s.authed(s.ruleStats))

	s.handle(s.mux, routeFeedback, provider("generic feedback", "feedback.generic", s.admitFeedback(routeFeedback, opts.GenericFeedback)))
	s.handle(s.mux, routeFeedbackSES, provider("SES feedback", "feedback.ses", s.admitFeedback(routeFeedbackSES, opts.SESFeedback)))
	s.handle(s.mux, routeFeedbackUseSend, provider("useSend feedback", "feedback.usesend", s.admitFeedback(routeFeedbackUseSend, opts.UseSendFeedback)))
	s.handle(s.mux, "POST /v1/secret-scanning/github", provider("GitHub secret scanning", "secret_scanning.github", opts.GitHubSecretScanning))

	if opts.TracerProvider != nil {
		s.tracer = opts.TracerProvider.Tracer(tracerName)
	}
	var metrics http.Handler = provider("metrics", "a Prometheus registry", nil)
	if opts.Gatherer != nil {
		// Exemplars exist only with tracing on, and only the OpenMetrics
		// format carries them; without tracing the format stays as it was.
		metrics = promhttp.HandlerFor(opts.Gatherer, promhttp.HandlerOpts{EnableOpenMetrics: s.tracer != nil})
	}
	for _, route := range []struct {
		pattern string
		h       http.Handler
	}{
		{"GET /healthz", http.HandlerFunc(s.healthz)},
		{"GET /readyz", http.HandlerFunc(s.readyz)},
		{"GET /metrics", metrics},
	} {
		s.handle(s.admin, route.pattern, route.h)
		if !opts.SeparateAdmin {
			s.handle(s.mux, route.pattern, route.h)
		}
	}
	s.mux.HandleFunc("/", s.fallback(s.mux))
	s.admin.HandleFunc("/", s.fallback(s.admin))
	return s, nil
}

// Admin returns the handler for GET /healthz, /readyz and /metrics alone,
// with the request ids, logs and metrics of the Server's own handler. With
// Options.SeparateAdmin, it is the only one that serves them.
func (s *Server) Admin() http.Handler { return adminHandler{s} }

type adminHandler struct{ s *Server }

func (h adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.s.serve(w, r, h.s.admin)
}

// handle registers h on mux for pattern and labels its requests with the
// pattern, so logs and metrics name routes, not paths full of ids.
func (s *Server) handle(mux *http.ServeMux, pattern string, h http.Handler) {
	mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ri := infoFrom(r.Context()); ri != nil {
			ri.route = pattern
		}
		h.ServeHTTP(w, r)
	}))
}

// provider returns h, or a handler that explains how to configure it.
func provider(name, section string, h http.Handler) http.Handler {
	if h != nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_configured", fmt.Sprintf("%s is not configured: add %s to catraca.yaml", name, section))
	})
}

// fallback answers requests no route of mux matches: 405 with Allow when
// the path exists for another method, 404 otherwise.
func (s *Server) fallback(mux *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var allowed []string
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			if m == r.Method {
				continue
			}
			probe := *r
			probe.Method = m
			if _, pattern := mux.Handler(&probe); pattern != "/" && pattern != "" {
				allowed = append(allowed, m)
			}
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
				fmt.Sprintf("%s is not allowed on %s; use %s", r.Method, r.URL.Path, strings.Join(allowed, " or ")))
			return
		}
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("no route for %s %s", r.Method, r.URL.Path))
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ReadyResponse is the body of GET /readyz.
type ReadyResponse struct {
	// Status is "ready" (200) or "not_ready" (503).
	Status string `json:"status"`
	// Checks has the result of each readiness check: "ok" or what is wrong.
	Checks map[string]string `json:"checks"`
	// Dependencies is the health of the services the server uses, with
	// ?verbose only. It does not affect Status.
	Dependencies map[string]DependencyStatus `json:"dependencies,omitempty"`
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	resp := ReadyResponse{Status: "ready", Checks: make(map[string]string, len(s.checks))}
	status := http.StatusOK
	for _, c := range s.checks {
		if err := c.Check(r.Context()); err != nil {
			status, resp.Status = http.StatusServiceUnavailable, "not_ready"
			resp.Checks[c.Name] = err.Error()
			continue
		}
		resp.Checks[c.Name] = "ok"
	}
	if r.URL.Query().Has("verbose") && s.dependencies != nil {
		resp.Dependencies = s.dependencies()
	}
	writeJSON(w, status, resp)
}
