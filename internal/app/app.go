// Package app builds a Catraca server from its configuration, runs it and
// shuts it down in order.
//
// New opens the store, the audit database, the hooks, the engine, the
// feedback and secret scanning handlers and the HTTP API. Serve runs the
// HTTP server until its context ends and then shuts everything down so that
// no accepted work is lost: it stops accepting requests, lets the
// leaked-key reports in flight finish, writes queued decisions, stops
// webhook delivery, and closes the audit database and the store, in that
// order.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	ossignal "os/signal"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/feedback"
	"github.com/guilhermebsantiago/catraca/internal/hooks"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/secretscan"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// HTTP server timeouts. WriteTimeout leaves room for the secret scanning
// endpoint, which may wait 20 seconds for tokens to resolve before
// answering GitHub.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 2 * time.Minute
)

// Options are the parts of an App that do not come from the configuration.
type Options struct {
	// Logger receives every log line. Nil builds one from the logging
	// section of the configuration, writing to stderr.
	Logger *slog.Logger
	// Version is the build version, exported as catraca_build_info.
	Version string
}

// App is a configured Catraca server.
type App struct {
	cfg     *config.Config
	log     *slog.Logger
	version string

	registry *prometheus.Registry
	holder   *rules.Holder
	loads    *prometheus.CounterVec
	reloadMu sync.Mutex

	store   store.Store
	catalog signal.Catalog
	audit   *auditLog
	hooks   *hooks.Dispatcher
	// stopHooks cancels hooks.Run; hooksDone is closed when it returns.
	stopHooks context.CancelFunc
	hooksDone chan struct{}
	engine    *engine.Engine
	scan      *secretscan.Handler
	api       *api.Server
	deps      *dependencyMonitor
	// draining is set when Serve's context ends, so /readyz reports not
	// ready while the server still serves.
	draining atomic.Bool
	// drainEnd returns the channel that ends a drain of the given delay:
	// time.After, or a channel a test controls.
	drainEnd func(time.Duration) <-chan time.Time

	closeOnce sync.Once
	closeErr  error
}

// New builds an App from cfg. It loads the ruleset, opens the store and the
// audit database, starts webhook delivery and starts checking the store and
// the audit database in the background. A ruleset that fails to load does
// not stop it: the error is logged, /readyz reports not ready and decisions
// answer 503 until a reload succeeds, so an edit that breaks the file never
// takes down a running deployment. A SQLite audit database that cannot be
// opened does. A Postgres one opens in the background, retried while it is
// unreachable, and the server decides without the audit log meanwhile; an
// error that waiting cannot fix stops Serve (see auditLog).
func New(ctx context.Context, cfg *config.Config, opts Options) (_ *App, err error) {
	log := opts.Logger
	if log == nil {
		log = NewLogger(cfg.Logging, os.Stderr)
	}
	a := &App{
		cfg:      cfg,
		log:      log,
		version:  opts.Version,
		registry: prometheus.NewRegistry(),
		holder:   &rules.Holder{},
		drainEnd: time.After,
	}
	defer func() {
		if err != nil {
			_ = a.Close(context.Background())
		}
	}()
	a.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	a.loads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "catraca_ruleset_loads_total",
		Help: "Ruleset loads at start and on reload, by result (ok or error).",
	}, []string{"result"})
	a.registry.MustRegister(a.loads)
	if _, err := a.Reload(); err != nil {
		log.Error("serving without a ruleset until it loads: fix the file, then POST /v1/rules/reload or send SIGHUP",
			"path", cfg.Rules.Path)
	}

	if a.store, err = openStore(cfg.Store); err != nil {
		return nil, err
	}
	dedupe := cfg.Engine.DedupeTTL
	if dedupe == 0 {
		dedupe = -1 // engine.dedupe_ttl: 0s turns deduplication off.
	}
	a.catalog = signal.NewCatalog(a.store, signal.Options{DedupeTTL: dedupe})

	alog := log.With("component", "audit")
	auditOpts := cfg.Audit.Options()
	auditOpts.Logger = alog
	a.audit, err = openAuditLog(ctx, cfg.Audit.DSN.Value(), auditOpts, alog)
	if err != nil {
		return nil, fmt.Errorf("open the audit database: %w", err)
	}

	if len(cfg.Hooks) > 0 {
		if err := a.startHooks(); err != nil {
			return nil, err
		}
	}

	// Every ingress, the /v1 routes, the feedback endpoints and secret
	// scanning, decides through this engine, so its time bounds and the
	// event limits of Validate cover them all.
	eopts := engine.Options{
		Catalog:         a.catalog,
		Rules:           a.holder,
		Recorder:        a.audit,
		Deadline:        cfg.Engine.Deadline,
		DispatchTimeout: cfg.Engine.DispatchTimeout,
		MaxFutureSkew:   cfg.Engine.MaxFutureSkew,
		MaxEventAge:     cfg.Engine.MaxEventAge,
		Registerer:      a.registry,
		Logger:          log.With("component", "engine"),
	}
	if a.hooks != nil {
		eopts.Dispatcher = a.hooks
	}
	if a.engine, err = engine.New(eopts); err != nil {
		return nil, err
	}
	a.audit.handedOver = a.engine.Sync

	a.deps = newDependencyMonitor(a.dependencies(), a.registry, log)
	a.deps.start()

	aopts := api.Options{
		Decider:       a.engine,
		Rules:         a.holder,
		Reload:        a.Reload,
		Audit:         a.audit,
		Gate:          cfg.Gate.Precision(),
		Checks:        a.checks(),
		Dependencies:  a.deps.statuses,
		Gatherer:      a.registry,
		SeparateAdmin: cfg.Server.AdminAddr != "",
		Registerer:    a.registry,
		Logger:        log,
		MaxBodyBytes:  cfg.Server.MaxBodyBytes,
	}
	for _, t := range cfg.Auth.Tokens {
		aopts.Tokens = append(aopts.Tokens, api.Token{Name: t.Name, Value: t.Token.Value()})
	}
	if err := a.feedback(&aopts); err != nil {
		return nil, err
	}
	if err := a.secretScanning(&aopts); err != nil {
		return nil, err
	}
	a.registerStats()
	if a.api, err = api.New(aopts); err != nil {
		return nil, err
	}
	return a, nil
}

// NewLogger returns the logger the logging section describes.
func NewLogger(cfg config.Logging, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func openStore(c config.Store) (store.Store, error) {
	if c.Backend == config.StoreRedis {
		s, err := store.OpenRedis(c.Redis.URL.Value(), store.RedisOptions{Prefix: c.Redis.Prefix, Mode: c.Redis.Mode})
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	return store.NewMemory(), nil
}

func (a *App) startHooks() error {
	hs := make([]hooks.Hook, 0, len(a.cfg.Hooks))
	for _, h := range a.cfg.Hooks {
		hs = append(hs, h.Options())
	}
	d, err := hooks.New(a.audit, hooks.Config{Hooks: hs, Workers: a.cfg.Outbox.Workers, Logger: a.log.With("component", "hooks")})
	if err != nil {
		return err
	}
	a.hooks = d
	ctx, cancel := context.WithCancel(context.Background())
	a.stopHooks, a.hooksDone = cancel, make(chan struct{})
	go func() {
		defer close(a.hooksDone)
		_ = d.Run(ctx)
	}()
	return nil
}

func (a *App) feedback(opts *api.Options) error {
	log := a.log.With("component", "feedback")
	outcomes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "catraca_feedback_outcomes_total",
		Help: "What the feedback endpoints did with requests and events, by provider and outcome.",
	}, []string{"provider", "outcome"})
	a.registry.MustRegister(outcomes)
	count := func(provider string) func(feedback.Outcome) {
		for _, o := range []feedback.Outcome{feedback.OutcomeDecided, feedback.OutcomeDecideFailed, feedback.OutcomeUncounted, feedback.OutcomeInvalidSignature} {
			outcomes.WithLabelValues(provider, string(o))
		}
		return func(o feedback.Outcome) { outcomes.WithLabelValues(provider, string(o)).Inc() }
	}
	fb := a.cfg.Feedback
	var err error
	if c := fb.SES; c != nil {
		opts.SESFeedback, err = feedback.NewSESHandler(feedback.SESConfig{
			Decider:       a.engine,
			TopicARNs:     c.TopicARNs,
			AccountTag:    c.AccountTag,
			AccountHeader: c.AccountHeader,
			Logger:        log,
			OnOutcome:     count("ses"),
		})
		if err != nil {
			return err
		}
	}
	if c := fb.UseSend; c != nil {
		opts.UseSendFeedback, err = feedback.NewUseSendHandler(feedback.UseSendConfig{
			Decider:            a.engine,
			Secret:             c.Secret.Value(),
			AccountMetadataKey: c.AccountMetadataKey,
			Logger:             log,
			OnOutcome:          count("usesend"),
		})
		if err != nil {
			return err
		}
	}
	if c := fb.Generic; c != nil {
		opts.GenericFeedback, err = feedback.NewGenericHandler(feedback.GenericConfig{
			Decider:   a.engine,
			Secret:    c.Secret.Value(),
			Logger:    log,
			OnOutcome: count("generic"),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *App) secretScanning(opts *api.Options) error {
	gh := a.cfg.SecretScanning.GitHub
	if !gh.Enabled {
		return nil
	}
	outcomes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "catraca_secret_scanning_outcomes_total",
		Help: "What the GitHub secret scanning endpoint did with batches and leaked-key reports, by outcome.",
	}, []string{"outcome"})
	a.registry.MustRegister(outcomes, leakReportStats{a.audit})
	for _, o := range []secretscan.Outcome{secretscan.OutcomeAccepted, secretscan.OutcomeUnavailable, secretscan.OutcomeLeaked,
		secretscan.OutcomeRetry, secretscan.OutcomeResolveFailed, secretscan.OutcomeDecideFailed, secretscan.OutcomeInvalidSignature} {
		outcomes.WithLabelValues(string(o))
	}
	resolver, err := secretscan.NewHTTPResolver(secretscan.HTTPResolverConfig{
		URL:          gh.Resolver.URL,
		Secret:       gh.Resolver.Secret.Value(),
		SendRawToken: gh.Resolver.SendRawToken,
	})
	if err != nil {
		return err
	}
	cfg := secretscan.Config{
		Decider:     a.engine,
		Resolver:    resolver,
		Reports:     a.audit,
		Feedback:    gh.Feedback,
		MaxAttempts: gh.MaxAttempts,
		MaxAge:      gh.MaxAge,
		KeysURL:     gh.KeysURL,
		GitHubToken: gh.GitHubToken.Value(),
		Logger:      a.log.With("component", "secretscan"),
		OnOutcome:   func(o secretscan.Outcome) { outcomes.WithLabelValues(string(o)).Inc() },
	}
	if gh.Resolver.SendRawToken {
		// The resolver needs the raw token, so it waits in the queue,
		// sealed with a key only this secret's holders can derive.
		cfg.RawTokenSecret = gh.Resolver.Secret.Value()
	}
	if a.scan, err = secretscan.New(cfg); err != nil {
		return err
	}
	opts.GitHubSecretScanning = a.scan
	return nil
}

// Handler returns the HTTP handler for every route, except health and
// metrics when server.admin_addr is set. To serve it with your own
// http.Server, stop that server before calling Close.
func (a *App) Handler() http.Handler { return a.api }

// AdminHandler returns the HTTP handler for health and metrics alone, the
// routes server.admin_addr serves.
func (a *App) AdminHandler() http.Handler { return a.api.Admin() }

// Ruleset returns the ruleset decisions are made with, or nil when none is
// loaded.
func (a *App) Ruleset() *rules.Ruleset { return a.holder.Current() }

// Reload loads the ruleset file again and makes it current. On error the
// current ruleset keeps serving.
func (a *App) Reload() (*rules.Ruleset, error) {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	prev := a.holder.Current()
	// Load rather than Reload: Reload needs an earlier successful Load, and
	// the first load may have failed.
	rs, err := a.holder.Load(a.cfg.Rules.Path)
	if err != nil {
		a.loads.WithLabelValues("error").Inc()
		attrs := []any{"path", a.cfg.Rules.Path, "error", err}
		if prev != nil {
			attrs = append(attrs, "serving_version", prev.Version())
		}
		a.log.Error("ruleset did not load", attrs...)
		return nil, err
	}
	a.loads.WithLabelValues("ok").Inc()
	enforced := 0
	for _, r := range rs.Rules() {
		if r.Mode == decision.Enforce {
			enforced++
		}
	}
	attrs := []any{"path", a.cfg.Rules.Path, "version", rs.Version(), "rules", len(rs.Rules()), "enforced", enforced}
	if prev != nil {
		attrs = append(attrs, "previous_version", prev.Version())
	}
	a.log.Info("ruleset loaded", attrs...)
	for _, w := range rs.Lint() {
		a.log.Warn("ruleset warning", "warning", w.String())
	}
	for _, m := range MissingHooks(rs, a.cfg.Hooks) {
		a.log.Warn("ruleset warning", "warning", m)
	}
	return rs, nil
}

// MissingHooks lists the effects enforced rules of rs call that no hook
// carries out. Those effects are skipped, so each is probably a typo or a
// hook left out of the configuration.
func MissingHooks(rs *rules.Ruleset, hs []config.Hook) []string {
	var out []string
	for _, r := range rs.Rules() {
		if r.Mode != decision.Enforce {
			continue
		}
		for _, e := range r.Effects {
			if !slices.ContainsFunc(hs, func(h config.Hook) bool { return h.Name == e }) {
				out = append(out, fmt.Sprintf("rule %s: effect %s has no hook in the configuration, so it will not run", r.ID, e))
			}
		}
	}
	return out
}

// checks are the readiness checks: a ruleset is loaded and the server is not
// draining. They read the server's own state only; see dependencyMonitor
// for why the store and the audit database are not among them.
func (a *App) checks() []api.Check {
	return []api.Check{
		{Name: "rules", Check: func(context.Context) error {
			if a.holder.Current() == nil {
				return errors.New("no ruleset loaded")
			}
			return nil
		}},
		{Name: "shutdown", Check: func(context.Context) error {
			if a.draining.Load() {
				return errors.New("draining")
			}
			return nil
		}},
	}
}

// dependencies are the services the dependency monitor checks: Redis, when
// it is the store, and the audit database.
func (a *App) dependencies() []dependency {
	var deps []dependency
	if p, ok := a.store.(interface{ Ping(context.Context) error }); ok {
		deps = append(deps, dependency{name: "store", check: p.Ping})
	}
	deps = append(deps, dependency{name: "audit", check: a.audit.Ping})
	return deps
}

// Run listens on the configured addresses, server.listen and, when it is
// set, server.admin_addr, and serves until ctx ends, then shuts down. See
// Serve.
func (a *App) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", a.cfg.Server.Listen)
	if err != nil {
		_ = a.Close(context.Background())
		return fmt.Errorf("listen on %s: %w", a.cfg.Server.Listen, err)
	}
	var admin net.Listener
	if addr := a.cfg.Server.AdminAddr; addr != "" {
		if admin, err = net.Listen("tcp", addr); err != nil {
			ln.Close()
			_ = a.Close(context.Background())
			return fmt.Errorf("listen on %s (server.admin_addr): %w", addr, err)
		}
	}
	return a.Serve(ctx, ln, admin)
}

// Serve serves the API on ln, and health and metrics on admin when
// server.admin_addr is set, until ctx ends or a server fails. When ctx ends
// it drains first (see drain), then shuts down within the configured
// shutdown timeout: it stops accepting requests and waits for those in
// flight, then closes the rest (see Close). On Unix, SIGHUP reloads the
// ruleset while it serves. admin must be nil when server.admin_addr is not
// set, and not nil when it is.
func (a *App) Serve(ctx context.Context, ln, admin net.Listener) error {
	if (admin != nil) != (a.cfg.Server.AdminAddr != "") {
		ln.Close()
		if admin != nil {
			admin.Close()
		}
		_ = a.Close(context.Background())
		return errors.New("serve: pass an admin listener exactly when server.admin_addr is set")
	}
	servers := []*http.Server{a.httpServer(a.api)}
	listeners := []net.Listener{ln}
	attrs := []any{"addr", ln.Addr().String()}
	if admin != nil {
		servers = append(servers, a.httpServer(a.api.Admin()))
		listeners = append(listeners, admin)
		attrs = append(attrs, "admin_addr", admin.Addr().String())
	}
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	stopReloads := a.reloadOnSignal()
	defer stopReloads()
	a.log.Info("catraca is listening", append(attrs, "version", a.version)...)

	var serveErr error
	select {
	case <-ctx.Done():
		a.drain(servers...)
	case err := <-errc:
		serveErr = fmt.Errorf("serve HTTP: %w", err)
	case err := <-a.audit.failed():
		a.log.Error("the audit database cannot be opened, and waiting will not fix it; stopping", "error", err)
		serveErr = err
	}
	a.log.Info("shutting down", "timeout", a.cfg.Server.ShutdownTimeout)
	sctx, cancel := context.WithTimeout(context.Background(), a.cfg.Server.ShutdownTimeout)
	defer cancel()
	// The admin server stops after the API's, so probes and scrapes keep an
	// answer until the API has stopped.
	for _, srv := range servers {
		if err := srv.Shutdown(sctx); err != nil {
			serveErr = errors.Join(serveErr, fmt.Errorf("stop the HTTP server: %w", err))
		}
	}
	if err := a.Close(sctx); err != nil {
		serveErr = errors.Join(serveErr, err)
	}
	a.log.Info("stopped")
	return serveErr
}

func (a *App) httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
	}
}

// drain reports not ready on /readyz and keeps serving for
// server.drain_delay before the shutdown starts. A load balancer or a
// Kubernetes Service needs a few seconds to stop sending requests to an
// instance that is going away; an instance that stopped accepting at once
// would refuse the requests sent meanwhile. Responses close their
// connections from now on, so clients holding pooled connections to this
// instance reconnect, and the new connections go where the load balancer
// sends them. A second SIGINT or SIGTERM ends the wait early.
func (a *App) drain(servers ...*http.Server) {
	// Keep-alives go first, so a client that sees /readyz report draining
	// already gets its connection closed with the next response.
	for _, s := range servers {
		s.SetKeepAlivesEnabled(false)
	}
	a.draining.Store(true)
	delay := a.cfg.Server.DrainDelay
	if delay <= 0 {
		return
	}
	a.log.Info("draining: reporting not ready and still serving until the delay ends; signal again to stop now",
		"drain_delay", delay)
	again := make(chan os.Signal, 1)
	ossignal.Notify(again, os.Interrupt, syscall.SIGTERM)
	defer ossignal.Stop(again)
	select {
	case <-a.drainEnd(delay):
	case <-again:
		a.log.Info("second signal: shutting down without the rest of the drain delay")
	}
}

// reloadOnSignal reloads the ruleset on SIGHUP, where the platform has it,
// until the returned function is called.
func (a *App) reloadOnSignal() (stop func()) {
	ch := make(chan os.Signal, 1)
	if !notifyReload(ch) {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				a.log.Info("SIGHUP received: reloading the ruleset")
				_, _ = a.Reload()
			case <-done:
				return
			}
		}
	}()
	return func() {
		ossignal.Stop(ch)
		close(done)
	}
}

// Close shuts down everything but the HTTP server, which must already be
// stopped, in dependency order, once the dependency checks have stopped and
// the audit database, if it is still being opened, is given up on (the
// decisions waiting for it are dropped, and counted):
//
//  1. secret scanning stops claiming leaked-key reports and finishes the
//     attempts in flight, which still need the engine; reports still
//     pending wait in the audit database for the next start;
//  2. the engine hands its queued decisions to the audit log;
//  3. webhook delivery stops after the attempts in flight;
//  4. the audit database writes what is queued and closes;
//  5. the catalog closes the store.
//
// When ctx ends first, the remaining steps still run but stop waiting. Close
// is safe to call more than once.
func (a *App) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		var errs []error
		if a.deps != nil {
			a.deps.close()
		}
		if a.audit != nil {
			a.audit.stopOpening()
		}
		if a.scan != nil {
			if err := a.scan.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("stop secret scanning: %w", err))
			}
		}
		if a.engine != nil {
			if err := a.engine.Close(ctx); err != nil {
				errs = append(errs, fmt.Errorf("stop the engine: %w", err))
			}
		}
		if a.stopHooks != nil {
			a.stopHooks()
			select {
			case <-a.hooksDone:
			case <-ctx.Done():
				errs = append(errs, fmt.Errorf("stop webhook delivery: %w", ctx.Err()))
			}
		}
		if a.audit != nil {
			if err := a.audit.Close(ctx); err != nil {
				errs = append(errs, fmt.Errorf("close the audit database: %w", err))
			}
		}
		switch {
		case a.catalog != nil:
			if err := a.catalog.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close the store: %w", err))
			}
		case a.store != nil:
			if err := a.store.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close the store: %w", err))
			}
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}
