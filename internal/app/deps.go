package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/api"
)

// How often the dependencies are checked, and how long each check may take.
// A check that takes longer is reported as timed out; the next one starts
// only once it returns, so a hung dependency holds one check at a time.
const (
	dependencyInterval = 5 * time.Second
	dependencyTimeout  = 2 * time.Second
)

// dependency is a service the server uses but does not need in order to be
// ready. check returns nil when the service answers; its error is logged,
// not shown on /readyz, so it may name hosts.
type dependency struct {
	name  string
	check func(context.Context) error
}

// dependencyMonitor checks the dependencies in the background, each on its
// own, under its own timeout, and keeps their latest health for
// /readyz?verbose and for metrics. It logs when a dependency goes down and
// when it comes back, not on every check.
//
// Readiness does not depend on it. The store and the audit database are
// shared by every instance, so a readiness check on them would take every
// instance out of the load balancer when one of them fails, while decisions
// work without them: degraded without the store, unrecorded without the
// audit database.
type dependencyMonitor struct {
	deps     []dependency
	interval time.Duration
	timeout  time.Duration
	log      *slog.Logger

	up       *prometheus.GaugeVec
	duration *prometheus.GaugeVec
	failures *prometheus.CounterVec

	mu      sync.Mutex
	state   map[string]api.DependencyStatus
	running map[string]bool

	// ctx ends when the monitor is closed, which cancels the checks.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newDependencyMonitor(deps []dependency, reg prometheus.Registerer, log *slog.Logger) *dependencyMonitor {
	m := &dependencyMonitor{
		deps:     deps,
		interval: dependencyInterval,
		timeout:  dependencyTimeout,
		log:      log,
		up: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "catraca_dependency_up",
			Help: "1 when the last check of the dependency (store, audit) succeeded, else 0. Readiness does not depend on it.",
		}, []string{"dependency"}),
		duration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "catraca_dependency_check_duration_seconds",
			Help: "How long the last check of the dependency took; a check that timed out counts as the timeout.",
		}, []string{"dependency"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_dependency_check_failures_total",
			Help: "Checks of the dependency that failed or timed out.",
		}, []string{"dependency"}),
		state:   make(map[string]api.DependencyStatus, len(deps)),
		running: make(map[string]bool, len(deps)),
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	reg.MustRegister(m.up, m.duration, m.failures)
	for _, d := range deps {
		m.state[d.name] = api.DependencyStatus{Status: "unknown"}
		m.up.WithLabelValues(d.name)
		m.duration.WithLabelValues(d.name)
		m.failures.WithLabelValues(d.name)
	}
	return m
}

// start checks every dependency now and then every interval, until Close.
func (m *dependencyMonitor) start() {
	m.wg.Go(func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			m.checkAll()
			select {
			case <-ticker.C:
			case <-m.ctx.Done():
				return
			}
		}
	})
}

// checkAll starts a check of each dependency whose previous check has
// returned.
func (m *dependencyMonitor) checkAll() {
	for _, d := range m.deps {
		m.mu.Lock()
		busy := m.running[d.name]
		m.running[d.name] = true
		m.mu.Unlock()
		if !busy {
			m.wg.Go(func() { m.checkOne(d) })
		}
	}
}

var errCheckTimeout = errors.New("the check timed out")

// checkOne runs one check and records its result. A check that ignores its
// context is reported at the timeout and left to return on its own, in the
// background, so a dependency that hangs never delays the others.
func (m *dependencyMonitor) checkOne(d dependency) {
	ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
	defer cancel()
	start := time.Now()
	result := make(chan error, 1)
	go func() {
		err := d.check(ctx)
		m.mu.Lock()
		m.running[d.name] = false
		m.mu.Unlock()
		result <- err
	}()
	var err error
	select {
	case err = <-result:
		if err != nil && ctx.Err() != nil {
			err = errCheckTimeout
		}
	case <-ctx.Done():
		err = errCheckTimeout
	}
	if m.ctx.Err() != nil {
		return // closed
	}
	m.record(d.name, err, time.Since(start))
}

func (m *dependencyMonitor) record(name string, err error, took time.Duration) {
	now := time.Now()
	status := "ok"
	switch {
	case errors.Is(err, errCheckTimeout):
		status = "timeout"
	case errors.Is(err, errAuditNotOpen):
		status = "not_open"
	case err != nil:
		status = "unavailable"
	}
	m.duration.WithLabelValues(name).Set(took.Seconds())
	if err != nil {
		m.up.WithLabelValues(name).Set(0)
		m.failures.WithLabelValues(name).Inc()
	} else {
		m.up.WithLabelValues(name).Set(1)
	}

	m.mu.Lock()
	prev := m.state[name]
	next := api.DependencyStatus{Status: status, Since: prev.Since, CheckedAt: now, DurationMS: float64(took.Microseconds()) / 1000}
	if status != prev.Status {
		next.Since = now
	}
	m.state[name] = next
	m.mu.Unlock()

	switch {
	case err != nil && (prev.Status == "ok" || prev.Status == "unknown"):
		m.log.Warn("a dependency is unavailable; deciding without it until it is back",
			"dependency", name, "status", status, "error", err)
	case err == nil && prev.Status != "ok" && prev.Status != "unknown":
		m.log.Info("a dependency is available again", "dependency", name, "down_for", now.Sub(prev.Since).Round(time.Millisecond))
	}
}

// statuses returns the latest health of every dependency.
func (m *dependencyMonitor) statuses() map[string]api.DependencyStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]api.DependencyStatus, len(m.state))
	for k, v := range m.state {
		out[k] = v
	}
	return out
}

// close stops the checks: those running are canceled and no longer
// recorded.
func (m *dependencyMonitor) close() {
	m.cancel()
	m.wg.Wait()
}
