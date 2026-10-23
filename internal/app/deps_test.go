package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// lockedBuffer is a bytes.Buffer safe for a logger's concurrent writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDependencyMonitor checks dependencies that answer, fail and hang:
// each is checked on its own, under its own timeout, a hung check is not
// started again while it runs, and logs mark changes, not every check.
func TestDependencyMonitor(t *testing.T) {
	var (
		failing   atomic.Bool
		hangCalls atomic.Int32
		release   = make(chan struct{})
	)
	failing.Store(true)
	deps := []dependency{
		{name: "fast", check: func(context.Context) error { return nil }},
		{name: "flaky", check: func(context.Context) error {
			if failing.Load() {
				return errors.New("dial tcp 10.0.0.7:6379: connection refused")
			}
			return nil
		}},
		// hung ignores its context, like a client blocked on a socket.
		{name: "hung", check: func(context.Context) error {
			hangCalls.Add(1)
			<-release
			return nil
		}},
	}
	logs := &lockedBuffer{}
	m := newDependencyMonitor(deps, prometheus.NewRegistry(), slog.New(slog.NewTextHandler(logs, nil)))
	// The timeout leaves the answering checks room on a loaded machine.
	m.interval, m.timeout = 20*time.Millisecond, 200*time.Millisecond
	if s := m.statuses(); s["fast"].Status != "unknown" {
		t.Errorf("before the first check: %+v", s)
	}
	m.start()
	defer m.close()
	defer close(release)

	waitFor(t, "the first round", func() bool {
		s := m.statuses()
		return s["fast"].Status == "ok" && s["flaky"].Status == "unavailable" && s["hung"].Status == "timeout"
	})
	s := m.statuses()
	if d := s["hung"].DurationMS; d < 200 || d > 10_000 {
		t.Errorf("hung reported after %vms, want about the 200ms timeout", d)
	}
	if strings.Contains(s["flaky"].Status, "10.0.0.7") {
		t.Errorf("the status shows the error: %q", s["flaky"].Status)
	}
	if gaugeValue(t, m.up.WithLabelValues("fast")) != 1 || gaugeValue(t, m.up.WithLabelValues("flaky")) != 0 || gaugeValue(t, m.up.WithLabelValues("hung")) != 0 {
		t.Error("catraca_dependency_up does not match the statuses")
	}

	// Several more rounds, counted by the failures metric: the hung check
	// is still running, so it is not started again, and the failing one is
	// logged once.
	waitFor(t, "more rounds", func() bool { return counterValue(t, m.failures.WithLabelValues("flaky")) >= 4 })
	if n := hangCalls.Load(); n != 1 {
		t.Errorf("the hung check was started %d times, want once while it runs", n)
	}
	if n := strings.Count(logs.String(), "dependency=flaky"); n != 1 {
		t.Errorf("flaky logged %d times while down, want once:\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), "10.0.0.7") {
		t.Errorf("the log lacks the error:\n%s", logs)
	}

	down := m.statuses()["flaky"].Since
	failing.Store(false)
	waitFor(t, "flaky to recover", func() bool { return m.statuses()["flaky"].Status == "ok" })
	// Not After: the wall clock of some systems ticks every few
	// milliseconds.
	if up := m.statuses()["flaky"]; up.Since.Before(down) || up.CheckedAt.Before(up.Since) {
		t.Errorf("since and checked_at after recovery: %+v (down since %v)", up, down)
	}
	if !strings.Contains(logs.String(), "available again") {
		t.Errorf("no recovery log:\n%s", logs)
	}
}
