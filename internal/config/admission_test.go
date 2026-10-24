package config

import (
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/engine"
)

func TestAdmissionAndBreakerDefaults(t *testing.T) {
	cfg := mustParse(t, minimal, nil)
	s, b := cfg.Server, cfg.Engine.Breaker
	if s.MaxInflight != 256 || s.InflightWait != 2*time.Millisecond || s.InflightLimit != "adaptive" {
		t.Errorf("server admission = %d, %s, %s; want 256, 2ms, adaptive", s.MaxInflight, s.InflightWait, s.InflightLimit)
	}
	if b.FailureThreshold != 20 || b.FailureWindow != 500*time.Millisecond || b.Cooldown != 2*time.Second || b.Probes != 5 {
		t.Errorf("engine.breaker = %+v, want 20, 500ms, 2s, 5", b)
	}
	want := engine.BreakerOptions{
		Failures: engine.DefaultBreakerFailures,
		Window:   engine.DefaultBreakerWindow,
		Cooldown: engine.DefaultBreakerCooldown,
		Probes:   engine.DefaultBreakerProbes,
	}
	if got := b.Options(); got != want {
		t.Errorf("breaker options = %+v, want the engine's defaults %+v", got, want)
	}
}

func TestAdmissionAndBreakerSet(t *testing.T) {
	cfg := mustParse(t, minimal+`
server:
  max_inflight: 64
  inflight_wait: 5ms
  inflight_limit: static
engine:
  breaker:
    failure_threshold: 50
    failure_window: 1s
    cooldown: 500ms
    probes: 2
`, nil)
	s := cfg.Server
	if s.MaxInflight != 64 || s.InflightWait != 5*time.Millisecond || s.InflightLimit != "static" {
		t.Errorf("server admission = %d, %s, %s", s.MaxInflight, s.InflightWait, s.InflightLimit)
	}
	want := engine.BreakerOptions{Failures: 50, Window: time.Second, Cooldown: 500 * time.Millisecond, Probes: 2}
	if got := cfg.Engine.Breaker.Options(); got != want {
		t.Errorf("breaker options = %+v, want %+v", got, want)
	}
}

// TestInflightWaitZero checks that 0s, unlike for other durations, is a
// setting: requests over the limit are shed without waiting.
func TestInflightWaitZero(t *testing.T) {
	cfg := mustParse(t, minimal+"server: {inflight_wait: 0s}\n", nil)
	if cfg.Server.InflightWait != 0 {
		t.Errorf("inflight_wait = %v, want 0", cfg.Server.InflightWait)
	}
}

func TestAdmissionAndBreakerValidation(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"max inflight", "server: {max_inflight: 0}", "server.max_inflight: must be at least 1, got 0"},
		{"inflight wait", "server: {inflight_wait: -1ms}", "server.inflight_wait: must not be negative, got -1ms; 0s sheds at once"},
		{"inflight limit", "server: {inflight_limit: gradient}", `server.inflight_limit: want adaptive or static, got "gradient"`},
		{"failure threshold", "engine: {breaker: {failure_threshold: 0}}", "engine.breaker.failure_threshold: must be at least 1, got 0"},
		{"failure window", "engine: {breaker: {failure_window: -1s}}", "engine.breaker.failure_window: must be a positive duration, got -1s"},
		{"cooldown", "engine: {breaker: {cooldown: 0s}}", "engine.breaker.cooldown: must be a positive duration, got 0s"},
		{"probes", "engine: {breaker: {probes: -1}}", "engine.breaker.probes: must be at least 1, got -1"},
		{"unknown breaker field", "engine: {breaker: {threshold: 3}}", "engine.breaker.threshold: unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireError(t, parseErrors(t, minimal+tt.yaml+"\n", nil), tt.want)
		})
	}
}
