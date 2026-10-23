package app_test

import (
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/engine"
)

// TestStoreBreakerWithRedisDown points the server at a "Redis" that closes
// every connection it accepts: after a run of failed decisions the breaker
// opens, later decisions skip the store, a key leak answers 503 with
// Retry-After at once, and the metrics and the log say so.
func TestStoreBreakerWithRedisDown(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	h := newHarness(t, options{redisURL: "redis://" + ln.Addr().String() + "/0"})

	const open = `catraca_store_breaker_state{state="open"} 1`
	decisions := 0
	decide := func() {
		t.Helper()
		if d, _ := h.decide(send("acct", "a@shop.example")); !d.Degraded {
			t.Fatalf("decision with Redis down is not degraded: %+v", d)
		}
		decisions++
	}
	// The calls fail at once, so the breaker opens once they have failed
	// for its window.
	start := time.Now()
	for !strings.Contains(string(h.do("GET", "/metrics", "", nil).body), open) {
		if time.Since(start) > 30*time.Second {
			t.Fatalf("the breaker did not open after %d failed decisions", decisions)
		}
		for range 10 {
			decide()
		}
	}
	if decisions < engine.DefaultBreakerFailures {
		t.Errorf("the breaker opened after %d decisions, fewer than its threshold", decisions)
	}
	for range 3 {
		decide()
	}
	r := h.do("POST", "/v1/events", token, `{"type":"key_leak","api_key_id":"key_1"}`)
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "1" || r.errorCode(t) != "unavailable" {
		t.Errorf("key_leak with the breaker open: %d %v %s", r.status, r.header, r.body)
	}

	m := string(h.do("GET", "/metrics", "", nil).body)
	for _, want := range []string{
		// A probe after a slow moment fails and opens it again, so it is
		// open either way, and opened from closed once.
		open,
		`catraca_store_breaker_transitions_total{from="closed",to="open"} 1`,
		`catraca_degraded_decisions_total ` + strconv.Itoa(decisions),
		`catraca_admission_limit{group="decisions"} 256`,
		`catraca_admission_limit{group="feedback"} 256`,
		`catraca_admission_inflight{route="POST /v1/decide"} 0`,
		`catraca_admission_shed_total{route="POST /v1/decide"} 0`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	short := regexp.MustCompile(`(?m)^catraca_short_circuited_decisions_total (\d+)$`).FindStringSubmatch(m)
	if short == nil || short[1] == "0" {
		t.Errorf("short-circuited decisions = %v, want some", short)
	}
	if !strings.Contains(h.logs.String(), "store breaker opened") {
		t.Error("no log line for the breaker opening")
	}
}
