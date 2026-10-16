// Command load sends send events to a running Catraca at a fixed rate and
// reports the latency of POST /v1/decide as the platform would see it
// (connection, JSON, rules, store and audit included) next to the engine's
// own time, which the server reports in each decision's latency_us.
//
//	go run ./bench/load -url http://localhost:8080 -token $CATRACA_API_TOKEN -rps 2000 -duration 30s
//
// The load is open-loop: requests start on schedule whether or not earlier
// ones finished, so a slow server shows up as latency instead of hiding
// behind a lower request rate.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/monotime"
)

func main() {
	url := flag.String("url", "http://localhost:8080", "Catraca base URL")
	token := flag.String("token", os.Getenv("CATRACA_API_TOKEN"), "API token (default $CATRACA_API_TOKEN)")
	rps := flag.Int("rps", 1000, "requests per second")
	duration := flag.Duration("duration", 20*time.Second, "how long to measure")
	warmup := flag.Duration("warmup", 3*time.Second, "requests sent before measuring starts")
	accounts := flag.Int("accounts", 5000, "distinct accounts the events come from")
	flag.Parse()
	if *token == "" {
		fmt.Fprintln(os.Stderr, "load: -token or CATRACA_API_TOKEN is required")
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 1024,
		},
	}
	var (
		mu        sync.Mutex
		roundTrip = make([]time.Duration, 0, *rps*int(duration.Seconds()))
		engine    = make([]time.Duration, 0, *rps*int(duration.Seconds()))
		failures  atomic.Int64
		actions   sync.Map
		wg        sync.WaitGroup
	)
	ctx, cancel := context.WithTimeout(context.Background(), *warmup+*duration)
	defer cancel()
	start := time.Now()

	// Timers on some systems (Windows) cannot fire every few hundred
	// microseconds, so requests go out in small batches on a 5 ms tick.
	const tick = 5 * time.Millisecond
	perTick := float64(*rps) * tick.Seconds()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	sent, due := 0, 0.0
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			fmt.Printf("target      %d req/s for %s\n", *rps, *duration)
			fmt.Printf("measured    %d requests, %d failed (%.0f req/s achieved)\n",
				len(roundTrip), failures.Load(), float64(len(roundTrip))/duration.Seconds())
			fmt.Printf("round trip  %s\n", percentiles(roundTrip))
			fmt.Printf("engine      %s\n", percentiles(engine))
			fmt.Print("actions    ")
			actions.Range(func(k, v any) bool {
				fmt.Printf(" %s=%d", k, v.(*atomic.Int64).Load())
				return true
			})
			fmt.Println()
			return
		case <-ticker.C:
		}
		measured := time.Since(start) >= *warmup
		for due += perTick; due >= 1; due-- {
			body := event(sent, *accounts)
			sent++
			wg.Add(1)
			go func() {
				defer wg.Done()
				t0 := monotime.Now()
				action, micros, err := decide(client, *url, *token, body)
				elapsed := monotime.Since(t0)
				if !measured {
					return
				}
				if err != nil {
					failures.Add(1)
					return
				}
				n, _ := actions.LoadOrStore(action, new(atomic.Int64))
				n.(*atomic.Int64).Add(1)
				mu.Lock()
				roundTrip = append(roundTrip, elapsed)
				engine = append(engine, time.Duration(micros)*time.Microsecond)
				mu.Unlock()
			}()
		}
	}
}

// event builds a send from one of n accounts. A few accounts send far more
// than the rest, as on a real platform, so some rules see bursts.
func event(i, n int) []byte {
	account := int(float64(n) * rand.Float64() * rand.Float64())
	b, _ := json.Marshal(map[string]any{
		"type":       "send",
		"account_id": fmt.Sprintf("acc_%d", account),
		"api_key_id": fmt.Sprintf("key_%d", account),
		"ip":         fmt.Sprintf("198.51.100.%d", account%250+1),
		"from":       fmt.Sprintf("hello@sender%d.example", account),
		"to":         []string{fmt.Sprintf("user%d@mail%d.example", i, i%40)},
		"subject":    "Your receipt",
		"links":      []string{"https://example.com/r"},
	})
	return b
}

func decide(client *http.Client, url, token string, body []byte) (action string, engineMicros int64, err error) {
	req, err := http.NewRequest(http.MethodPost, url+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return "", 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out struct {
		Decision struct {
			Action  string `json:"action"`
			Latency int64  `json:"latency_us"`
		} `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	return out.Decision.Action, out.Decision.Latency, nil
}

func percentiles(lat []time.Duration) string {
	if len(lat) == 0 {
		return "no samples"
	}
	slices.Sort(lat)
	pct := func(p float64) time.Duration {
		return lat[min(len(lat)-1, int(p*float64(len(lat))))].Round(time.Microsecond)
	}
	return fmt.Sprintf("p50 %s  p90 %s  p99 %s  p99.9 %s  max %s",
		pct(0.50), pct(0.90), pct(0.99), pct(0.999), pct(1))
}
