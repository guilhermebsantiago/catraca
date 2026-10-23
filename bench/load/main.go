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
//
// -phases runs several rates one after the other, such as 4000x20s,1000x20s
// for an overload and what follows it. -timeline prints a line per second,
// and -metrics, the server's /metrics URL, adds to each line the decision
// limit, the store breaker's state and what was shed or short-circuited, and
// prints how those counters moved over the run.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/monotime"
)

// phase is a rate held for a while.
type phase struct {
	rps      int
	duration time.Duration
}

// sample is one measured request.
type sample struct {
	// at is when it was sent, from the start of the measurement.
	at        time.Duration
	roundTrip time.Duration
	engine    time.Duration
	status    int
	action    string
	degraded  bool
	err       bool
}

func main() {
	url := flag.String("url", "http://localhost:8080", "Catraca base URL")
	token := flag.String("token", os.Getenv("CATRACA_API_TOKEN"), "API token (default $CATRACA_API_TOKEN)")
	rps := flag.Int("rps", 1000, "requests per second")
	duration := flag.Duration("duration", 20*time.Second, "how long to measure")
	phasesFlag := flag.String("phases", "", "rates to run one after the other, as RPSxDURATION,...; replaces -rps and -duration")
	warmup := flag.Duration("warmup", 3*time.Second, "requests sent before measuring starts, at the first rate")
	accounts := flag.Int("accounts", 5000, "distinct accounts the events come from")
	timeline := flag.Bool("timeline", false, "print a line per second of the measurement")
	metricsURL := flag.String("metrics", "", "the server's /metrics URL, sampled every second")
	flag.Parse()
	if *token == "" {
		fmt.Fprintln(os.Stderr, "load: -token or CATRACA_API_TOKEN is required")
		os.Exit(2)
	}
	phases := []phase{{*rps, *duration}}
	if *phasesFlag != "" {
		var err error
		if phases, err = parsePhases(*phasesFlag); err != nil {
			fmt.Fprintln(os.Stderr, "load: -phases:", err)
			os.Exit(2)
		}
	}
	var total time.Duration
	for _, p := range phases {
		total += p.duration
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 1024,
		},
	}
	var (
		mu      sync.Mutex
		samples = make([]sample, 0, phases[0].rps*int(total.Seconds()))
		wg      sync.WaitGroup
	)
	ctx, cancel := context.WithTimeout(context.Background(), *warmup+total)
	defer cancel()
	start := time.Now()
	measureStart := start.Add(*warmup)

	var scrapes []scrape
	if *metricsURL != "" {
		done := make(chan struct{})
		var swg sync.WaitGroup
		swg.Go(func() { scrapes = scrapeEverySecond(client, *metricsURL, measureStart, done) })
		defer func() {
			close(done)
			swg.Wait()
			report(samples, phases, *timeline, scrapes)
		}()
	} else {
		defer func() { report(samples, phases, *timeline, nil) }()
	}

	// Timers on some systems (Windows) cannot fire every few hundred
	// microseconds, so requests go out in small batches on a 5 ms tick.
	const tick = 5 * time.Millisecond
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	sent, due := 0, 0.0
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-ticker.C:
		}
		now := time.Now()
		rate := rateAt(phases, now.Sub(measureStart))
		measured := !now.Before(measureStart)
		at := now.Sub(measureStart)
		for due += float64(rate) * tick.Seconds(); due >= 1; due-- {
			body := event(sent, *accounts)
			sent++
			wg.Add(1)
			go func() {
				defer wg.Done()
				t0 := monotime.Now()
				s := decide(client, *url, *token, body)
				s.roundTrip = monotime.Since(t0)
				s.at = at
				if !measured {
					return
				}
				mu.Lock()
				samples = append(samples, s)
				mu.Unlock()
			}()
		}
	}
}

func parsePhases(s string) ([]phase, error) {
	var out []phase
	for part := range strings.SplitSeq(s, ",") {
		rate, dur, ok := strings.Cut(strings.TrimSpace(part), "x")
		r, err := strconv.Atoi(rate)
		if !ok || err != nil || r <= 0 {
			return nil, fmt.Errorf("%q: want RPSxDURATION, such as 4000x20s", part)
		}
		d, err := time.ParseDuration(dur)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("%q: want RPSxDURATION, such as 4000x20s", part)
		}
		out = append(out, phase{r, d})
	}
	return out, nil
}

// rateAt is the rate of the phase that elapsed falls in; the warmup, before
// the measurement, runs at the first.
func rateAt(phases []phase, elapsed time.Duration) int {
	for _, p := range phases {
		if elapsed < p.duration {
			return p.rps
		}
		elapsed -= p.duration
	}
	return phases[len(phases)-1].rps
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

func decide(client *http.Client, url, token string, body []byte) sample {
	req, err := http.NewRequest(http.MethodPost, url+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return sample{err: true}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return sample{err: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return sample{err: true, status: resp.StatusCode}
	}
	var out struct {
		Decision struct {
			Action   string `json:"action"`
			Degraded bool   `json:"degraded"`
			Latency  int64  `json:"latency_us"`
		} `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return sample{err: true, status: resp.StatusCode}
	}
	return sample{
		status:   resp.StatusCode,
		action:   out.Decision.Action,
		degraded: out.Decision.Degraded,
		engine:   time.Duration(out.Decision.Latency) * time.Microsecond,
	}
}

func report(samples []sample, phases []phase, timeline bool, scrapes []scrape) {
	var parts []string
	for _, p := range phases {
		parts = append(parts, fmt.Sprintf("%d req/s for %s", p.rps, p.duration))
	}
	fmt.Printf("target      %s\n", strings.Join(parts, ", then "))
	var total time.Duration
	for _, p := range phases {
		total += p.duration
	}
	s := summarize(samples)
	fmt.Printf("measured    %d requests, %d failed%s (%.0f req/s achieved)\n",
		len(samples), s.failed, s.statuses(), float64(len(samples))/total.Seconds())
	fmt.Printf("round trip  %s\n", percentiles(s.roundTrip))
	fmt.Printf("engine      %s\n", percentiles(s.engine))
	fmt.Printf("degraded    %d of %d decisions (%.1f%%)\n", s.degraded, len(s.roundTrip), pct(s.degraded, len(s.roundTrip)))
	fmt.Print("actions    ")
	for _, a := range sortedKeys(s.actions) {
		fmt.Printf(" %s=%d", a, s.actions[a])
	}
	fmt.Println()
	if len(scrapes) >= 2 {
		first, last := scrapes[0], scrapes[len(scrapes)-1]
		fmt.Println("server      " + first.delta(last))
	}
	if len(phases) > 1 {
		var from time.Duration
		for _, p := range phases {
			var in []sample
			for _, smp := range samples {
				if smp.at >= from && smp.at < from+p.duration {
					in = append(in, smp)
				}
			}
			ps := summarize(in)
			fmt.Printf("phase       %d req/s: %d requests, %d failed, degraded %.1f%%, round trip %s\n",
				p.rps, len(in), ps.failed, pct(ps.degraded, len(ps.roundTrip)), percentiles(ps.roundTrip))
			from += p.duration
		}
	}

	if !timeline {
		return
	}
	fmt.Println()
	header := "  s    req/s    p50     p99     max   degraded  failed"
	if scrapes != nil {
		header += "   limit  breaker    shed  short  goroutines"
	}
	fmt.Println(header)
	bySecond := map[int][]sample{}
	for _, smp := range samples {
		bySecond[int(smp.at/time.Second)] = append(bySecond[int(smp.at/time.Second)], smp)
	}
	for sec := range int(total / time.Second) {
		s := summarize(bySecond[sec])
		line := fmt.Sprintf("%3d %8d %7s %7s %7s %8.1f%% %7d", sec, len(bySecond[sec]),
			ms(at(s.roundTrip, 0.5)), ms(at(s.roundTrip, 0.99)), ms(at(s.roundTrip, 1)), pct(s.degraded, len(s.roundTrip)), s.failed)
		if scrapes != nil && sec+1 < len(scrapes) {
			prev, cur := scrapes[sec], scrapes[sec+1]
			line += fmt.Sprintf(" %7.0f  %-9s %6.0f %6.0f %11.0f", cur.limit, cur.breaker,
				cur.shed-prev.shed, cur.short-prev.short, cur.goroutines)
		}
		fmt.Println(line)
	}
}

type summary struct {
	roundTrip, engine []time.Duration
	degraded, failed  int
	byStatus          map[int]int
	actions           map[string]int
}

func summarize(samples []sample) summary {
	s := summary{byStatus: map[int]int{}, actions: map[string]int{}}
	for _, smp := range samples {
		if smp.err {
			s.failed++
			s.byStatus[smp.status]++
			continue
		}
		s.roundTrip = append(s.roundTrip, smp.roundTrip)
		s.engine = append(s.engine, smp.engine)
		s.actions[smp.action]++
		if smp.degraded {
			s.degraded++
		}
	}
	slices.Sort(s.roundTrip)
	slices.Sort(s.engine)
	return s
}

// statuses lists the failures by HTTP status; 0 is a request that got no
// answer.
func (s summary) statuses() string {
	if s.failed == 0 {
		return ""
	}
	var parts []string
	for _, st := range sortedKeys(s.byStatus) {
		parts = append(parts, fmt.Sprintf("%d: %d", st, s.byStatus[st]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func sortedKeys[K int | string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func pct(n, of int) float64 {
	if of == 0 {
		return 0
	}
	return 100 * float64(n) / float64(of)
}

// at returns the p-quantile of sorted latencies, or 0 for none.
func at(lat []time.Duration, p float64) time.Duration {
	if len(lat) == 0 {
		return 0
	}
	return lat[min(len(lat)-1, int(p*float64(len(lat))))]
}

func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d.Microseconds())/1000, 'f', 2, 64)
}

func percentiles(lat []time.Duration) string {
	if len(lat) == 0 {
		return "no samples"
	}
	return fmt.Sprintf("p50 %s  p90 %s  p99 %s  p99.9 %s  max %s",
		at(lat, 0.50).Round(time.Microsecond), at(lat, 0.90).Round(time.Microsecond),
		at(lat, 0.99).Round(time.Microsecond), at(lat, 0.999).Round(time.Microsecond), at(lat, 1).Round(time.Microsecond))
}

// scrape is what the server's metrics said at one moment.
type scrape struct {
	limit      float64
	breaker    string
	shed       float64
	short      float64
	degraded   float64
	opened     float64
	goroutines float64
}

func (a scrape) delta(b scrape) string {
	return fmt.Sprintf("shed %.0f, short-circuited %.0f, degraded %.0f, breaker opened %.0f times; decision limit %.0f, breaker %s at the end",
		b.shed-a.shed, b.short-a.short, b.degraded-a.degraded, b.opened-a.opened, b.limit, b.breaker)
}

var metricLine = regexp.MustCompile(`^([a-z_]+)(\{[^}]*\})? ([0-9.eE+-]+)$`)

// scrapeEverySecond reads the metrics at the start of the measurement and
// once a second after it, until done is closed.
func scrapeEverySecond(client *http.Client, url string, from time.Time, done <-chan struct{}) []scrape {
	var out []scrape
	next := from
	for {
		select {
		case <-done:
			return out
		case <-time.After(time.Until(next)):
		}
		out = append(out, scrapeOnce(client, url))
		next = next.Add(time.Second)
	}
}

func scrapeOnce(client *http.Client, url string) scrape {
	var s scrape
	resp, err := client.Get(url)
	if err != nil {
		return s
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := metricLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		v, _ := strconv.ParseFloat(m[3], 64)
		switch name, labels := m[1], m[2]; {
		case name == "catraca_admission_limit" && labels == `{group="decisions"}`:
			s.limit = v
		case name == "catraca_store_breaker_state" && v == 1:
			s.breaker = strings.TrimSuffix(strings.TrimPrefix(labels, `{state="`), `"}`)
		case name == "catraca_admission_shed_total":
			s.shed += v
		case name == "catraca_short_circuited_decisions_total":
			s.short = v
		case name == "catraca_degraded_decisions_total":
			s.degraded = v
		case name == "catraca_store_breaker_transitions_total" && strings.Contains(labels, `to="open"`):
			s.opened += v
		case name == "go_goroutines":
			s.goroutines = v
		}
	}
	return s
}
