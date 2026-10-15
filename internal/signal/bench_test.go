package signal_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// BenchmarkObserve measures one send event, with an API key, an IP, a sender
// domain and three recipients, spread over 1000 accounts. The redis case runs
// against miniredis over loopback TCP, so it shows client and round trip
// overhead rather than what a real Redis server would sustain; redis-server
// runs against the real server at CATRACA_TEST_REDIS_URL, when it is set.
func BenchmarkObserve(b *testing.B) {
	const accounts = 1000
	events := make([]event.Event, accounts)
	for i := range events {
		events[i] = event.Event{
			Type:      event.Send,
			AccountID: fmt.Sprintf("acct-%d", i),
			APIKeyID:  fmt.Sprintf("key-%d", i),
			IP:        fmt.Sprintf("203.0.%d.%d", i/256, i%256),
			From:      fmt.Sprintf("news@sender-%d.example", i%50),
			To:        []string{"a@gmail.example", "b@outlook.example", "c@gmail.example"},
			Subject:   "Your weekly digest",
			Links:     []string{"https://sender.example/read", "https://bit.ly/x"},
		}
	}
	for i, be := range backends {
		b.Run(be.name, func(b *testing.B) {
			skipBackend(b, i)
			c := signal.NewCatalog(be.new(b), signal.Options{})
			defer c.Close()
			ctx := context.Background()
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				ev := events[i%accounts]
				ev.Time = t0.Add(time.Duration(i) * time.Millisecond)
				if _, err := c.Observe(ctx, ev); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

// BenchmarkObserveBusy is BenchmarkObserve for 20 busy accounts: before
// timing, each account sends once in every bucket of every window that ends
// when the benchmark starts, so every read sums 60 live buckets, as for an
// account that sends all the time.
func BenchmarkObserveBusy(b *testing.B) {
	const accounts = 20
	events := make([]event.Event, accounts)
	for i := range events {
		events[i] = event.Event{
			Type:      event.Send,
			AccountID: fmt.Sprintf("busy-%d", i),
			APIKeyID:  fmt.Sprintf("busy-key-%d", i),
			IP:        fmt.Sprintf("198.51.100.%d", i),
			From:      fmt.Sprintf("news@busy-%d.example", i),
			To:        []string{"a@gmail.example", "b@outlook.example", "c@gmail.example"},
			Subject:   "Your weekly digest",
			Links:     []string{"https://sender.example/read"},
		}
	}
	start := t0.Add(week)
	for i, be := range backends {
		b.Run(be.name, func(b *testing.B) {
			skipBackend(b, i)
			c := signal.NewCatalog(be.new(b), signal.Options{})
			defer c.Close()
			ctx := context.Background()
			for _, w := range []time.Duration{time.Minute, time.Hour, day, week} {
				for j := range 60 {
					for _, ev := range events {
						ev.Time = start.Add(-time.Duration(j) * w / 60)
						ev.To = []string{fmt.Sprintf("u%d@d%d.example", j, j%7)}
						if _, err := c.Observe(ctx, ev); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				ev := events[i%accounts]
				ev.Time = start.Add(time.Duration(i) * time.Microsecond)
				if _, err := c.Observe(ctx, ev); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}
