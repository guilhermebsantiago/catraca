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
// and redis-cluster-server run against the real server at
// CATRACA_TEST_REDIS_URL and the cluster at CATRACA_TEST_REDIS_CLUSTER, when
// they are set, and also report redis-us/op: the CPU time Redis spent per
// event during the loop, which bounds how many events one Redis core can take.
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
			done := measureRedis(b, i)
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				ev := events[n%accounts]
				ev.Time = t0.Add(time.Duration(n) * time.Millisecond)
				if _, err := c.Observe(ctx, ev); err != nil {
					b.Fatal(err)
				}
				n++
			}
			done()
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
			done := measureRedis(b, i)
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				ev := events[n%accounts]
				ev.Time = start.Add(time.Duration(n) * time.Microsecond)
				if _, err := c.Observe(ctx, ev); err != nil {
					b.Fatal(err)
				}
				n++
			}
			done()
		})
	}
}

// BenchmarkObserveWideSend measures the most store work one event may ask
// for: a send to event.MaxRecipients recipients, each at a domain of its own.
// Every distinct recipient domain is added to two distinct sets, so the cost
// grows with the domains, and on Redis the script that pays it holds the
// server; the limit on recipients is what bounds it.
func BenchmarkObserveWideSend(b *testing.B) {
	to := make([]string, event.MaxRecipients)
	for i := range to {
		to[i] = fmt.Sprintf("u@d%d.example", i)
	}
	for i, be := range backends {
		b.Run(be.name, func(b *testing.B) {
			skipBackend(b, i)
			c := signal.NewCatalog(be.new(b), signal.Options{})
			defer c.Close()
			ctx := context.Background()
			done := measureRedis(b, i)
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				ev := event.Event{
					Type:      event.Send,
					AccountID: fmt.Sprintf("wide-%d", n%20),
					Time:      t0.Add(time.Duration(n) * time.Millisecond),
					To:        to,
				}
				if _, err := c.Observe(ctx, ev); err != nil {
					b.Fatal(err)
				}
				n++
			}
			done()
		})
	}
}

// measureRedis reads the CPU time of backend i's server, when it has one, and
// returns a function to call after the loop, which reports the CPU time per
// iteration as redis-us/op.
func measureRedis(b *testing.B, i int) func() {
	if backends[i].cpu == nil {
		return func() {}
	}
	cpu := backends[i].cpu(b)
	before := cpu()
	return func() {
		b.ReportMetric((cpu()-before)*1e6/float64(b.N), "redis-us/op")
	}
}
