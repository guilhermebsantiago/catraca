package signal_test

import (
	"context"
	"fmt"
	"strconv"
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
// The events have no id, so nothing guards them against a retry.
func BenchmarkObserve(b *testing.B) { benchmarkObserve(b, "") }

// BenchmarkObserveWithID is BenchmarkObserve for events that carry an id, as
// a platform sends to make its retries count once: each event's id is new,
// so each one writes its dedupe entry (one key on a single Redis, one per
// slot with increments on a cluster). BenchmarkObserveRetry sends one event
// with an id once and then again on every iteration: each is a duplicate,
// which skips its increments.
func BenchmarkObserveWithID(b *testing.B) { benchmarkObserve(b, "new") }

func BenchmarkObserveRetry(b *testing.B) { benchmarkObserve(b, "same") }

// benchmarkObserve runs BenchmarkObserve with event ids: none ("") a new one
// per event ("new"), or the same one for every event of an account ("same").
func benchmarkObserve(b *testing.B, ids string) {
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
		if ids == "same" {
			events[i].ID = fmt.Sprintf("msg-%d", i)
		}
	}
	for i, be := range backends {
		b.Run(be.name, func(b *testing.B) {
			skipBackend(b, i)
			c := signal.NewCatalog(be.new(b), signal.Options{})
			defer c.Close()
			ctx := context.Background()
			if ids == "same" {
				// The first send of each event, so the loop has only
				// retries.
				for _, ev := range events {
					ev.Time = t0
					if _, err := c.Observe(ctx, ev); err != nil {
						b.Fatal(err)
					}
				}
			}
			done := measureRedis(b, i)
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				ev := events[n%accounts]
				switch ids {
				case "new":
					ev.ID = "msg-" + strconv.Itoa(n)
					ev.Time = t0.Add(time.Duration(n) * time.Millisecond)
				case "same":
					ev.Time = t0
				default:
					ev.Time = t0.Add(time.Duration(n) * time.Millisecond)
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

// BenchmarkObserveRecipientMemory measures what the recipient memory adds to
// a send: the same send with the memory on and off, to 3, 100 and
// event.MaxRecipients recipients, half of them in a memory of 2,000
// addresses that hard-bounced. A send checks at most
// signal.MaxCheckedRecipients of them, so the store work stops growing past
// that; hashing every address to pick them does not.
func BenchmarkObserveRecipientMemory(b *testing.B) {
	const remembered = 2000
	for _, recipients := range []int{3, 100, event.MaxRecipients} {
		to := make([]string, recipients)
		for i := range to {
			// Even addresses bounced; odd ones did not.
			to[i] = fmt.Sprintf("r%d@list.example", i*remembered/recipients/2*2+i%2)
		}
		for _, mode := range []string{"off", "on"} {
			opts := signal.Options{}
			if mode == "off" {
				opts.RecipientMemory = -1
			}
			for i, be := range backends {
				b.Run(fmt.Sprintf("to=%d/memory=%s/%s", recipients, mode, be.name), func(b *testing.B) {
					skipBackend(b, i)
					c := signal.NewCatalog(be.new(b), opts)
					defer c.Close()
					ctx := context.Background()
					for j := 0; j < remembered; j += 2 {
						ev := event.Event{
							Type:      event.Feedback,
							Time:      t0,
							AccountID: "old-sender",
							Feedback:  &event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent", Recipient: fmt.Sprintf("r%d@list.example", j)},
						}
						if _, err := c.Observe(ctx, ev); err != nil {
							b.Fatal(err)
						}
					}
					done := measureRedis(b, i)
					b.ReportAllocs()
					n := 0
					for b.Loop() {
						ev := event.Event{
							Type:      event.Send,
							AccountID: fmt.Sprintf("acct-%d", n%1000),
							APIKeyID:  fmt.Sprintf("key-%d", n%1000),
							IP:        fmt.Sprintf("203.0.%d.%d", n%1000/256, n%256),
							From:      "news@sender.example",
							Time:      t0.Add(time.Hour + time.Duration(n)*time.Millisecond),
							To:        to,
						}
						set, err := c.Observe(ctx, ev)
						if err != nil {
							b.Fatal(err)
						}
						if mode == "on" && set.Event["suppressed_recipients"].(int64) == 0 {
							b.Fatal("no recipient found in the memory")
						}
						n++
					}
					done()
				})
			}
		}
	}
}

// BenchmarkObserveEntities is BenchmarkObserve with 0, 1 and 4 entities
// declared, each named by every send: the difference per entity is what one
// costs a send. Values come from a pool of 200 per entity, so the distinct
// sets hold several accounts each, as for a template many accounts share.
func BenchmarkObserveEntities(b *testing.B) {
	const accounts = 1000
	for _, n := range []int{0, 1, 4} {
		var ents []signal.Entity
		for j := range n {
			ents = append(ents, signal.Entity{Name: fmt.Sprintf("e%d", j), Attribute: fmt.Sprintf("attr_%d", j)})
		}
		events := make([]event.Event, accounts)
		for i := range events {
			events[i] = event.Event{
				Type:       event.Send,
				AccountID:  fmt.Sprintf("acct-%d", i),
				APIKeyID:   fmt.Sprintf("key-%d", i),
				IP:         fmt.Sprintf("203.0.%d.%d", i/256, i%256),
				From:       fmt.Sprintf("news@sender-%d.example", i%50),
				To:         []string{"a@gmail.example", "b@outlook.example", "c@gmail.example"},
				Subject:    "Your weekly digest",
				Attributes: map[string]string{},
			}
			for j := range n {
				events[i].Attributes[fmt.Sprintf("attr_%d", j)] = fmt.Sprintf("value-%d-%d", j, i%200)
			}
		}
		for i, be := range backends {
			b.Run(fmt.Sprintf("entities=%d/%s", n, be.name), func(b *testing.B) {
				skipBackend(b, i)
				c := signal.NewCatalog(be.new(b), signal.Options{Entities: ents})
				defer c.Close()
				ctx := context.Background()
				done := measureRedis(b, i)
				b.ReportAllocs()
				k := 0
				for b.Loop() {
					ev := events[k%accounts]
					ev.Time = t0.Add(time.Duration(k) * time.Millisecond)
					set, err := c.Observe(ctx, ev)
					if err != nil {
						b.Fatal(err)
					}
					if len(set.Entity) != n {
						b.Fatalf("%d entities in the set, want %d", len(set.Entity), n)
					}
					k++
				}
				done()
			})
		}
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
