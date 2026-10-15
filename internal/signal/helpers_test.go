package signal_test

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

// t0 is aligned to the buckets of every window, the widest being the 7 day
// window's 2h48m, so windows here behave exactly as their names say.
var t0 = time.Unix(1_767_225_600-1_767_225_600%10_080, 0).UTC()

const (
	day  = 24 * time.Hour
	week = 7 * day
)

// backends are the stores the catalog is tested on. redis-server is a real
// Redis server, used when CATRACA_TEST_REDIS_URL is set, and
// redis-cluster-server a real Redis Cluster, used when
// CATRACA_TEST_REDIS_CLUSTER is set; each test writes under its own prefix
// and deletes its keys when it ends.
var backends = []struct {
	name string
	new  func(tb testing.TB) store.Store
	// skip, when set, says why the backend cannot run here, or returns "".
	skip func() string
}{
	{name: "memory", new: func(testing.TB) store.Store { return store.NewMemory() }},
	{name: "redis", new: func(tb testing.TB) store.Store {
		mr := storetest.Miniredis(tb)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		tb.Cleanup(func() { client.Close() })
		return store.NewRedis(client, store.RedisOptions{})
	}},
	{name: "redis-server", skip: storetest.RedisServerSkip, new: func(tb testing.TB) store.Store {
		client, prefix := storetest.RedisServer(tb)
		return store.NewRedis(client, store.RedisOptions{Prefix: prefix})
	}},
	{name: "redis-cluster-server", skip: storetest.RedisClusterSkip, new: func(tb testing.TB) store.Store {
		client, prefix := storetest.RedisCluster(tb)
		return store.NewRedis(client, store.RedisOptions{Prefix: prefix})
	}},
}

// skipBackend skips tb when backend i cannot run here.
func skipBackend(tb testing.TB, i int) {
	tb.Helper()
	if skip := backends[i].skip; skip != nil {
		if why := skip(); why != "" {
			tb.Skip(why)
		}
	}
}

// eachBackend runs test once per store backend, with a fresh catalog.
func eachBackend(t *testing.T, test func(t *testing.T, c signal.Catalog)) {
	t.Helper()
	for i, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			skipBackend(t, i)
			c := signal.NewCatalog(be.new(t), signal.Options{})
			t.Cleanup(func() { c.Close() })
			test(t, c)
		})
	}
}

func observe(t *testing.T, c signal.Catalog, ev event.Event) signal.Set {
	t.Helper()
	set, err := c.Observe(context.Background(), ev)
	if err != nil {
		t.Fatalf("Observe(%s at %v): %v", ev.Type, ev.Time.Sub(t0), err)
	}
	return set
}

// send returns a send event at t0+offset from acct-1 with key-1 and an IP,
// changed by the options.
func send(offset time.Duration, opts ...func(*event.Event)) event.Event {
	ev := event.Event{
		Type:      event.Send,
		Time:      t0.Add(offset),
		AccountID: "acct-1",
		APIKeyID:  "key-1",
		IP:        "203.0.113.7",
		From:      "news@sender.example",
		To:        []string{"someone@inbox.example"},
		Subject:   "Hello",
	}
	for _, o := range opts {
		o(&ev)
	}
	return ev
}

func feedback(offset time.Duration, kind event.FeedbackKind, bounceType string, opts ...func(*event.Event)) event.Event {
	ev := event.Event{
		Type:      event.Feedback,
		Time:      t0.Add(offset),
		AccountID: "acct-1",
		From:      "news@sender.example",
		Feedback:  &event.FeedbackInfo{Kind: kind, BounceType: bounceType},
	}
	for _, o := range opts {
		o(&ev)
	}
	return ev
}

func accountEvent(offset time.Duration, action string, opts ...func(*event.Event)) event.Event {
	ev := event.Event{
		Type:      event.Account,
		Time:      t0.Add(offset),
		AccountID: "acct-1",
		Account:   &event.AccountInfo{Action: action},
	}
	for _, o := range opts {
		o(&ev)
	}
	return ev
}

func withAccount(id string) func(*event.Event) { return func(e *event.Event) { e.AccountID = id } }
func withKey(id string) func(*event.Event)     { return func(e *event.Event) { e.APIKeyID = id } }
func withIP(ip string) func(*event.Event)      { return func(e *event.Event) { e.IP = ip } }
func withFrom(f string) func(*event.Event)     { return func(e *event.Event) { e.From = f } }
func withTo(to ...string) func(*event.Event)   { return func(e *event.Event) { e.To = to } }

func withCreatedAt(t time.Time) func(*event.Event) {
	return func(e *event.Event) {
		if e.Account == nil {
			e.Account = &event.AccountInfo{}
		}
		e.Account.CreatedAt = &t
	}
}

// want checks that m holds the expected values, compared exactly.
func want(t *testing.T, label string, m map[string]any, expected map[string]any) {
	t.Helper()
	for name, w := range expected {
		got, ok := m[name]
		if !ok {
			t.Errorf("%s: %s is absent", label, name)
			continue
		}
		if got != w {
			t.Errorf("%s: %s = %v (%T), want %v (%T)", label, name, got, got, w, w)
		}
	}
}
