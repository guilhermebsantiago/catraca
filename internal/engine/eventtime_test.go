package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

// The tests in this file guard against what event times far from the clock
// did before the engine bounded them. Windows slide with event time and
// first-seen keeps the earliest time, so a single send dated a month ahead
// emptied an account's counters until the clock caught up, and a single
// event dated 1970 made an account look 56 years old for as long as it kept
// sending. Both blind the rules for new accounts, in the abuser's favor.
// They run on every store backend, through a real catalog.

// storeBackends are the stores the catalog runs on here. redis-server is the
// real Redis at CATRACA_TEST_REDIS_URL, when it is set.
var storeBackends = []struct {
	name string
	new  func(tb testing.TB) store.Store
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
}

// spyCatalog keeps the signals of the last event it observed.
type spyCatalog struct {
	signal.Catalog
	mu   sync.Mutex
	last signal.Set
}

func (c *spyCatalog) Observe(ctx context.Context, ev event.Event) (signal.Set, error) {
	set, err := c.Catalog.Observe(ctx, ev)
	c.mu.Lock()
	c.last = set
	c.mu.Unlock()
	return set, err
}

func (c *spyCatalog) lastSet() signal.Set {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// eachStore runs test once per backend with an engine on the wall clock, as
// the server runs, and the default time bounds.
func eachStore(t *testing.T, test func(t *testing.T, d func(event.Event) error, cat *spyCatalog)) {
	t.Helper()
	rs, err := rules.Parse([]byte(testRuleset))
	if err != nil {
		t.Fatal(err)
	}
	for _, be := range storeBackends {
		t.Run(be.name, func(t *testing.T) {
			if be.skip != nil {
				if why := be.skip(); why != "" {
					t.Skip(why)
				}
			}
			cat := &spyCatalog{Catalog: signal.NewCatalog(be.new(t), signal.Options{})}
			t.Cleanup(func() { cat.Close() })
			// A generous deadline: a slow moment on a busy test machine must
			// not drop the signals these tests read.
			eng, err := New(Options{Catalog: cat, Rules: rules.NewHolder(rs), Deadline: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			decide := func(ev event.Event) error {
				d, err := eng.Decide(context.Background(), ev)
				if err == nil && d.Degraded {
					t.Fatalf("decision for %s at %s is degraded", ev.Type, ev.Time)
				}
				return err
			}
			test(t, decide, cat)
		})
	}
}

func wantCounts(t *testing.T, m map[string]any, want int64, names ...string) {
	t.Helper()
	for _, name := range names {
		if got := m[name]; got != want {
			t.Errorf("%s = %v, want %d", name, got, want)
		}
	}
}

func TestFutureEventTimeDoesNotEmptyCounters(t *testing.T) {
	eachStore(t, func(t *testing.T, decide func(event.Event) error, cat *spyCatalog) {
		send := event.Event{Type: event.Send, AccountID: "acct_skew", APIKeyID: "key_skew", IP: "203.0.113.7"}
		ahead := send
		ahead.Time = time.Now().Add(30 * 24 * time.Hour)
		if err := decide(ahead); err != nil {
			t.Fatal(err)
		}
		for range 5 {
			if err := decide(send); err != nil {
				t.Fatal(err)
			}
		}
		// The send dated ahead counts when it arrived, with the five after it.
		set := cat.lastSet()
		wantCounts(t, set.Account, 6, "sends_1m", "sends_1h", "sends_24h", "sends_7d", "ip_sends_24h")
		wantCounts(t, set.Key, 6, "sends_1m", "sends_1h")
		wantCounts(t, set.IP, 6, "sends_1m", "sends_1h")
	})
}

func TestOldEventTimeDoesNotAgeAccounts(t *testing.T) {
	eachStore(t, func(t *testing.T, decide func(event.Event) error, cat *spyCatalog) {
		old := event.Event{
			Type: event.Account, AccountID: "acct_new", APIKeyID: "key_new",
			Time: time.Unix(0, 0), Account: &event.AccountInfo{Action: "api_key_created"},
		}
		if err := decide(old); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("event dated 1970: error = %v, want ErrInvalidEvent", err)
		}
		if err := decide(event.Event{Type: event.Send, AccountID: "acct_new", APIKeyID: "key_new"}); err != nil {
			t.Fatal(err)
		}
		set := cat.lastSet()
		for name, m := range map[string]map[string]any{"account": set.Account, "key": set.Key} {
			if age, _ := m["age_hours"].(float64); age > 0.1 {
				t.Errorf("%s.age_hours = %v, want a new %s", name, m["age_hours"], name)
			}
		}
	})
}

func TestLateFeedbackStillCounts(t *testing.T) {
	eachStore(t, func(t *testing.T, decide func(event.Event) error, cat *spyCatalog) {
		bounce := event.Event{
			Type: event.Feedback, AccountID: "acct_late", Time: time.Now().Add(-5 * time.Hour),
			Feedback: &event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent"},
		}
		if err := decide(bounce); err != nil {
			t.Fatal(err)
		}
		if err := decide(event.Event{Type: event.Send, AccountID: "acct_late"}); err != nil {
			t.Fatal(err)
		}
		set := cat.lastSet()
		wantCounts(t, set.Account, 1, "bounces_24h", "hard_bounces_24h", "sends_24h")
		if age, _ := set.Account["age_hours"].(float64); age < 4.9 || age > 5.1 {
			t.Errorf("account.age_hours = %v, want about 5: a late event is still the first seen", set.Account["age_hours"])
		}
	})
}
