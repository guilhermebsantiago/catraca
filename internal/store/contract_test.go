package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

// backend is a store under test and a way to move the wall clock it expires
// entries by.
type backend struct {
	Store
	advance func(time.Duration)
}

// backends lists the constructors the contract suite runs against.
var backends = []struct {
	name string
	new  func(t *testing.T) backend
	// skip, when set, says why the backend cannot run here, or returns "".
	skip func() string
}{
	{name: "memory", new: newMemoryBackend},
	{name: "redis", new: newRedisBackend},
	{name: "redis-cluster", new: newRedisClusterBackend},
	{name: "redis-server", new: newRedisServerBackend, skip: redisServerSkip},
	{name: "redis-cluster-server", new: newRedisClusterServerBackend, skip: redisClusterSkip},
}

func newMemoryBackend(t *testing.T) backend {
	m := NewMemory()
	clock := &fakeClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	m.now = clock.Now
	t.Cleanup(func() { m.Close() })
	return backend{Store: m, advance: clock.Advance}
}

func newRedisBackend(t *testing.T) backend {
	mr := storetest.Miniredis(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, ReadTimeout: storetest.MiniredisReadTimeout})
	t.Cleanup(func() { client.Close() })
	return backend{Store: NewRedis(client, RedisOptions{Prefix: "test:"}), advance: mr.FastForward}
}

// newRedisClusterBackend runs the Redis store through a Cluster client, which
// splits each batch into one script call per hash slot. miniredis serves
// every slot from one node, so this checks the split, not slot ownership.
func newRedisClusterBackend(t *testing.T) backend {
	mr := storetest.Miniredis(t)
	client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{mr.Addr()}, MaxRetries: -1, ReadTimeout: storetest.MiniredisReadTimeout})
	t.Cleanup(func() { client.Close() })
	return backend{Store: NewRedis(client, RedisOptions{Prefix: "test:"}), advance: mr.FastForward}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// t0 is aligned to the buckets of every window used below, the widest being
// the 7 day window's 2h48m.
var t0 = time.Unix(1_767_225_600-1_767_225_600%10_080, 0).UTC()

const week = 7 * 24 * time.Hour

func run(t *testing.T, s Store, build func(b *Batch)) {
	t.Helper()
	var b Batch
	build(&b)
	if err := s.Do(context.Background(), &b); err != nil {
		t.Fatalf("Do: %v", err)
	}
}

func count(t *testing.T, s Store, key string, w time.Duration, at time.Time) int64 {
	t.Helper()
	var r *IntResult
	run(t, s, func(b *Batch) { r = b.Count(key, w, at) })
	return r.Val()
}

func distinct(t *testing.T, s Store, key string, w time.Duration, at time.Time) int64 {
	t.Helper()
	var r *IntResult
	run(t, s, func(b *Batch) { r = b.Distinct(key, w, at) })
	return r.Val()
}

func seenWithin(t *testing.T, s Store, key, member string, lookback time.Duration, at time.Time) bool {
	t.Helper()
	var r *BoolResult
	run(t, s, func(b *Batch) { r = b.SeenWithin(key, member, lookback, at) })
	return r.Val()
}

func firstSeenAt(t *testing.T, s Store, key string, at time.Time, ttl time.Duration) time.Time {
	t.Helper()
	var r *TimeResult
	run(t, s, func(b *Batch) { r = b.FirstSeen(key, at, ttl) })
	return r.Val()
}

func get(t *testing.T, s Store, key string) (string, bool) {
	t.Helper()
	var r *StringResult
	run(t, s, func(b *Batch) { r = b.Get(key) })
	return r.Val(), r.Found()
}

func TestContract(t *testing.T) {
	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			if be.skip != nil {
				if why := be.skip(); why != "" {
					t.Skip(why)
				}
			}
			for _, tc := range contractCases {
				t.Run(tc.name, func(t *testing.T) { tc.run(t, be.new(t)) })
			}
		})
	}
}

// boundaryCases are counts of one event at t0+offset for windows w, read at
// t0+offset+age.
var boundaryCases = []struct {
	name   string
	w      time.Duration
	offset time.Duration
	age    time.Duration
	want   int64
}{
	{"same instant", time.Hour, 0, 0, 1},
	{"just before the event", time.Hour, 0, -time.Millisecond, 0},
	{"aligned, last ms of window", time.Hour, 0, time.Hour - time.Millisecond, 1},
	{"aligned, window later", time.Hour, 0, time.Hour, 0},
	{"aligned, two windows later", time.Hour, 0, 2 * time.Hour, 0},
	{"mid bucket, less than window minus a bucket", time.Hour, 30 * time.Second, time.Hour - time.Minute - time.Millisecond, 1},
	{"mid bucket, until its bucket leaves", time.Hour, 30 * time.Second, time.Hour - 30*time.Second - time.Millisecond, 1},
	{"mid bucket, bucket left", time.Hour, 30 * time.Second, time.Hour - 30*time.Second, 0},
	{"1m window, 59s later", time.Minute, 0, 59 * time.Second, 1},
	{"1m window, 60s later", time.Minute, 0, time.Minute, 0},
	{"24h window, 23h later", 24 * time.Hour, 0, 23 * time.Hour, 1},
	{"24h window, 24h later", 24 * time.Hour, 0, 24 * time.Hour, 0},
	{"7d window, 6d later", week, 0, 6 * 24 * time.Hour, 1},
	{"7d window, 7d later", week, 0, week, 0},
}

var contractCases = []struct {
	name string
	run  func(t *testing.T, s backend)
}{
	{"empty batch", func(t *testing.T, s backend) {
		run(t, s, func(*Batch) {})
	}},

	{"count of a missing key is zero", func(t *testing.T, s backend) {
		if got := count(t, s, "nothing", time.Hour, t0); got != 0 {
			t.Errorf("Count = %d, want 0", got)
		}
	}},

	{"count sums increments across buckets", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) {
			b.Incr("k", time.Hour, t0, 1)
			b.Incr("k", time.Hour, t0.Add(10*time.Minute), 2)
			b.Incr("k", time.Hour, t0.Add(10*time.Minute), 3)
			b.Incr("k", time.Hour, t0.Add(59*time.Minute), -1)
		})
		if got := count(t, s, "k", time.Hour, t0.Add(59*time.Minute)); got != 5 {
			t.Errorf("Count = %d, want 5", got)
		}
		if got := count(t, s, "k", time.Hour, t0.Add(65*time.Minute)); got != 4 {
			t.Errorf("Count after the first bucket left = %d, want 4", got)
		}
	}},

	{"count window boundaries", func(t *testing.T, s backend) {
		for i, tc := range boundaryCases {
			key := fmt.Sprintf("k%d", i)
			at := t0.Add(tc.offset)
			run(t, s, func(b *Batch) { b.Incr(key, tc.w, at, 1) })
			if got := count(t, s, key, tc.w, at.Add(tc.age)); got != tc.want {
				t.Errorf("%s: Count = %d, want %d", tc.name, got, tc.want)
			}
		}
	}},

	{"keys and windows are independent", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) {
			b.Incr("a", time.Minute, t0, 1)
			b.Incr("a", time.Hour, t0, 2)
			b.Incr("b", time.Minute, t0, 4)
		})
		for _, c := range []struct {
			key  string
			w    time.Duration
			want int64
		}{{"a", time.Minute, 1}, {"a", time.Hour, 2}, {"b", time.Minute, 4}, {"b", time.Hour, 0}} {
			if got := count(t, s, c.key, c.w, t0); got != c.want {
				t.Errorf("Count(%s, %v) = %d, want %d", c.key, c.w, got, c.want)
			}
		}
	}},

	{"reads see earlier writes in the batch", func(t *testing.T, s backend) {
		var before, after, dBefore, dAfter *IntResult
		run(t, s, func(b *Batch) {
			before = b.Count("k", time.Hour, t0)
			b.Incr("k", time.Hour, t0, 1)
			after = b.Count("k", time.Hour, t0)
			dBefore = b.Distinct("d", time.Hour, t0)
			b.AddDistinct("d", "x", time.Hour, t0)
			dAfter = b.Distinct("d", time.Hour, t0)
		})
		if before.Val() != 0 || after.Val() != 1 {
			t.Errorf("Count before/after Incr = %d/%d, want 0/1", before.Val(), after.Val())
		}
		if dBefore.Val() != 0 || dAfter.Val() != 1 {
			t.Errorf("Distinct before/after AddDistinct = %d/%d, want 0/1", dBefore.Val(), dAfter.Val())
		}
	}},

	{"counters expire by the wall clock", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) { b.Incr("k", time.Hour, t0, 1) })
		s.advance(time.Hour)
		if got := count(t, s, "k", time.Hour, t0); got != 1 {
			t.Fatalf("Count before the TTL = %d, want 1", got)
		}
		s.advance(time.Minute)
		if got := count(t, s, "k", time.Hour, t0); got != 0 {
			t.Errorf("Count after window plus a bucket = %d, want 0", got)
		}
	}},

	{"writes refresh a bucket's expiry", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) { b.Incr("k", time.Hour, t0, 1) })
		s.advance(time.Hour)
		run(t, s, func(b *Batch) { b.Incr("k", time.Hour, t0.Add(time.Second), 1) })
		s.advance(time.Hour)
		if got := count(t, s, "k", time.Hour, t0.Add(time.Second)); got != 2 {
			t.Errorf("Count = %d, want 2", got)
		}
	}},

	{"distinct counts each member once", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) {
			b.AddDistinct("d", "a", time.Hour, t0)
			b.AddDistinct("d", "a", time.Hour, t0.Add(10*time.Minute))
			b.AddDistinct("d", "b", time.Hour, t0.Add(20*time.Minute))
			b.AddDistinct("d", "a", time.Hour, t0.Add(20*time.Minute))
			b.AddDistinct("other", "c", time.Hour, t0)
			b.AddDistinct("d", "c", 24*time.Hour, t0)
		})
		if got := distinct(t, s, "d", time.Hour, t0.Add(20*time.Minute)); got != 2 {
			t.Errorf("Distinct = %d, want 2", got)
		}
		if got := distinct(t, s, "d", time.Hour, t0.Add(65*time.Minute)); got != 2 {
			t.Errorf("Distinct after the first bucket left = %d, want 2", got)
		}
		if got := distinct(t, s, "d", time.Hour, t0.Add(80*time.Minute)); got != 0 {
			t.Errorf("Distinct after every bucket left = %d, want 0", got)
		}
		if got := distinct(t, s, "missing", time.Hour, t0); got != 0 {
			t.Errorf("Distinct of a missing key = %d, want 0", got)
		}
	}},

	{"distinct window boundaries", func(t *testing.T, s backend) {
		for i, tc := range boundaryCases {
			key := fmt.Sprintf("d%d", i)
			at := t0.Add(tc.offset)
			run(t, s, func(b *Batch) { b.AddDistinct(key, "m", tc.w, at) })
			if got := distinct(t, s, key, tc.w, at.Add(tc.age)); got != tc.want {
				t.Errorf("%s: Distinct = %d, want %d", tc.name, got, tc.want)
			}
		}
	}},

	{"distinct estimates large sets closely", func(t *testing.T, s backend) {
		const n = 2000
		run(t, s, func(b *Batch) {
			for i := range n {
				at := t0.Add(time.Duration(i) * time.Hour / n)
				b.AddDistinct("big", fmt.Sprintf("member-%d", i), 24*time.Hour, at)
				b.AddDistinct("big", fmt.Sprintf("member-%d", i/2), 24*time.Hour, at)
			}
		})
		got := distinct(t, s, "big", 24*time.Hour, t0.Add(time.Hour))
		if got < n*98/100 || got > n*102/100 {
			t.Errorf("Distinct = %d, want %d within 2%%", got, n)
		}
	}},

	{"distinct sets expire by the wall clock", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) { b.AddDistinct("d", "a", time.Minute, t0) })
		s.advance(time.Minute)
		if got := distinct(t, s, "d", time.Minute, t0); got != 1 {
			t.Fatalf("Distinct before the TTL = %d, want 1", got)
		}
		s.advance(time.Second)
		if got := distinct(t, s, "d", time.Minute, t0); got != 0 {
			t.Errorf("Distinct after the TTL = %d, want 0", got)
		}
	}},

	{"first seen keeps the earliest time", func(t *testing.T, s backend) {
		steps := []struct {
			at, want time.Time
		}{
			{t0.Add(time.Hour), t0.Add(time.Hour)},
			{t0.Add(2 * time.Hour), t0.Add(time.Hour)},
			{t0, t0},
			{t0.Add(time.Hour), t0},
		}
		for i, st := range steps {
			if got := firstSeenAt(t, s, "f", st.at, week); !got.Equal(st.want) {
				t.Errorf("step %d: FirstSeen = %v, want %v", i, got, st.want)
			}
		}
		if got := firstSeenAt(t, s, "g", t0.Add(1500*time.Microsecond), week); !got.Equal(t0.Add(time.Millisecond)) {
			t.Errorf("FirstSeen = %v, want millisecond precision %v", got, t0.Add(time.Millisecond))
		}
	}},

	{"first seen expires after its ttl since the last write", func(t *testing.T, s backend) {
		firstSeenAt(t, s, "f", t0, time.Hour)
		s.advance(30 * time.Minute)
		firstSeenAt(t, s, "f", t0.Add(time.Hour), time.Hour)
		s.advance(45 * time.Minute)
		if got := firstSeenAt(t, s, "f", t0.Add(2*time.Hour), time.Hour); !got.Equal(t0) {
			t.Errorf("FirstSeen after a refresh = %v, want %v", got, t0)
		}
		s.advance(time.Hour)
		if got := firstSeenAt(t, s, "f", t0.Add(3*time.Hour), time.Hour); !got.Equal(t0.Add(3 * time.Hour)) {
			t.Errorf("FirstSeen after expiry = %v, want %v", got, t0.Add(3*time.Hour))
		}
	}},

	{"first seen with zero ttl never expires", func(t *testing.T, s backend) {
		firstSeenAt(t, s, "f", t0, 0)
		s.advance(10 * 365 * 24 * time.Hour)
		if got := firstSeenAt(t, s, "f", t0.Add(time.Hour), 0); !got.Equal(t0) {
			t.Errorf("FirstSeen = %v, want %v", got, t0)
		}
	}},

	{"set and get", func(t *testing.T, s backend) {
		if v, ok := get(t, s, "v"); ok || v != "" {
			t.Errorf("Get of a missing key = %q, %v; want \"\", false", v, ok)
		}
		var inBatch *StringResult
		run(t, s, func(b *Batch) {
			b.Set("v", "one", 0)
			inBatch = b.Get("v")
			b.Set("v", "two", 0)
			b.Set("short", "x", time.Minute)
		})
		if inBatch.Val() != "one" || !inBatch.Found() {
			t.Errorf("Get in the batch = %q, %v; want \"one\", true", inBatch.Val(), inBatch.Found())
		}
		if v, ok := get(t, s, "v"); !ok || v != "two" {
			t.Errorf("Get = %q, %v; want \"two\", true", v, ok)
		}
		s.advance(time.Minute)
		if _, ok := get(t, s, "short"); ok {
			t.Error("Get found a value after its ttl")
		}
		if _, ok := get(t, s, "v"); !ok {
			t.Error("Get lost a value stored without ttl")
		}
	}},

	{"seen within", func(t *testing.T, s backend) {
		const lookback = 30 * 24 * time.Hour
		if seenWithin(t, s, "s", "1.2.3.4", lookback, t0) {
			t.Error("SeenWithin before any mark = true")
		}
		run(t, s, func(b *Batch) { b.MarkSeen("s", "1.2.3.4", t0, lookback) })
		cases := []struct {
			key, member string
			at          time.Time
			want        bool
		}{
			{"s", "1.2.3.4", t0, true},
			{"s", "1.2.3.4", t0.Add(lookback - time.Millisecond), true},
			{"s", "1.2.3.4", t0.Add(lookback), false},
			{"s", "1.2.3.4", t0.Add(-time.Hour), true},
			{"s", "5.6.7.8", t0, false},
			{"other", "1.2.3.4", t0, false},
		}
		for _, c := range cases {
			if got := seenWithin(t, s, c.key, c.member, lookback, c.at); got != c.want {
				t.Errorf("SeenWithin(%s, %s, %v) = %v, want %v", c.key, c.member, c.at.Sub(t0), got, c.want)
			}
		}
		if !seenWithin(t, s, "s", "1.2.3.4", time.Hour, t0.Add(59*time.Minute)) {
			t.Error("SeenWithin with a shorter lookback = false")
		}
		if seenWithin(t, s, "s", "1.2.3.4", time.Hour, t0.Add(time.Hour)) {
			t.Error("SeenWithin past a shorter lookback = true")
		}
	}},

	{"mark seen keeps the latest time", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) {
			b.MarkSeen("s", "m", t0.Add(10*time.Hour), 24*time.Hour)
			b.MarkSeen("s", "m", t0, 24*time.Hour)
		})
		if !seenWithin(t, s, "s", "m", 24*time.Hour, t0.Add(33*time.Hour)) {
			t.Error("an earlier mark moved the last-seen time back")
		}
	}},

	{"mark seen forgets members older than the retention", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) {
			b.MarkSeen("s", "old", t0, 24*time.Hour)
			b.MarkSeen("s", "new", t0.Add(25*time.Hour), 24*time.Hour)
		})
		if seenWithin(t, s, "s", "old", 24*time.Hour, t0.Add(time.Hour)) {
			t.Error("a member older than the retention was kept")
		}
	}},

	{"seen within reads marks queued before it", func(t *testing.T, s backend) {
		var before, after *BoolResult
		run(t, s, func(b *Batch) {
			before = b.SeenWithin("s", "m", time.Hour, t0)
			b.MarkSeen("s", "m", t0, time.Hour)
			after = b.SeenWithin("s", "m", time.Hour, t0)
		})
		if before.Val() || !after.Val() {
			t.Errorf("SeenWithin before/after MarkSeen = %v/%v, want false/true", before.Val(), after.Val())
		}
	}},

	{"seen members expire by the wall clock", func(t *testing.T, s backend) {
		run(t, s, func(b *Batch) { b.MarkSeen("s", "m", t0, 24*time.Hour) })
		s.advance(23 * time.Hour)
		if !seenWithin(t, s, "s", "m", 24*time.Hour, t0.Add(time.Hour)) {
			t.Fatal("SeenWithin before the retention = false")
		}
		s.advance(time.Hour)
		if seenWithin(t, s, "s", "m", 24*time.Hour, t0.Add(time.Hour)) {
			t.Error("SeenWithin after the retention = true")
		}
	}},

	{"invalid operations fail the batch", func(t *testing.T, s backend) {
		cases := []struct {
			name  string
			build func(b *Batch)
			want  string
		}{
			{"empty key", func(b *Batch) { b.Incr("", time.Hour, t0, 1) }, "empty key"},
			{"zero window", func(b *Batch) { b.Count("k", 0, t0) }, "window"},
			{"short window", func(b *Batch) { b.AddDistinct("k", "m", time.Millisecond, t0) }, "window"},
			{"zero time", func(b *Batch) { b.Distinct("k", time.Hour, time.Time{}) }, "out of range"},
			{"zero lookback", func(b *Batch) { b.SeenWithin("k", "m", 0, t0) }, "lookback"},
			{"zero retention", func(b *Batch) { b.MarkSeen("k", "m", t0, 0) }, "retention"},
			{"negative ttl", func(b *Batch) { b.Set("k", "v", -time.Second) }, "ttl"},
			{"tiny ttl", func(b *Batch) { b.FirstSeen("k", t0, time.Microsecond) }, "ttl"},
			{"empty get key", func(b *Batch) { b.Get("") }, "empty key"},
		}
		for _, c := range cases {
			var b Batch
			b.Incr("valid", time.Hour, t0, 1)
			c.build(&b)
			b.Incr("valid", time.Hour, t0, 1)
			err := s.Do(context.Background(), &b)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: Do error = %v, want one mentioning %q", c.name, err, c.want)
			}
			if err != b.Err() {
				t.Errorf("%s: Do error %v differs from Err %v", c.name, err, b.Err())
			}
		}
		if got := count(t, s, "valid", time.Hour, t0); got != 0 {
			t.Errorf("an invalid batch ran %d increments", got)
		}
	}},

	{"canceled context", func(t *testing.T, s backend) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var b Batch
		b.Incr("k", time.Hour, t0, 1)
		if err := s.Do(ctx, &b); !errors.Is(err, context.Canceled) {
			t.Errorf("Do error = %v, want context.Canceled", err)
		}
	}},
}
