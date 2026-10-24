package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestMemory(t *testing.T, wall time.Time) (*Memory, *fakeClock) {
	t.Helper()
	m := NewMemory()
	clock := &fakeClock{t: wall}
	m.now = clock.Now
	return m, clock
}

// entries counts what the store holds, across shards.
func (m *Memory) entries() int {
	n := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		n += len(s.counters) + len(s.distincts) + len(s.seen) + len(s.first) + len(s.values) + len(s.ids)
		s.mu.Unlock()
	}
	return n
}

// TestMemoryForgetsDedupeIDs checks that ids go by the wall clock, and by
// event time once the newest event time stored is their ttl past them or
// past the newest event time when they were written, whichever is later.
func TestMemoryForgetsDedupeIDs(t *testing.T) {
	// The wall clock stays put, as in a replay of old events.
	m, _ := newTestMemory(t, t0.Add(365*24*time.Hour))
	send := func(id string, at time.Time) bool {
		t.Helper()
		var rep *BoolResult
		run(t, m, func(b *Batch) {
			rep = b.Dedupe(id, at, 10*time.Minute)
			b.Incr("k", time.Hour, at, 1)
		})
		return rep.Val()
	}
	send("now", t0.Add(time.Hour))
	// An event an hour older than the newest stored: its id lasts as long
	// as one written for the newest, so its retry is caught too.
	send("late", t0)
	m.sweepAll()
	if !send("late", t0) || !send("now", t0.Add(time.Hour)) {
		t.Fatal("an id was forgotten before its ttl")
	}
	run(t, m, func(b *Batch) { b.Incr("k", time.Hour, t0.Add(time.Hour+10*time.Minute), 1) })
	m.sweepAll()
	if got := m.entries(); got != 1 {
		t.Errorf("entries = %d, want only the counter once event time is the ttl past the ids", got)
	}
	if send("late", t0) {
		t.Error("the id was still remembered after event time moved its ttl past it")
	}
}

// TestMemoryKeepsLateFirstSeenForItsTTL writes a first-seen record late, an
// hour behind the newest event time stored, with the wall clock moving with
// event time as it does in production. The record lasts its time to live on
// the wall clock, as in Redis, instead of being forgotten by event time at
// the next sweep; FuzzStoresAgree found the difference.
func TestMemoryKeepsLateFirstSeenForItsTTL(t *testing.T) {
	m, clock := newTestMemory(t, t0.Add(2*time.Hour))
	run(t, m, func(b *Batch) { b.Incr("newest", time.Hour, t0.Add(2*time.Hour), 1) })
	firstSeenAt(t, m, "f", t0.Add(time.Hour), 30*time.Minute)
	m.sweepAll()
	clock.Advance(29 * time.Minute)
	run(t, m, func(b *Batch) { b.Incr("newest", time.Hour, t0.Add(2*time.Hour+29*time.Minute), 1) })
	m.sweepAll()
	if got := firstSeenAt(t, m, "f", t0.Add(2*time.Hour+29*time.Minute), 30*time.Minute); !got.Equal(t0.Add(time.Hour)) {
		t.Errorf("FirstSeen = %v, want the late write's %v: its ttl has not run out", got.Sub(t0), time.Hour)
	}
	// Event time still forgets it once the newest event time is the ttl
	// past the last write's: here before the wall clock does.
	clock.Advance(29 * time.Minute)
	run(t, m, func(b *Batch) { b.Incr("newest", time.Hour, t0.Add(3*time.Hour), 1) })
	m.sweepAll()
	if got := m.entries(); got != 1 {
		t.Errorf("entries = %d, want only the counter once event time is the ttl past the record", got)
	}
}

func (m *Memory) sweepAll() {
	now := m.now().UnixNano()
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		s.sweep(now, m.horizon.Load())
		s.mu.Unlock()
	}
}

// fillKeys writes one entry of each kind for n keys at time at.
func fillKeys(t *testing.T, m *Memory, n int, at time.Time, ttl time.Duration) {
	t.Helper()
	run(t, m, func(b *Batch) {
		for i := range n {
			k := fmt.Sprintf("key-%d", i)
			b.Incr(k, time.Hour, at, 1)
			b.AddDistinct(k, "m", time.Hour, at)
			b.MarkSeen(k, "m", at, ttl)
			b.FirstSeen(k, at, ttl)
			b.Set(k, "v", ttl)
		}
	})
}

func TestMemoryConcurrentUse(t *testing.T) {
	m, _ := newTestMemory(t, t0)
	const workers, batches = 8, 300
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range batches {
				var b Batch
				at := t0.Add(time.Duration(i) * time.Millisecond)
				b.Incr("shared", time.Hour, at, 1)
				b.AddDistinct("shared", fmt.Sprint(w), time.Hour, at)
				b.FirstSeen("shared", at, time.Hour)
				b.Count("shared", time.Hour, at)
				if err := m.Do(context.Background(), &b); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	at := t0.Add(time.Second)
	if got := count(t, m, "shared", time.Hour, at); got != workers*batches {
		t.Errorf("Count = %d, want %d", got, workers*batches)
	}
	if got := distinct(t, m, "shared", time.Hour, at); got != workers {
		t.Errorf("Distinct = %d, want %d", got, workers)
	}
}

func TestMemorySweepsExpiredEntries(t *testing.T) {
	m, clock := newTestMemory(t, t0)
	fillKeys(t, m, 500, t0, 2*time.Hour)
	run(t, m, func(b *Batch) { b.Set("forever", "v", 0) })
	if got := m.entries(); got != 5*500+1 {
		t.Fatalf("entries = %d, want %d", got, 5*500+1)
	}
	clock.Advance(3 * time.Hour)
	// Each Do checks one shard, so a round of empty batches sweeps them all.
	for range shardCount {
		run(t, m, func(*Batch) {})
	}
	if got := m.entries(); got != 1 {
		t.Errorf("entries after the TTLs = %d, want 1 (the value without TTL)", got)
	}
}

func TestMemoryForgetsWhatTheNewestEventTimeOutdates(t *testing.T) {
	// The wall clock stays put, as in a replay of old events.
	m, _ := newTestMemory(t, t0.Add(365*24*time.Hour))
	fillKeys(t, m, 100, t0, time.Hour)
	// Each Do checks one shard: event time moving on makes them all due.
	for range shardCount {
		run(t, m, func(b *Batch) { b.Incr("later", time.Hour, t0.Add(3*time.Hour), 1) })
	}
	// The values remain: Set records no event time, so only the wall clock
	// expires them.
	if got := m.entries(); got != 100+1 {
		t.Errorf("entries = %d, want %d", got, 100+1)
	}
}

func TestMemoryIgnoresFutureEventsForTheHorizon(t *testing.T) {
	m, _ := newTestMemory(t, t0)
	fillKeys(t, m, 100, t0, time.Hour)
	run(t, m, func(b *Batch) { b.Incr("bogus", time.Hour, t0.Add(10*365*24*time.Hour), 1) })
	m.sweepAll()
	if got := m.entries(); got != 5*100+1 {
		t.Errorf("entries = %d, want %d: a future event wiped the store", got, 5*100+1)
	}
	if got := count(t, m, "key-0", time.Hour, t0); got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
}

func TestMemoryKeepsAtMostBucketsPerWindow(t *testing.T) {
	m, _ := newTestMemory(t, t0)
	for i := range 10 * Buckets {
		run(t, m, func(b *Batch) { b.Incr("k", time.Hour, t0.Add(time.Duration(i)*time.Minute), 1) })
	}
	for i := range m.shards {
		if c := m.shards[i].counters[series{"k", time.Hour}]; c != nil && len(c.list) > Buckets {
			t.Errorf("counter holds %d buckets, want at most %d", len(c.list), Buckets)
		}
	}
	if got := count(t, m, "k", time.Hour, t0.Add((10*Buckets-1)*time.Minute)); got != Buckets {
		t.Errorf("Count = %d, want %d", got, Buckets)
	}
}

func TestMemoryOutOfOrderWrites(t *testing.T) {
	m, _ := newTestMemory(t, t0)
	run(t, m, func(b *Batch) {
		b.Incr("k", time.Hour, t0.Add(2*time.Hour), 1)
		b.Incr("k", time.Hour, t0.Add(90*time.Minute), 1)
		b.Incr("k", time.Hour, t0.Add(90*time.Minute), 1)
		b.Incr("k", time.Hour, t0.Add(100*time.Minute), 1)
		// More than a window older than the newest bucket: not kept.
		b.Incr("k", time.Hour, t0, 1)
	})
	if got := count(t, m, "k", time.Hour, t0.Add(2*time.Hour)); got != 4 {
		t.Errorf("Count = %d, want 4", got)
	}
	if got := count(t, m, "k", time.Hour, t0.Add(95*time.Minute)); got != 2 {
		t.Errorf("Count in the past = %d, want 2", got)
	}
	if got := count(t, m, "k", time.Hour, t0); got != 0 {
		t.Errorf("Count of the dropped write = %d, want 0", got)
	}
}

func TestMemorySeenSetStaysBounded(t *testing.T) {
	m, _ := newTestMemory(t, t0)
	for i := range 1000 {
		at := t0.Add(time.Duration(i) * time.Minute)
		run(t, m, func(b *Batch) { b.MarkSeen("k", fmt.Sprint(i), at, time.Hour) })
	}
	for i := range m.shards {
		if e := m.shards[i].seen["k"]; e != nil && len(e.last) > 61 {
			t.Errorf("seen set holds %d members, want at most 61", len(e.last))
		}
	}
}

func TestMemoryClose(t *testing.T) {
	m, _ := newTestMemory(t, t0)
	fillKeys(t, m, 10, t0, time.Hour)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if got := m.entries(); got != 0 {
		t.Errorf("entries after Close = %d, want 0", got)
	}
	var b Batch
	b.Incr("k", time.Hour, t0, 1)
	if err := m.Do(context.Background(), &b); !errors.Is(err, ErrClosed) {
		t.Errorf("Do after Close = %v, want ErrClosed", err)
	}
}
