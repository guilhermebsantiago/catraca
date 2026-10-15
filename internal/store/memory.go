package store

import (
	"cmp"
	"context"
	"hash/maphash"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// shardCount spreads keys over independently locked shards, so
	// concurrent batches for different accounts rarely wait for each other.
	shardCount = 64
	// A shard is scanned for expired entries once a sweepInterval of wall
	// clock time, or once a sweepEventInterval of event time, whichever comes
	// first, so a replay running far faster than real time is swept too.
	sweepInterval      = time.Minute
	sweepEventInterval = time.Hour
	// maxSkew caps how far ahead of the wall clock an event time may move the
	// horizon, so one bogus future timestamp cannot wipe the store.
	maxSkew = time.Minute
)

// Memory is a Store that keeps everything in the process. It is safe for
// concurrent use. It suits a single Catraca instance, tests and replays; use
// Redis to share counters between instances.
//
// Entries expire by the wall clock exactly as they do in Redis. Memory also
// forgets entries that have fallen out of every window relative to the newest
// event time it has stored (never more than a minute ahead of the wall
// clock), so a replay of months of events holds about a week of counters, not
// months. The price is that an event arriving later than its window, after
// newer events, may see less than Redis would show.
type Memory struct {
	now    func() time.Time
	seed   maphash.Seed
	shards [shardCount]memShard
	// horizon is the newest event time stored, in Unix nanoseconds.
	horizon atomic.Int64
	// cursor picks the next shard to check for a sweep.
	cursor atomic.Uint32
	closed atomic.Bool
}

type memShard struct {
	mu        sync.Mutex
	counters  map[series]*buckets[int64]
	distincts map[series]*buckets[members]
	seen      map[string]*seenSet
	first     map[string]*firstSeen
	values    map[string]*value
	// nextSweep is when the shard is next due a sweep by the wall clock, and
	// nextSweepAt by the newest event time, both Unix ns.
	nextSweep   atomic.Int64
	nextSweepAt atomic.Int64
}

// series identifies the buckets of one key and window.
type series struct {
	key    string
	window time.Duration
}

type members = map[string]struct{}

// NewMemory returns an empty in-process store.
func NewMemory() *Memory {
	m := &Memory{now: time.Now, seed: maphash.MakeSeed()}
	m.horizon.Store(math.MinInt64)
	for i := range m.shards {
		m.shards[i].reset()
		m.shards[i].nextSweepAt.Store(math.MinInt64)
	}
	return m
}

func (s *memShard) reset() {
	s.counters = make(map[series]*buckets[int64])
	s.distincts = make(map[series]*buckets[members])
	s.seen = make(map[string]*seenSet)
	s.first = make(map[string]*firstSeen)
	s.values = make(map[string]*value)
}

// Do runs the batch. Each operation is atomic; the batch as a whole is not,
// as with Redis.
func (m *Memory) Do(ctx context.Context, b *Batch) error {
	if err := b.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed.Load() {
		return ErrClosed
	}
	now := m.now().UnixNano()
	newest := int64(math.MinInt64)
	for i := range b.ops {
		o := &b.ops[i]
		s := &m.shards[maphash.String(m.seed, o.key)%shardCount]
		s.mu.Lock()
		s.apply(o, now)
		s.mu.Unlock()
		if o.recordsTime() && o.at > newest {
			newest = o.at
		}
	}
	m.raiseHorizon(newest, now)
	m.sweepNext(now)
	return nil
}

// Close drops everything the store holds. Do returns ErrClosed afterwards.
func (m *Memory) Close() error {
	m.closed.Store(true)
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		s.reset()
		s.mu.Unlock()
	}
	return nil
}

// recordsTime reports whether the operation stores an event time.
func (o *op) recordsTime() bool {
	switch o.kind {
	case opIncr, opAddDistinct, opMarkSeen, opFirstSeen:
		return true
	}
	return false
}

func (m *Memory) raiseHorizon(at, now int64) {
	at = min(at, addSat(now, int64(maxSkew)))
	for {
		h := m.horizon.Load()
		if at <= h || m.horizon.CompareAndSwap(h, at) {
			return
		}
	}
}

// sweepNext looks at one shard per call, in turn, and sweeps it when due. As
// long as traffic flows every shard is swept regularly, and no single call
// pays for scanning the whole store.
func (m *Memory) sweepNext(now int64) {
	s := &m.shards[m.cursor.Add(1)%shardCount]
	horizon := m.horizon.Load()
	next := s.nextSweep.Load()
	if now < next && horizon < s.nextSweepAt.Load() {
		return
	}
	if !s.nextSweep.CompareAndSwap(next, now+int64(sweepInterval)) {
		return
	}
	s.nextSweepAt.Store(addSat(horizon, int64(sweepEventInterval)))
	s.mu.Lock()
	s.sweep(now, horizon)
	s.mu.Unlock()
}

func (s *memShard) apply(o *op, now int64) {
	switch o.kind {
	case opIncr:
		c := s.counters[series{o.key, o.span}]
		if c == nil {
			c = new(buckets[int64])
			s.counters[series{o.key, o.span}] = c
		}
		if n := c.get(floorDiv(o.at, bucketWidth(o.span)), deadline(now, bucketTTL(o.span))); n != nil {
			*n += o.n
		}

	case opCount:
		var sum int64
		if c := s.counters[series{o.key, o.span}]; c != nil {
			for _, b := range c.window(floorDiv(o.at, bucketWidth(o.span))) {
				if b.expires > now {
					sum += b.val
				}
			}
		}
		o.ints.val = sum

	case opAddDistinct:
		d := s.distincts[series{o.key, o.span}]
		if d == nil {
			d = new(buckets[members])
			s.distincts[series{o.key, o.span}] = d
		}
		if set := d.get(floorDiv(o.at, bucketWidth(o.span)), deadline(now, bucketTTL(o.span))); set != nil {
			if *set == nil {
				*set = make(members)
			}
			(*set)[o.member] = struct{}{}
		}

	case opDistinct:
		var n int64
		if d := s.distincts[series{o.key, o.span}]; d != nil {
			n = countDistinct(d.window(floorDiv(o.at, bucketWidth(o.span))), now)
		}
		o.ints.val = n

	case opMarkSeen:
		e := s.seen[o.key]
		if e == nil || e.expires <= now {
			e = &seenSet{last: make(map[string]int64), oldest: math.MaxInt64}
			s.seen[o.key] = e
		}
		e.mark(o.member, unixMilli(o.at), o.span.Milliseconds())
		e.expires = deadline(now, o.span)

	case opSeenWithin:
		seen := false
		if e := s.seen[o.key]; e != nil && e.expires > now {
			last, ok := e.last[o.member]
			seen = ok && unixMilli(o.at)-last < o.span.Milliseconds()
		}
		o.bools.val = seen

	case opFirstSeen:
		ms := unixMilli(o.at)
		e := s.first[o.key]
		if e == nil || e.expires <= now {
			e = &firstSeen{ms: ms, until: math.MinInt64}
			s.first[o.key] = e
		}
		e.ms = min(e.ms, ms)
		e.expires = deadline(now, o.span)
		e.until = max(e.until, deadline(o.at, o.span))
		o.times.ms = e.ms

	case opSet:
		s.values[o.key] = &value{v: o.member, expires: deadline(now, o.span)}

	case opGet:
		if e := s.values[o.key]; e != nil && e.expires > now {
			o.strs.val, o.strs.found = e.v, true
		}
	}
}

// sweep deletes what has expired by the wall clock (now) or can no longer be
// read relative to the newest event time stored (horizon).
func (s *memShard) sweep(now, horizon int64) {
	for k, c := range s.counters {
		if c.prune(now, floorDiv(horizon, bucketWidth(k.window))) {
			delete(s.counters, k)
		}
	}
	for k, d := range s.distincts {
		if d.prune(now, floorDiv(horizon, bucketWidth(k.window))) {
			delete(s.distincts, k)
		}
	}
	horizonMs := unixMilli(horizon)
	for k, e := range s.seen {
		if e.expires <= now {
			delete(s.seen, k)
			continue
		}
		if e.prune(horizonMs - e.retention); len(e.last) == 0 {
			delete(s.seen, k)
		}
	}
	for k, e := range s.first {
		if e.expires <= now || e.until <= horizon {
			delete(s.first, k)
		}
	}
	for k, e := range s.values {
		if e.expires <= now {
			delete(s.values, k)
		}
	}
}

// deadline returns t plus ttl, or the end of time when ttl is zero.
func deadline(t int64, ttl time.Duration) int64 {
	if ttl == 0 {
		return math.MaxInt64
	}
	return addSat(t, int64(ttl))
}

// buckets holds the buckets of one window of a counter or distinct set,
// oldest first. It keeps at most Buckets of them: those a window ending in
// the newest bucket can read.
type buckets[T any] struct {
	list []bucket[T]
}

type bucket[T any] struct {
	idx int64
	// expires is when the bucket expires by the wall clock, Unix ns.
	expires int64
	val     T
}

func byIdx[T any](b bucket[T], idx int64) int { return cmp.Compare(b.idx, idx) }

// get returns the value of bucket idx, creating the bucket when needed, and
// sets its expiry. It returns nil when idx is too old for any window that
// ends in the newest bucket.
func (bs *buckets[T]) get(idx, expires int64) *T {
	l := bs.list
	if n := len(l); n > 0 && idx <= l[n-1].idx-Buckets {
		return nil
	}
	i, found := slices.BinarySearchFunc(l, idx, byIdx[T])
	if !found {
		l = slices.Insert(l, i, bucket[T]{idx: idx})
		newest := l[len(l)-1].idx
		drop := 0
		for l[drop].idx <= newest-Buckets {
			drop++
		}
		l = slices.Delete(l, 0, drop)
		i -= drop
		bs.list = l
	}
	l[i].expires = expires
	return &l[i].val
}

// window returns the buckets of the window that ends in bucket idx.
func (bs *buckets[T]) window(idx int64) []bucket[T] {
	l := bs.list
	lo, _ := slices.BinarySearchFunc(l, idx-Buckets+1, byIdx[T])
	hi, found := slices.BinarySearchFunc(l, idx, byIdx[T])
	if found {
		hi++
	}
	return l[lo:hi]
}

// prune drops buckets expired by the wall clock or older than any window
// ending in bucket horizonIdx can read, and reports whether none is left.
func (bs *buckets[T]) prune(now, horizonIdx int64) bool {
	bs.list = slices.DeleteFunc(bs.list, func(b bucket[T]) bool {
		return b.expires <= now || b.idx <= horizonIdx-Buckets
	})
	return len(bs.list) == 0
}

// countDistinct returns the size of the union of the live sets in win.
func countDistinct(win []bucket[members], now int64) int64 {
	var largest members
	live := 0
	for _, b := range win {
		if b.expires > now {
			live++
			if len(b.val) > len(largest) {
				largest = b.val
			}
		}
	}
	if live <= 1 {
		return int64(len(largest))
	}
	union := make(members, 2*len(largest))
	for _, b := range win {
		if b.expires > now {
			for m := range b.val {
				union[m] = struct{}{}
			}
		}
	}
	return int64(len(union))
}

// seenSet holds when each member was last seen, in Unix milliseconds.
type seenSet struct {
	last map[string]int64
	// oldest is at most the smallest value in last, so marks can skip
	// pruning when nothing is old enough.
	oldest int64
	// retention is how long members are kept after they were last seen, ms.
	retention int64
	expires   int64
}

func (e *seenSet) mark(member string, ms, retention int64) {
	if prev, ok := e.last[member]; !ok || ms > prev {
		e.last[member] = ms
		e.oldest = min(e.oldest, ms)
	}
	e.retention = retention
	e.prune(ms - retention)
}

// prune drops members last seen at or before cutoff.
func (e *seenSet) prune(cutoff int64) {
	if e.oldest > cutoff {
		return
	}
	e.oldest = math.MaxInt64
	for m, last := range e.last {
		if last <= cutoff {
			delete(e.last, m)
		} else {
			e.oldest = min(e.oldest, last)
		}
	}
}

type firstSeen struct {
	ms      int64
	expires int64
	// until is when the record expires by event time: its newest write plus
	// its TTL, Unix ns.
	until int64
}

type value struct {
	v       string
	expires int64
}
