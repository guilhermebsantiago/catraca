// Package store keeps the counters behind Catraca's signals: sliding-window
// counts, distinct counts, first-seen times, recently seen members and plain
// values.
//
// Operations are queued on a Batch and run by Store.Do in one round trip, so
// computing every signal for an event costs one call to the backend.
// Operations run in the order they were queued: a read sees the writes queued
// before it in the same batch.
//
// # Windows
//
// Windows slide with the event time passed to each operation, not with the
// wall clock, so replaying old events in order reproduces the values they
// had. A window w is split into Buckets buckets of w/Buckets each. A count
// over w at time at always includes events less than w-w/Buckets old, never
// includes events w or more old, and includes those in between while their
// bucket is the window's oldest. For the 1 hour window that is a one minute
// margin.
//
// # Expiry
//
// Every entry has a time to live on the wall clock, like a Redis TTL, long
// enough for every window that can still read it, so storage stays bounded by
// recent traffic. A write renews the time to live of what it touches.
//
// # Retries
//
// Every write but Incr has the same effect applied twice as once. A batch
// queued with Dedupe applies its increments once per id, so a caller that
// does not know whether a batch ran, after a timeout say, can send it again.
package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
)

// Buckets is the number of buckets each window is split into.
const Buckets = 60

// MinWindow is the shortest window Incr, Count, AddDistinct and Distinct
// accept.
const MinWindow = time.Second

// Store runs batches of operations. Implementations are safe for concurrent
// use.
type Store interface {
	// Do runs the operations queued on b, in order, in one round trip to the
	// backend, and fills their results. When Do returns an error, results may
	// be unfilled or partially filled and must not be used. When ctx is
	// already done, Do runs nothing and returns ctx's error at once: the
	// engine skips the store that way while its breaker is open.
	Do(ctx context.Context, b *Batch) error
	// Close releases the store's resources.
	Close() error
}

// ErrClosed is returned by Do after the store was closed.
var ErrClosed = errors.New("store: closed")

// Batch is a list of operations for Store.Do. The zero value is an empty batch
// ready to use. A Batch is not safe for concurrent use and is meant to be run
// once.
//
// Arguments are checked as operations are queued. The first invalid one is
// reported by Err and by Do, which then runs nothing.
type Batch struct {
	ops []op
	err error
	// once is set by Dedupe.
	once *once
	// incrs is set when the batch holds an Incr, the one write once guards.
	incrs bool
}

// once is what Dedupe queued: the batch's id, its event time in Unix
// nanoseconds, how long the id is remembered, and where Do says whether the
// batch repeated one that had applied.
type once struct {
	id       string
	at       int64
	ttl      time.Duration
	repeated *BoolResult
}

type opKind uint8

const (
	opIncr opKind = iota + 1
	opCount
	opAddDistinct
	opDistinct
	opMarkSeen
	opSeenWithin
	opFirstSeen
	opSet
	opGet
)

type op struct {
	kind opKind
	key  string
	// member is the member for AddDistinct, MarkSeen and SeenWithin, and the
	// value for Set.
	member string
	// span is the window, lookback, retention or TTL, depending on kind.
	span time.Duration
	// at is the event time in Unix nanoseconds.
	at int64
	n  int64

	ints  *IntResult
	bools *BoolResult
	times *TimeResult
	strs  *StringResult
}

// IntResult holds the result of Count or Distinct once Store.Do has run.
type IntResult struct{ val int64 }

// Val returns the result.
func (r *IntResult) Val() int64 { return r.val }

// BoolResult holds the result of SeenWithin or Dedupe once Store.Do has run.
type BoolResult struct{ val bool }

// Val returns the result.
func (r *BoolResult) Val() bool { return r.val }

// TimeResult holds the result of FirstSeen once Store.Do has run.
type TimeResult struct{ ms int64 }

// Val returns the result, in UTC, with millisecond precision.
func (r *TimeResult) Val() time.Time { return time.UnixMilli(r.ms).UTC() }

// StringResult holds the result of Get once Store.Do has run.
type StringResult struct {
	val   string
	found bool
}

// Val returns the value, or "" when the key was not found.
func (r *StringResult) Val() string { return r.val }

// Found reports whether the key held a value.
func (r *StringResult) Found() bool { return r.found }

// Err returns the first invalid operation queued on b, if any.
func (b *Batch) Err() error { return b.err }

// Incr adds n to the counter key in window w at time at.
func (b *Batch) Incr(key string, w time.Duration, at time.Time, n int64) {
	if b.check("Incr", key, at) && b.checkWindow("Incr", key, w) {
		b.ops = append(b.ops, op{kind: opIncr, key: key, span: w, at: at.UnixNano(), n: n})
		b.incrs = true
	}
}

// Dedupe makes the batch's increments apply once per id: when a batch with
// the same id applied its increments less than ttl ago, by the wall clock,
// Do skips this batch's Incr operations and the result's Val is true. The
// rest of the batch runs as usual. Those operations are idempotent (adding a
// member to a distinct set, marking it seen, keeping the earliest first-seen
// time, setting a value), so a batch sent again changes nothing, and its
// reads see the counters with the first batch counted once. at is the
// batch's event time: the memory store also forgets an id once the newest
// event time it has stored is ttl past at, or past the newest event time it
// had stored when the id came if that is later, as it forgets counters. So
// the memory store remembers the id of an event that is behind the wall
// clock and ahead of every event it holds, such as a late first event after
// a start or a quiet spell, for less than ttl by the wall clock: less by as
// much as the event was late.
//
// The id is remembered for ttl from the first batch that carried it, at the
// cost of one entry per batch with increments: one Redis key, or on a
// cluster one key in each hash slot whose increments it guards. Each slot is
// guarded on its own, so sending again a batch that applied in some slots
// and failed in others applies the rest, once. A batch without increments
// has nothing to guard: it leaves no entry, and its result is false.
//
// Dedupe may be queued once per batch, anywhere in it.
func (b *Batch) Dedupe(id string, at time.Time, ttl time.Duration) *BoolResult {
	r := new(BoolResult)
	switch {
	case b.once != nil:
		b.fail("Dedupe %q: the batch already has id %q", id, b.once.id)
	case b.check("Dedupe", id, at) && b.checkSpan("Dedupe", id, "ttl", ttl):
		b.once = &once{id: id, at: at.UnixNano(), ttl: ttl, repeated: r}
	}
	return r
}

// Count returns the sum of what was added to the counter key in window w
// during the window that ends at at. w must be the window the counter was
// incremented with.
func (b *Batch) Count(key string, w time.Duration, at time.Time) *IntResult {
	r := new(IntResult)
	if b.check("Count", key, at) && b.checkWindow("Count", key, w) {
		b.ops = append(b.ops, op{kind: opCount, key: key, span: w, at: at.UnixNano(), ints: r})
	}
	return r
}

// AddDistinct adds member to the distinct set key in window w at time at.
func (b *Batch) AddDistinct(key, member string, w time.Duration, at time.Time) {
	if b.check("AddDistinct", key, at) && b.checkWindow("AddDistinct", key, w) {
		b.ops = append(b.ops, op{kind: opAddDistinct, key: key, member: member, span: w, at: at.UnixNano()})
	}
}

// Distinct returns how many different members were added to the distinct
// set key in window w during the window that ends at at. The memory store
// counts exactly; the Redis store estimates with HyperLogLog, which is exact
// for small sets and has a standard error of 0.81% for large ones.
func (b *Batch) Distinct(key string, w time.Duration, at time.Time) *IntResult {
	r := new(IntResult)
	if b.check("Distinct", key, at) && b.checkWindow("Distinct", key, w) {
		b.ops = append(b.ops, op{kind: opDistinct, key: key, span: w, at: at.UnixNano(), ints: r})
	}
	return r
}

// MarkSeen records that member was seen under key at time at. Members are
// kept for retention after the last time they were seen, so SeenWithin
// lookbacks must not exceed it. Recording an earlier time than the one
// already recorded changes nothing.
func (b *Batch) MarkSeen(key, member string, at time.Time, retention time.Duration) {
	if b.check("MarkSeen", key, at) && b.checkSpan("MarkSeen", key, "retention", retention) {
		b.ops = append(b.ops, op{kind: opMarkSeen, key: key, member: member, span: retention, at: at.UnixNano()})
	}
}

// SeenWithin reports whether member was marked seen under key less than
// lookback before at. A member marked seen after at also counts.
func (b *Batch) SeenWithin(key, member string, lookback time.Duration, at time.Time) *BoolResult {
	r := new(BoolResult)
	if b.check("SeenWithin", key, at) && b.checkSpan("SeenWithin", key, "lookback", lookback) {
		b.ops = append(b.ops, op{kind: opSeenWithin, key: key, member: member, span: lookback, at: at.UnixNano(), bools: r})
	}
	return r
}

// FirstSeen records at as the first time key was seen, unless an earlier time
// is already recorded, and returns the earliest time. Keeping the earliest,
// rather than the first written, makes the result independent of the order
// events arrive in. The record expires ttl after its last write; zero keeps
// it forever.
func (b *Batch) FirstSeen(key string, at time.Time, ttl time.Duration) *TimeResult {
	r := new(TimeResult)
	if b.check("FirstSeen", key, at) && b.checkTTL("FirstSeen", key, ttl) {
		b.ops = append(b.ops, op{kind: opFirstSeen, key: key, span: ttl, at: at.UnixNano(), times: r})
	}
	return r
}

// Set stores value under key. It expires ttl after the write; zero keeps it
// forever.
func (b *Batch) Set(key, value string, ttl time.Duration) {
	if b.checkKey("Set", key) && b.checkTTL("Set", key, ttl) {
		b.ops = append(b.ops, op{kind: opSet, key: key, member: value, span: ttl})
	}
}

// Get returns the value stored under key by Set.
func (b *Batch) Get(key string) *StringResult {
	r := new(StringResult)
	if b.checkKey("Get", key) {
		b.ops = append(b.ops, op{kind: opGet, key: key, strs: r})
	}
	return r
}

// minTime and maxTime bound the times that fit in Unix nanoseconds.
var (
	minTime = time.Unix(0, math.MinInt64)
	maxTime = time.Unix(0, math.MaxInt64)
)

func (b *Batch) fail(format string, args ...any) bool {
	if b.err == nil {
		b.err = fmt.Errorf("store: "+format, args...)
	}
	return false
}

func (b *Batch) checkKey(name, key string) bool {
	if key == "" {
		return b.fail("%s: empty key", name)
	}
	return true
}

func (b *Batch) check(name, key string, at time.Time) bool {
	if !b.checkKey(name, key) {
		return false
	}
	if at.Before(minTime) || at.After(maxTime) {
		return b.fail("%s %q: time %v is out of range", name, key, at)
	}
	return true
}

func (b *Batch) checkWindow(name, key string, w time.Duration) bool {
	if w < MinWindow {
		return b.fail("%s %q: window %v is shorter than %v", name, key, w, MinWindow)
	}
	return true
}

func (b *Batch) checkSpan(name, key, what string, d time.Duration) bool {
	if d < time.Millisecond {
		return b.fail("%s %q: %s %v is shorter than 1ms", name, key, what, d)
	}
	return true
}

func (b *Batch) checkTTL(name, key string, ttl time.Duration) bool {
	if ttl != 0 && ttl < time.Millisecond {
		return b.fail("%s %q: ttl %v must be zero or at least 1ms", name, key, ttl)
	}
	return true
}

// bucketWidth is the width of one bucket of window w, in nanoseconds.
func bucketWidth(w time.Duration) int64 { return int64(w) / Buckets }

// bucketTTL is how long a bucket of window w is kept after its last write.
// Counts read a bucket until w after its start, so w after any write to it is
// enough; one more bucket absorbs jitter between event times and the wall
// clock.
func bucketTTL(w time.Duration) time.Duration {
	return time.Duration(addSat(int64(w), bucketWidth(w)))
}

// addSat returns a+b for b >= 0, saturating instead of overflowing.
func addSat(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// floorDiv divides rounding toward negative infinity, so times before 1970
// fall in the right bucket.
func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// unixMilli converts Unix nanoseconds to Unix milliseconds, rounding down.
func unixMilli(ns int64) int64 { return floorDiv(ns, int64(time.Millisecond)) }
