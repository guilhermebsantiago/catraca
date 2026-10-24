package store

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

// The differential tests run one program on every backend and compare what
// each read returns. The wall clock moves with event time, as in
// production, where events arrive within moments of happening: it is the
// newest event time stored so far, rounded down to the second. Every
// window, time to live and retention the programs use is a whole number of
// seconds, so each entry expires on a whole second too, the same second in
// every backend.
//
// Where the backends agree is the store's contract. A batch that is not
// late, whose time is not before an earlier one's, reads the same values on
// every backend. A late batch reads the same on every Redis backend, but
// not on the memory store, which forgets by the newest event time and
// expires each bucket on its own (see Memory and Redis): its counts may be
// lower, where it forgot buckets Redis keeps, or higher, where it forgot a
// counter whose newer buckets make Redis ignore the late write; it sees at
// most the members Redis sees; and it agrees on the rest. What a late batch
// leaves behind never makes a later batch that is not late differ.

// DiffBackend is a store the differential tests run, with a way to move the
// wall clock it expires entries by.
type DiffBackend struct {
	Name string
	// New returns an empty store and a function that moves its wall clock
	// on by whole seconds; the store goes away when tb ends.
	New func(tb testing.TB) (Store, func(time.Duration))
	// Memory is set for the memory store, which may read other counts than
	// the others in a late batch.
	Memory bool
	skip   func() string
}

// Skip says why the backend cannot run here, or returns "".
func (b DiffBackend) Skip() string {
	if b.skip == nil {
		return ""
	}
	return b.skip()
}

// DiffBackends lists the backends the differential tests compare: the
// memory store, the Redis store on miniredis through a single-node client
// and through a Cluster client, and on a real Redis server and Cluster when
// CATRACA_TEST_REDIS_URL and CATRACA_TEST_REDIS_CLUSTER are set.
func DiffBackends() []DiffBackend {
	return []DiffBackend{
		{Name: "memory", Memory: true, New: func(tb testing.TB) (Store, func(time.Duration)) {
			m := NewMemory()
			clock := &fakeClock{t: t0}
			m.now = clock.Now
			tb.Cleanup(func() { m.Close() })
			return m, clock.Advance
		}},
		{Name: "redis", New: func(tb testing.TB) (Store, func(time.Duration)) {
			mr := storetest.Miniredis(tb)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, ReadTimeout: storetest.MiniredisReadTimeout})
			tb.Cleanup(func() { client.Close() })
			return NewRedis(client, RedisOptions{}), mr.FastForward
		}},
		{Name: "redis-cluster", New: func(tb testing.TB) (Store, func(time.Duration)) {
			mr := storetest.Miniredis(tb)
			client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{mr.Addr()}, MaxRetries: -1, ReadTimeout: storetest.MiniredisReadTimeout})
			tb.Cleanup(func() { client.Close() })
			return NewRedis(client, RedisOptions{}), mr.FastForward
		}},
		{Name: "redis-server", skip: storetest.RedisServerSkip, New: func(tb testing.TB) (Store, func(time.Duration)) {
			client, prefix := storetest.RedisServer(tb)
			return NewRedis(client, RedisOptions{Prefix: prefix}), realClock(tb, client, prefix)
		}},
		{Name: "redis-cluster-server", skip: storetest.RedisClusterSkip, New: func(tb testing.TB) (Store, func(time.Duration)) {
			client, prefix := storetest.RedisCluster(tb)
			return NewRedis(client, RedisOptions{Prefix: prefix}), realClock(tb, client, prefix)
		}},
	}
}

// realClock returns a function that moves a real Redis server's clock on by
// d, for the keys under prefix, as fastForward does, and keeps it in step
// with the test's clock while the test runs. Redis counts time to live on
// its own clock, which moves on as the test runs, so a key's time to live
// drifts below the test's by the real time since it was set. Every time to
// live the test sets is a whole number of seconds, and so stays on the
// test's clock: rounding up to the second removes the drift, as long as
// less than a second passes between two calls. The function is called
// before every batch, with d = 0 when the test's clock has not moved, and
// skips the test when the machine is too slow for that.
func realClock(tb testing.TB, client redis.UniversalClient, prefix string) func(time.Duration) {
	last := time.Now()
	return func(d time.Duration) {
		tb.Helper()
		if since := time.Since(last); since > 900*time.Millisecond {
			tb.Skipf("%v passed between two batches; the real Redis clock cannot be kept in step", since)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		keys := storetest.ScanKeys(tb, ctx, client, prefix)
		ttls := make([]*redis.DurationCmd, len(keys))
		pipe := client.Pipeline()
		for i, k := range keys {
			ttls[i] = pipe.PTTL(ctx, k)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			tb.Fatalf("PTTL: %v", err)
		}
		pipe = client.Pipeline()
		for i, k := range keys {
			ttl := ttls[i].Val()
			if ttl < 0 {
				continue // no time to live, or gone
			}
			left := (ttl+time.Second-1)/time.Second*time.Second - d
			if left <= 0 {
				pipe.Del(ctx, k)
			} else {
				pipe.PExpire(ctx, k, left)
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			tb.Fatalf("move the clock on: %v", err)
		}
		last = time.Now()
	}
}

// Windows, times to live and retentions the store-level programs use: every
// window the catalog uses and a two minute one, each a whole number of
// seconds in its buckets too.
var (
	diffWindows = []time.Duration{time.Minute, 2 * time.Minute, time.Hour, 24 * time.Hour, week}
	diffTTLs    = []time.Duration{0, time.Second, 61 * time.Second, time.Hour, 10 * 24 * time.Hour}
	// diffRetentions is the retention of each seen key, fixed per key: the
	// contract asks lookbacks not to exceed it.
	diffRetentions = []time.Duration{30 * 24 * time.Hour, time.Hour, 24 * time.Hour, 2 * time.Second}
	// diffJumps are how far event time moves: across every bucket and
	// window edge and every time to live above.
	diffJumps = []time.Duration{
		0, time.Millisecond, 999 * time.Millisecond, time.Second, 59 * time.Second, time.Minute, 61 * time.Second,
		59 * time.Minute, time.Hour, 61 * time.Minute, 23 * time.Hour, 24 * time.Hour, 24*time.Hour + 24*time.Minute,
		6 * 24 * time.Hour, week, week + 2*time.Hour + 48*time.Minute, 10 * 24 * time.Hour, 31 * 24 * time.Hour,
	}
)

// diffOp is one operation of a program.
type diffOp struct {
	kind   opKind
	key    int
	window time.Duration
	member int
	n      int64
	ttl    time.Duration
}

// diffBatch is one batch of a program: operations at one time, and maybe a
// Dedupe id.
type diffBatch struct {
	ops []diffOp
	id  string
	ttl time.Duration
}

// program reads the steps of a differential test from fuzz data.
type program struct {
	data []byte
}

func (p *program) next() byte {
	if len(p.data) == 0 {
		return 0
	}
	b := p.data[0]
	p.data = p.data[1:]
	return b
}

func (p *program) more() bool { return len(p.data) > 0 }

// step is what a program does next: move event time by jump, or send a
// batch at the new time. A batch whose time is before the newest so far is
// late.
type step struct {
	jump  time.Duration
	batch *diffBatch
}

// nextStep reads a step. Most move time a little, within the shortest
// windows, so counts build up; some jump across a window or a time to live;
// some go back up to a week, so the batches until time catches up are late;
// some send an earlier batch again, as a retry; the rest send a new batch.
func (p *program) nextStep(sent []diffBatch) step {
	switch op := p.next(); {
	case op < 0x40:
		return step{jump: time.Duration(int(p.next())<<8|int(p.next())) * 2 * time.Millisecond}
	case op < 0x50:
		return step{jump: diffJumps[int(p.next())%len(diffJumps)]}
	case op < 0x58:
		return step{jump: -min(week, time.Duration(1+int(p.next()))*diffJumps[int(p.next())%len(diffJumps)])}
	case op < 0x70 && len(sent) > 0:
		if b := sent[int(p.next())%len(sent)]; b.id != "" {
			return step{batch: &b}
		}
	}
	b := p.batch(len(sent))
	return step{batch: &b}
}

// batch reads a new batch: writes, each followed by the read of what it
// wrote as the catalog does, and reads alone. Each kind has keys of its
// own, and each seen key a retention of its own.
func (p *program) batch(n int) diffBatch {
	var b diffBatch
	for range 1 + int(p.next())%6 {
		x, y := p.next(), p.next()
		o := diffOp{
			key:    int(x>>3) % 2,
			window: diffWindows[int(y)%len(diffWindows)],
			member: int(y>>3) % 4,
			n:      1 + int64(x>>6),
			ttl:    diffTTLs[int(y>>5)%len(diffTTLs)],
		}
		pair := func(write, read opKind) {
			o.kind = write
			b.ops = append(b.ops, o)
			o.kind = read
			b.ops = append(b.ops, o)
		}
		switch x % 6 {
		case 0:
			pair(opIncr, opCount)
		case 1:
			pair(opAddDistinct, opDistinct)
		case 2:
			// The catalog reads new_ip before it marks the IP seen.
			pair(opSeenWithin, opMarkSeen)
		case 3:
			o.kind = opFirstSeen
			b.ops = append(b.ops, o)
		case 4:
			pair(opSet, opGet)
		default:
			o.kind = []opKind{opCount, opDistinct, opSeenWithin, opGet}[int(x>>4)%4]
			b.ops = append(b.ops, o)
		}
	}
	if flag := p.next(); flag%4 != 0 {
		b.id = fmt.Sprintf("batch-%d", n)
		b.ttl = []time.Duration{time.Minute, 10 * time.Minute, time.Hour}[int(flag)%3]
		// A batch with an id records its time even when it repeats and
		// its increments are skipped, as each of the catalog's does with
		// first-seen times. Otherwise the memory store's newest event time
		// would fall behind the wall clock, which these tests keep in step
		// with it, and the store forgets ids and first-seen times by it.
		b.ops = append(b.ops, diffOp{kind: opFirstSeen, key: 1, ttl: diffTTLs[int(flag)%len(diffTTLs)]})
	}
	return b
}

// recordsTime reports whether the batch stores an event time, which moves
// the memory store's newest event time on.
func (b diffBatch) recordsTime() bool {
	for _, o := range b.ops {
		if (&op{kind: o.kind}).recordsTime() {
			return true
		}
	}
	return false
}

// FuzzStoresAgree runs a program of batches on every backend and compares
// every result.
func FuzzStoresAgree(f *testing.F) {
	for _, seed := range diffSeeds(8, 1500) {
		f.Add(seed)
	}
	backends := DiffBackends()
	f.Fuzz(func(t *testing.T, data []byte) {
		type runner struct {
			DiffBackend
			s       Store
			advance func(time.Duration)
		}
		var runs []runner
		for _, be := range backends {
			if be.Skip() != "" {
				continue
			}
			s, advance := be.New(t)
			runs = append(runs, runner{be, s, advance})
		}
		// The stores start with an event time stored at t0, where the wall
		// clock starts. An empty memory store has no newest event time to
		// forget by, so its first event, if late, would be remembered for
		// less than its ttl by the wall clock (see Batch.Dedupe).
		for _, r := range runs {
			runBatch(t, r.s, diffBatch{ops: []diffOp{{kind: opFirstSeen, key: 9}}}, t0)
		}
		p := &program{data: data}
		at, newest := t0, t0
		var sent []diffBatch
		for i := 0; p.more() && i < 150; i++ {
			st := p.nextStep(sent)
			if st.batch == nil {
				at = at.Add(st.jump)
				continue
			}
			b := *st.batch
			late := at.Before(newest)
			if at.After(newest) && b.recordsTime() {
				// The wall clock follows the newest event time stored, by
				// whole seconds. A batch that only reads stores none.
				d := at.Truncate(time.Second).Sub(newest.Truncate(time.Second))
				newest = at
				for _, r := range runs {
					r.advance(d)
				}
			} else {
				for _, r := range runs {
					r.advance(0)
				}
			}
			sent = append(sent, b)
			results := make([][]result, len(runs))
			for j, r := range runs {
				results[j] = runBatch(t, r.s, b, at)
			}
			// Each backend against the first Redis one; the memory store,
			// first, may read other counts in a late batch.
			for j := range runs {
				if j == 1 {
					continue
				}
				if why := differs(results[j], results[1], late && runs[j].Memory); why != "" {
					t.Fatalf("step %d, batch %+v at %v (late %v): %s and %s differ: %s",
						i, b, at.Sub(t0), late, runs[j].Name, runs[1].Name, why)
				}
			}
		}
	})
}

// diffSeeds returns n programs of size bytes drawn from a fixed random
// source.
func diffSeeds(n, size int) [][]byte {
	r := rand.New(rand.NewPCG(7, 11))
	seeds := make([][]byte, n)
	for i := range seeds {
		seeds[i] = make([]byte, size)
		for j := range seeds[i] {
			seeds[i][j] = byte(r.Uint32())
		}
	}
	return seeds
}

// result is what one operation read; for a Dedupe, whether it repeated.
type result struct {
	kind  opKind
	n     int64
	b     bool
	ms    int64
	s     string
	found bool
}

// runBatch runs b at time at on s and returns what each operation read.
func runBatch(t *testing.T, s Store, b diffBatch, at time.Time) []result {
	t.Helper()
	var batch Batch
	type read struct {
		kind  opKind
		ints  *IntResult
		bools *BoolResult
		times *TimeResult
		strs  *StringResult
	}
	var reads []read
	for _, o := range b.ops {
		key := fmt.Sprintf("k%d", o.key)
		member := fmt.Sprintf("m%d", o.member)
		switch o.kind {
		case opIncr:
			batch.Incr(key, o.window, at, o.n)
		case opCount:
			reads = append(reads, read{kind: o.kind, ints: batch.Count(key, o.window, at)})
		case opAddDistinct:
			batch.AddDistinct(key, member, o.window, at)
		case opDistinct:
			reads = append(reads, read{kind: o.kind, ints: batch.Distinct(key, o.window, at)})
		case opMarkSeen:
			batch.MarkSeen(key, member, at, diffRetentions[o.key])
		case opSeenWithin:
			// A lookback up to the key's retention.
			lookback := diffRetentions[o.key] / time.Duration(1+o.member%2)
			reads = append(reads, read{kind: o.kind, bools: batch.SeenWithin(key, member, lookback, at)})
		case opFirstSeen:
			reads = append(reads, read{kind: o.kind, times: batch.FirstSeen(key, at, o.ttl)})
		case opSet:
			batch.Set(key, fmt.Sprintf("%s@%d", member, at.UnixMilli()), o.ttl)
		case opGet:
			reads = append(reads, read{kind: o.kind, strs: batch.Get(key)})
		}
	}
	var repeated *BoolResult
	if b.id != "" {
		repeated = batch.Dedupe(b.id, at, b.ttl)
	}
	if err := s.Do(context.Background(), &batch); err != nil {
		t.Fatalf("Do: %v", err)
	}
	out := make([]result, 0, len(reads)+1)
	for _, r := range reads {
		res := result{kind: r.kind}
		switch {
		case r.ints != nil:
			res.n = r.ints.Val()
		case r.bools != nil:
			res.b = r.bools.Val()
		case r.times != nil:
			res.ms = r.times.Val().UnixMilli()
		case r.strs != nil:
			res.s, res.found = r.strs.Val(), r.strs.Found()
		}
		out = append(out, res)
	}
	if repeated != nil {
		out = append(out, result{kind: math.MaxUint8, b: repeated.Val()})
	}
	return out
}

// differs says how want differs from got, or returns "". With memoryLate,
// want are the memory store's results for a late batch: its counts may be
// lower or higher, and it may not see a member Redis sees.
func differs(want, got []result, memoryLate bool) string {
	if len(want) != len(got) {
		return fmt.Sprintf("%d results, %d results", len(want), len(got))
	}
	for i := range want {
		w, g := want[i], got[i]
		if w == g {
			continue
		}
		if memoryLate {
			switch w.kind {
			case opCount, opDistinct:
				continue
			case opSeenWithin:
				if !w.b && g.b {
					continue
				}
			}
		}
		return fmt.Sprintf("result %d: %+v, %+v", i, w, g)
	}
	return ""
}
