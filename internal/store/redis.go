package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultPrefix is the key prefix used when RedisOptions.Prefix is empty.
const DefaultPrefix = "catraca:"

// RedisOptions configures a Redis store.
type RedisOptions struct {
	// Prefix is prepended to every key, so several Catraca deployments can
	// share a Redis database. Default DefaultPrefix.
	Prefix string
}

// Redis is a Store backed by Redis 6.2 or later, so several Catraca instances
// share their counters. It needs Lua scripting (EVAL and EVALSHA). It is safe
// for concurrent use.
//
// Keys, after the prefix:
//
//	c:{key}:<window>             counter (hash: one field per bucket, plus n and s)
//	d:{key}:<window>:<bucket>    distinct bucket (HyperLogLog)
//	d:{key}:<window>:b<block>    distinct block, the union of 6 buckets (HyperLogLog)
//	s:key                        seen members (sorted set scored by Unix ms)
//	f:key                        first seen (sorted set with one member)
//	v:key                        value (string)
//
// The braces are a Redis Cluster hash tag: every key of a counter or distinct
// set shares a slot, so one script can read all of it on a cluster too.
//
// A counter is one hash rather than a key per bucket. Besides a field per
// bucket, it keeps the index of its newest bucket (n) and the sum of the
// buckets it holds (s), and drops buckets that leave the window of the newest
// one when a newer bucket is written, as the memory store does. A count that
// ends in the newest bucket, the common case, reads s and nothing else; any
// other count reads only the buckets between its window and the stored ones.
// Writes to a bucket too old for any window that ends in the newest one are
// ignored, as in the memory store.
//
// A distinct set keeps a HyperLogLog per bucket and one per block of 6
// aligned buckets, written together. The union of the 60 buckets of a window
// equals the union of its whole blocks and of the buckets at either end, so a
// count merges at most 15 HyperLogLogs instead of 60, and the estimate is
// identical: a HyperLogLog union is the register-wise maximum.
//
// Every key has a TTL except values and first-seen records stored with a zero
// TTL. A counter and a block expire w + w/60 after their last write, like a
// bucket: when event times keep up with the wall clock, each bucket has left
// every window by the time its own TTL would have run out, so counts are the
// same as with one key per bucket. Only when the wall clock runs ahead of
// event time (a replay slower than real time) can a count include a bucket
// whose own TTL would have run out; it is then the count event time alone
// gives, where the memory store, which expires each bucket, counts less.
//
// Why a script: a send event's batch used to be about 90 commands reading
// some 1,700 bucket keys, and parsing those arguments was most of Redis's
// work. Summing the buckets in Lua over the same keys was slower still, and a
// pipeline over block keys cut Redis's work as much as the script does but
// kept every bucket a key and every read O(15). The script sends one command
// per batch, keeps counts O(1) for counters written as often as they are
// read, and makes a NOSCRIPT retry exactly-once. docs/benchmark.md has the
// measurements.
type Redis struct {
	client redis.UniversalClient
	prefix string
	owned  bool
	// single is true for a client of one server (a single node or a
	// Sentinel failover client), where one script call can hold every key.
	// Cluster and Ring clients send one call per hash slot instead.
	single bool
}

// NewRedis returns a store that uses client, which may be a single node,
// Sentinel or Cluster client. Close does not close client.
func NewRedis(client redis.UniversalClient, opts RedisOptions) *Redis {
	prefix := opts.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	_, single := client.(*redis.Client)
	return &Redis{client: client, prefix: prefix, single: single}
}

// OpenRedis returns a store connected to the Redis server at url, for example
// "redis://user:password@localhost:6379/0" or "rediss://..." for TLS. It does
// not connect until first used. Close closes the connection.
func OpenRedis(url string, opts RedisOptions) (*Redis, error) {
	o, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("store: redis url: %w", err)
	}
	r := NewRedis(redis.NewClient(o), opts)
	r.owned = true
	return r, nil
}

// Ping checks that Redis answers.
func (r *Redis) Ping(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return r.wrap(err)
	}
	return nil
}

// Close closes the connection when the store opened it.
func (r *Redis) Close() error {
	if r.owned {
		return r.client.Close()
	}
	return nil
}

// Do runs the batch in one round trip as a Lua script, batchScript, which
// executes the operations in order and returns only their results: a count
// comes back as one integer, not as the 60 buckets it sums.
//
// On a single server the whole batch is one script call. A script may only
// touch keys in one hash slot on a cluster, and a batch spans many accounts,
// API keys and IPs, so on Cluster and Ring clients the operations are split
// by hash tag into one call per tag, sent together in one pipeline, which
// go-redis splits by node and sends to the nodes concurrently. Each counter,
// distinct set and value has its own tag, so a send event makes about 25
// calls; they still go out in one round trip per node. Every operation on a
// key lands in the call for its tag, in batch order, so a read still sees the
// writes queued before it. A call redirected with MOVED or ASK during
// resharding did not run, so go-redis can resend it.
//
// Each call runs atomically, so a call that fails with NOSCRIPT (after a
// restart, a failover or SCRIPT FLUSH) ran nothing, and is sent again with
// EVAL, which runs the script and loads it for the next EVALSHA. The batch as
// a whole is atomic on a single server only, which counters do not need.
//
// Do returns when ctx is done, whether or not Redis has answered. go-redis
// honors a context while it waits for a free connection but, unless the
// client sets ContextTimeoutEnabled, not on the connection itself; with that
// option a deadline closes the connection mid-reply, and under load the
// redials that follow exhaust ephemeral ports and degrade every decision. So
// a round trip that outlives ctx finishes in the background on its own
// connection, which then goes back to the pool, and the pool size bounds how
// many do. Its writes still apply.
func (r *Redis) Do(ctx context.Context, b *Batch) error {
	if err := b.Err(); err != nil {
		return err
	}
	if len(b.ops) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	calls := r.plan(b.ops)
	if ctx.Done() == nil {
		return r.run(ctx, calls)
	}
	done := make(chan error, 1)
	go func() { done <- r.run(ctx, calls) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return r.wrap(ctx.Err())
	}
}

// run sends calls and fills the results of their reads.
func (r *Redis) run(ctx context.Context, calls []*scriptCall) error {
	r.send(ctx, calls, false)
	var again []*scriptCall
	for _, c := range calls {
		if err := c.cmd.Err(); err != nil {
			if !redis.HasErrorPrefix(err, "NOSCRIPT") {
				return r.wrap(err)
			}
			again = append(again, c)
		}
	}
	if len(again) > 0 {
		r.send(ctx, again, true)
		for _, c := range again {
			if err := c.cmd.Err(); err != nil {
				return r.wrap(err)
			}
		}
	}
	for _, c := range calls {
		if err := c.setResults(); err != nil {
			return r.wrap(err)
		}
	}
	return nil
}

func (r *Redis) wrap(err error) error {
	if errors.Is(err, redis.ErrClosed) {
		return ErrClosed
	}
	return fmt.Errorf("store: redis: %w", err)
}

// scriptCall is one call of batchScript: the operations of a batch, or of the
// part of it whose keys share a hash slot.
type scriptCall struct {
	keys  []string
	index map[string]int // 1-based position of each key in keys
	args  []any
	reads []*op
	cmd   *redis.Cmd
}

func newScriptCall(ops int) *scriptCall {
	// A send event queues about 60 operations on about 170 keys, most of
	// them the HyperLogLogs of its distinct counts.
	return &scriptCall{index: make(map[string]int, 3*ops), args: make([]any, 0, 6*ops)}
}

// key adds k to the call's keys, once, and returns its index in KEYS.
func (c *scriptCall) key(k string) int {
	if i, ok := c.index[k]; ok {
		return i
	}
	c.keys = append(c.keys, k)
	c.index[k] = len(c.keys)
	return len(c.keys)
}

// plan turns the batch into script calls: one on a single server, else one
// per hash tag.
func (r *Redis) plan(ops []op) []*scriptCall {
	if r.single {
		c := newScriptCall(len(ops))
		for i := range ops {
			r.encode(c, &ops[i], r.keys(&ops[i]))
		}
		return []*scriptCall{c}
	}
	var calls []*scriptCall
	byTag := make(map[string]*scriptCall)
	for i := range ops {
		keys := r.keys(&ops[i])
		// Every key of one operation has the same hash tag.
		tag := hashTag(keys[0])
		c := byTag[tag]
		if c == nil {
			c = newScriptCall(4)
			byTag[tag] = c
			calls = append(calls, c)
		}
		r.encode(c, &ops[i], keys)
	}
	return calls
}

// send issues calls, with EVALSHA or, when eval is set, with EVAL. One call
// is sent on its own, several in one pipeline; results and errors are read
// from each call's cmd.
func (r *Redis) send(ctx context.Context, calls []*scriptCall, eval bool) {
	issue := func(s redis.Scripter, c *scriptCall) *redis.Cmd {
		if eval {
			return s.Eval(ctx, batchScript, c.keys, c.args...)
		}
		return s.EvalSha(ctx, batchSHA, c.keys, c.args...)
	}
	if len(calls) == 1 {
		calls[0].cmd = issue(r.client, calls[0])
		return
	}
	pipe := r.client.Pipeline()
	for _, c := range calls {
		c.cmd = issue(pipe, c)
	}
	// Exec's error is the first failed command's, which is checked per call.
	_, _ = pipe.Exec(ctx)
}

// keys returns the keys o touches, after the prefix. They share a hash tag.
func (r *Redis) keys(o *op) []string {
	switch o.kind {
	case opIncr, opCount:
		return []string{r.prefix + "c:{" + o.key + "}:" + o.span.String()}
	case opAddDistinct:
		idx := floorDiv(o.at, bucketWidth(o.span))
		base := r.seriesPrefix("d:", o.key, o.span)
		return []string{
			base + strconv.FormatInt(idx, 10),
			base + "b" + strconv.FormatInt(floorDiv(idx, distinctBlock), 10),
		}
	case opDistinct:
		return r.distinctKeys(o.key, o.span, o.at)
	case opMarkSeen, opSeenWithin:
		return []string{r.prefix + "s:" + o.key}
	case opFirstSeen:
		return []string{r.prefix + "f:" + o.key}
	default: // opSet, opGet
		return []string{r.prefix + "v:" + o.key}
	}
}

// encode appends o to the call, as batchScript reads it.
func (r *Redis) encode(c *scriptCall, o *op, keys []string) {
	switch o.kind {
	case opIncr:
		c.args = append(c.args, "I", c.key(keys[0]), floorDiv(o.at, bucketWidth(o.span)), o.n, bucketTTL(o.span).Milliseconds())
	case opCount:
		c.args = append(c.args, "C", c.key(keys[0]), floorDiv(o.at, bucketWidth(o.span)))
		c.reads = append(c.reads, o)
	case opAddDistinct:
		c.args = append(c.args, "A", c.key(keys[0]), c.key(keys[1]), o.member, bucketTTL(o.span).Milliseconds())
	case opDistinct:
		c.args = append(c.args, "D", len(keys))
		for _, k := range keys {
			c.args = append(c.args, c.key(k))
		}
		c.reads = append(c.reads, o)
	case opMarkSeen:
		ms := unixMilli(o.at)
		c.args = append(c.args, "M", c.key(keys[0]), o.member, ms, ms-o.span.Milliseconds(), o.span.Milliseconds())
	case opSeenWithin:
		c.args = append(c.args, "S", c.key(keys[0]), o.member)
		c.reads = append(c.reads, o)
	case opFirstSeen:
		c.args = append(c.args, "F", c.key(keys[0]), unixMilli(o.at), o.span.Milliseconds())
		c.reads = append(c.reads, o)
	case opSet:
		c.args = append(c.args, "V", c.key(keys[0]), o.member, o.span.Milliseconds())
	case opGet:
		c.args = append(c.args, "G", c.key(keys[0]))
		c.reads = append(c.reads, o)
	}
}

// setResults fills the results of the call's reads from its reply.
func (c *scriptCall) setResults() error {
	vals, ok := c.cmd.Val().([]any)
	if !ok || len(vals) != len(c.reads) {
		return fmt.Errorf("script returned %d results for %d reads", len(vals), len(c.reads))
	}
	for i, o := range c.reads {
		if err := setResult(o, vals[i]); err != nil {
			return err
		}
	}
	return nil
}

// setResult sets o's result from v, the script's result for it: an integer
// for counts, a score as a string or nil for seen members and first-seen
// records, a string or nil for values.
func setResult(o *op, v any) error {
	switch o.kind {
	case opCount, opDistinct:
		n, ok := v.(int64)
		if !ok {
			return fmt.Errorf("%q: script returned %T for a count", o.key, v)
		}
		o.ints.val = n

	case opSeenWithin:
		if v == nil {
			return nil
		}
		ms, err := score(o.key, v)
		if err != nil {
			return err
		}
		o.bools.val = unixMilli(o.at)-ms < o.span.Milliseconds()

	case opFirstSeen:
		ms, err := score(o.key, v)
		if err != nil {
			return err
		}
		o.times.ms = ms

	case opGet:
		if v == nil {
			return nil
		}
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%q: script returned %T for a value", o.key, v)
		}
		o.strs.val, o.strs.found = s, true
	}
	return nil
}

// score parses a sorted set score holding Unix milliseconds.
func score(key string, v any) (int64, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("%q: script returned %T for a score", key, v)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("%q: score %q: %w", key, s, err)
	}
	return int64(f), nil
}

func (r *Redis) seriesPrefix(kind, key string, w time.Duration) string {
	return r.prefix + kind + "{" + key + "}:" + w.String() + ":"
}

// distinctBlock is how many aligned buckets of a distinct set a block holds.
// With 60 buckets a window is 10 whole blocks when its first bucket is
// aligned, and otherwise 9 whole blocks and 6 buckets.
const distinctBlock = 6

// distinctKeys returns the keys whose union is the window of w that ends at
// at, Unix ns: its whole blocks and the buckets before and after them. The
// keys are slices of one string, built in one buffer: a batch reads over a
// hundred of them, and one allocation each adds up.
func (r *Redis) distinctKeys(key string, w time.Duration, at int64) []string {
	base := r.seriesPrefix("d:", key, w)
	last := floorDiv(at, bucketWidth(w))
	first := last - Buckets + 1
	// Whole blocks cover the buckets from lo to hi-1.
	lo := floorDiv(first+distinctBlock-1, distinctBlock) * distinctBlock
	hi := floorDiv(last+1, distinctBlock) * distinctBlock
	var (
		ends    [Buckets]int
		n       int
		digits  [21]byte
		builder strings.Builder
	)
	add := func(block string, idx int64) {
		builder.WriteString(base)
		builder.WriteString(block)
		builder.Write(strconv.AppendInt(digits[:0], idx, 10))
		ends[n] = builder.Len()
		n++
	}
	builder.Grow((2*distinctBlock + Buckets/distinctBlock) * (len(base) + len(strconv.AppendInt(digits[:0], first, 10)) + 1))
	for idx := first; idx < lo; idx++ {
		add("", idx)
	}
	for blk := lo / distinctBlock; blk < hi/distinctBlock; blk++ {
		add("b", blk)
	}
	for idx := hi; idx <= last; idx++ {
		add("", idx)
	}
	all := builder.String()
	keys := make([]string, n)
	start := 0
	for i, end := range ends[:n] {
		keys[i] = all[start:end]
		start = end
	}
	return keys
}

// hashTag returns the part of key that Redis Cluster hashes to pick its slot:
// what is between the first '{' and the first '}' after it, when that is not
// empty, else the whole key.
func hashTag(key string) string {
	open := strings.IndexByte(key, '{')
	if open < 0 {
		return key
	}
	end := strings.IndexByte(key[open+1:], '}')
	if end <= 0 {
		return key
	}
	return key[open+1 : open+1+end]
}
