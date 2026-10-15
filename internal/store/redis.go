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
// share their counters. It is safe for concurrent use.
//
// Keys, after the prefix:
//
//	c:{key}:<window>:<bucket>   counter bucket (string, INCRBY)
//	d:{key}:<window>:<bucket>   distinct bucket (HyperLogLog, PFADD)
//	s:key                       seen members (sorted set scored by Unix ms)
//	f:key                       first seen (sorted set with one member)
//	v:key                       value (string)
//
// The braces are a Redis Cluster hash tag: all buckets of a key share a slot,
// so MGET and PFCOUNT over them work on a cluster too. Every key has a TTL
// except values and first-seen records stored with a zero TTL.
type Redis struct {
	client redis.UniversalClient
	prefix string
	owned  bool
}

// NewRedis returns a store that uses client, which may be a single node,
// Sentinel or Cluster client. Close does not close client.
func NewRedis(client redis.UniversalClient, opts RedisOptions) *Redis {
	prefix := opts.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	return &Redis{client: client, prefix: prefix}
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

// Do sends the whole batch as one pipeline rather than as a Lua script. Every
// operation maps to plain commands, so a pipeline already makes it one round
// trip, without loading scripts or handling NOSCRIPT after a restart or
// failover. It also works on Redis Cluster, where a script must declare its
// keys and they must all live in one slot, while a batch spans many accounts,
// API keys and IPs. The price is that a batch is not atomic, which counters
// tolerate; commands still run in order, so a read sees the writes queued
// before it.
func (r *Redis) Do(ctx context.Context, b *Batch) error {
	if err := b.Err(); err != nil {
		return err
	}
	if len(b.ops) == 0 {
		return nil
	}
	pipe := r.client.Pipeline()
	reads := make([]redis.Cmder, len(b.ops))
	for i := range b.ops {
		reads[i] = r.queue(ctx, pipe, &b.ops[i])
	}
	cmds, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return r.wrap(err)
	}
	// Exec reports only the first failed command, and a missing key (Nil)
	// counts as one, so look at each.
	for _, c := range cmds {
		if err := c.Err(); err != nil && !errors.Is(err, redis.Nil) {
			return r.wrap(err)
		}
	}
	for i := range b.ops {
		if err := setResult(&b.ops[i], reads[i]); err != nil {
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

// queue adds the commands for o to pipe and returns the one whose reply fills
// o's result, or nil for writes.
func (r *Redis) queue(ctx context.Context, pipe redis.Pipeliner, o *op) redis.Cmder {
	switch o.kind {
	case opIncr:
		k := r.bucketKey("c:", o.key, o.span, floorDiv(o.at, bucketWidth(o.span)))
		pipe.IncrBy(ctx, k, o.n)
		pipe.PExpire(ctx, k, bucketTTL(o.span))

	case opCount:
		return pipe.MGet(ctx, r.windowKeys("c:", o.key, o.span, o.at)...)

	case opAddDistinct:
		k := r.bucketKey("d:", o.key, o.span, floorDiv(o.at, bucketWidth(o.span)))
		pipe.PFAdd(ctx, k, o.member)
		pipe.PExpire(ctx, k, bucketTTL(o.span))

	case opDistinct:
		return pipe.PFCount(ctx, r.windowKeys("d:", o.key, o.span, o.at)...)

	case opMarkSeen:
		k := r.prefix + "s:" + o.key
		ms := unixMilli(o.at)
		pipe.ZAddGT(ctx, k, redis.Z{Score: float64(ms), Member: o.member})
		pipe.ZRemRangeByScore(ctx, k, "-inf", strconv.FormatInt(ms-o.span.Milliseconds(), 10))
		pipe.PExpire(ctx, k, o.span)

	case opSeenWithin:
		return pipe.ZScore(ctx, r.prefix+"s:"+o.key, o.member)

	case opFirstSeen:
		// A sorted set with one member, because ZADD LT is the only command
		// that keeps the smaller of two values without a script.
		k := r.prefix + "f:" + o.key
		pipe.ZAddLT(ctx, k, redis.Z{Score: float64(unixMilli(o.at)), Member: "t"})
		if o.span > 0 {
			pipe.PExpire(ctx, k, o.span)
		} else {
			pipe.Persist(ctx, k)
		}
		return pipe.ZScore(ctx, k, "t")

	case opSet:
		pipe.Set(ctx, r.prefix+"v:"+o.key, o.member, o.span)

	case opGet:
		return pipe.Get(ctx, r.prefix+"v:"+o.key)
	}
	return nil
}

// setResult sets o's result from the reply of cmd.
func setResult(o *op, cmd redis.Cmder) error {
	switch o.kind {
	case opCount:
		var sum int64
		for _, v := range cmd.(*redis.SliceCmd).Val() {
			s, ok := v.(string)
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("counter %q holds %q", o.key, s)
			}
			sum += n
		}
		o.ints.val = sum

	case opDistinct:
		o.ints.val = cmd.(*redis.IntCmd).Val()

	case opSeenWithin:
		c := cmd.(*redis.FloatCmd)
		o.bools.val = c.Err() == nil && unixMilli(o.at)-int64(c.Val()) < o.span.Milliseconds()

	case opFirstSeen:
		o.times.ms = int64(cmd.(*redis.FloatCmd).Val())

	case opGet:
		c := cmd.(*redis.StringCmd)
		o.strs.val, o.strs.found = c.Val(), c.Err() == nil
	}
	return nil
}

func (r *Redis) bucketKey(kind, key string, w time.Duration, idx int64) string {
	return r.seriesPrefix(kind, key, w) + strconv.FormatInt(idx, 10)
}

func (r *Redis) seriesPrefix(kind, key string, w time.Duration) string {
	return r.prefix + kind + "{" + key + "}:" + w.String() + ":"
}

// windowKeys returns the keys of the buckets of the window of w that ends at
// at, Unix ns. The keys are slices of one string, built in one buffer: a
// batch reads thousands of them, and one allocation each adds up.
func (r *Redis) windowKeys(kind, key string, w time.Duration, at int64) []string {
	base := r.seriesPrefix(kind, key, w)
	first := floorDiv(at, bucketWidth(w)) - Buckets + 1
	var (
		ends    [Buckets]int
		digits  [20]byte
		builder strings.Builder
	)
	builder.Grow(Buckets * (len(base) + len(strconv.AppendInt(digits[:0], first, 10))))
	for i := range Buckets {
		builder.WriteString(base)
		builder.Write(strconv.AppendInt(digits[:0], first+int64(i), 10))
		ends[i] = builder.Len()
	}
	all := builder.String()
	keys := make([]string, Buckets)
	start := 0
	for i, end := range ends {
		keys[i] = all[start:end]
		start = end
	}
	return keys
}
