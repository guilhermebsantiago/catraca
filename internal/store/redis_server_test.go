package store

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

// The contract suite runs against a real Redis server when
// CATRACA_TEST_REDIS_URL is set, for example to redis://localhost:6379/0.
// miniredis only approximates some commands (storetest patches PFCOUNT over
// several keys, which it sums instead of counting their union), so this is
// the run that shows the Redis store works against the real thing. Each test
// writes under its own key prefix and deletes its keys when it ends, so the
// server can be shared.

func redisServerSkip() string { return storetest.RedisServerSkip() }

func newRedisServerBackend(t *testing.T) backend {
	t.Helper()
	client, prefix := storetest.RedisServer(t)
	return backend{
		Store:   NewRedis(client, RedisOptions{Prefix: prefix}),
		advance: func(d time.Duration) { fastForward(t, client, prefix, d) },
	}
}

// fastForward does to the keys under prefix what miniredis.FastForward does
// to a whole server: Redis cannot move its clock, so each time to live is
// shortened by d instead, and keys whose time to live runs out are deleted.
// Keys without a time to live are left alone.
func fastForward(t *testing.T, client *redis.Client, prefix string, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// ScanKeys returns each key once, so no time to live is shortened twice.
	for _, k := range storetest.ScanKeys(t, ctx, client, prefix) {
		ttl, err := client.PTTL(ctx, k).Result()
		if err != nil {
			t.Fatalf("PTTL %s: %v", k, err)
		}
		switch {
		case ttl < 0:
			// -1: no time to live; -2: the key expired since the scan.
		case ttl <= d:
			err = client.Del(ctx, k).Err()
		default:
			err = client.PExpire(ctx, k, ttl-d).Err()
		}
		if err != nil {
			t.Fatalf("fast forward %s: %v", k, err)
		}
	}
}
