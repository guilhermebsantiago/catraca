package store

import (
	"context"
	"crypto/rand"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// The contract suite runs against a real Redis server when
// CATRACA_TEST_REDIS_URL is set, for example to redis://localhost:6379/0.
// miniredis only approximates some commands (storetest patches PFCOUNT over
// several keys, which it sums instead of counting their union), so this is
// the run that shows the Redis store works against the real thing. Each test
// writes under its own key prefix and deletes its keys when it ends, so the
// server can be shared.

const redisServerEnv = "CATRACA_TEST_REDIS_URL"

func redisServerSkip() string {
	if os.Getenv(redisServerEnv) == "" {
		return "set " + redisServerEnv + " to run the contract suite against a Redis server"
	}
	return ""
}

func newRedisServerBackend(t *testing.T) backend {
	t.Helper()
	opts, err := redis.ParseURL(os.Getenv(redisServerEnv))
	if err != nil {
		t.Fatalf("%s: %v", redisServerEnv, err)
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		t.Fatalf("%s is set but Redis does not answer: %v", redisServerEnv, err)
	}

	// The prefix is letters and digits after a fixed part, so it is also a
	// literal SCAN pattern.
	prefix := "catraca-test:" + rand.Text() + ":"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, k := range scanKeys(t, ctx, client, prefix) {
			if err := client.Del(ctx, k).Err(); err != nil {
				t.Errorf("clean up %s: %v", k, err)
			}
		}
		client.Close()
	})
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
	for _, k := range scanKeys(t, ctx, client, prefix) {
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

// scanKeys returns the keys under prefix, each once: SCAN may return a key
// more than once, and fastForward must not shorten a time to live twice.
func scanKeys(t *testing.T, ctx context.Context, client *redis.Client, prefix string) []string {
	t.Helper()
	var keys []string
	iter := client.Scan(ctx, 0, prefix+"*", 500).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("SCAN %s*: %v", prefix, err)
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}
