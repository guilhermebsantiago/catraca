package storetest

import (
	"context"
	"crypto/rand"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisURLEnv names the environment variable that points tests at a real
// Redis server, for example redis://localhost:6379/0.
const RedisURLEnv = "CATRACA_TEST_REDIS_URL"

// RedisServerSkip returns why tests cannot use a real Redis server, or ""
// when RedisURLEnv is set.
func RedisServerSkip() string {
	if os.Getenv(RedisURLEnv) == "" {
		return "set " + RedisURLEnv + " to run against a Redis server"
	}
	return ""
}

// RedisServer connects to the server at RedisURLEnv and returns a client and
// a key prefix of its own, so tests can share the server. When the test ends,
// every key under the prefix is deleted and the client is closed. The prefix
// is letters and digits after a fixed part, so it is also a literal SCAN
// pattern.
func RedisServer(tb testing.TB) (*redis.Client, string) {
	tb.Helper()
	opts, err := redis.ParseURL(os.Getenv(RedisURLEnv))
	if err != nil {
		tb.Fatalf("%s: %v", RedisURLEnv, err)
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		tb.Fatalf("%s is set but Redis does not answer: %v", RedisURLEnv, err)
	}
	prefix := "catraca-test:" + rand.Text() + ":"
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		keys := ScanKeys(tb, ctx, client, prefix)
		for len(keys) > 0 {
			n := min(len(keys), 500)
			if err := client.Unlink(ctx, keys[:n]...).Err(); err != nil {
				tb.Errorf("clean up %s*: %v", prefix, err)
				break
			}
			keys = keys[n:]
		}
		client.Close()
	})
	return client, prefix
}

// ScanKeys returns the keys under prefix, each once: SCAN may return a key
// more than once.
func ScanKeys(tb testing.TB, ctx context.Context, client *redis.Client, prefix string) []string {
	tb.Helper()
	var keys []string
	iter := client.Scan(ctx, 0, prefix+"*", 1000).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		tb.Fatalf("SCAN %s*: %v", prefix, err)
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}
