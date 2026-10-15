package storetest

import (
	"context"
	"crypto/rand"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisURLEnv names the environment variable that points tests at a real
// Redis server, for example redis://localhost:6379/0.
const RedisURLEnv = "CATRACA_TEST_REDIS_URL"

// RedisClusterEnv names the environment variable that points tests at a
// real Redis Cluster: the addresses of some of its nodes, separated by
// commas, for example localhost:7001,localhost:7002.
const RedisClusterEnv = "CATRACA_TEST_REDIS_CLUSTER"

// RedisServerSkip returns why tests cannot use a real Redis server, or ""
// when RedisURLEnv is set.
func RedisServerSkip() string {
	if os.Getenv(RedisURLEnv) == "" {
		return "set " + RedisURLEnv + " to run against a Redis server"
	}
	return ""
}

// RedisClusterSkip returns why tests cannot use a real Redis Cluster, or ""
// when RedisClusterEnv is set.
func RedisClusterSkip() string {
	if os.Getenv(RedisClusterEnv) == "" {
		return "set " + RedisClusterEnv + " to run against a Redis Cluster"
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
	return client, connect(tb, client, RedisURLEnv)
}

// RedisCluster is RedisServer for the cluster at RedisClusterEnv.
func RedisCluster(tb testing.TB) (*redis.ClusterClient, string) {
	tb.Helper()
	client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: strings.Split(os.Getenv(RedisClusterEnv), ",")})
	return client, connect(tb, client, RedisClusterEnv)
}

// connect checks that client answers, picks a prefix and cleans up under it
// when the test ends.
func connect(tb testing.TB, client redis.UniversalClient, env string) string {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		tb.Fatalf("%s is set but Redis does not answer: %v", env, err)
	}
	prefix := "catraca-test:" + rand.Text() + ":"
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		// One key per command, so a cluster client routes each to its node.
		for _, k := range ScanKeys(tb, ctx, client, prefix) {
			if err := client.Unlink(ctx, k).Err(); err != nil {
				tb.Errorf("clean up %s: %v", k, err)
				break
			}
		}
		client.Close()
	})
	return prefix
}

// ScanKeys returns the keys under prefix, on every primary of a cluster, each
// once: SCAN may return a key more than once.
func ScanKeys(tb testing.TB, ctx context.Context, client redis.UniversalClient, prefix string) []string {
	tb.Helper()
	var (
		mu   sync.Mutex
		keys []string
	)
	scan := func(ctx context.Context, node redis.Cmdable) error {
		iter := node.Scan(ctx, 0, prefix+"*", 1000).Iterator()
		for iter.Next(ctx) {
			mu.Lock()
			keys = append(keys, iter.Val())
			mu.Unlock()
		}
		return iter.Err()
	}
	var err error
	if c, ok := client.(*redis.ClusterClient); ok {
		err = c.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error { return scan(ctx, node) })
	} else {
		err = scan(ctx, client)
	}
	if err != nil {
		tb.Fatalf("SCAN %s*: %v", prefix, err)
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}
