package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisLogEvery limits how often go-redis's own lines are logged.
const redisLogEvery = time.Second

var (
	redisLog     atomic.Pointer[slog.Logger]
	redisLogOnce sync.Once
	redisLogLast atomic.Int64
	redisDropped atomic.Int64
)

// SetRedisLogger sends go-redis's own log lines, such as a connection pool
// that failed to dial, to log as warnings, at most one a second; the next
// line through carries how many were suppressed. Without it go-redis prints
// unstructured lines to stderr, dozens a second while Redis is down.
// go-redis has a single logger per process: the last logger set wins, and a
// nil log discards the lines. It is safe to call concurrently.
func SetRedisLogger(log *slog.Logger) {
	redisLog.Store(log)
	redisLogOnce.Do(func() { redis.SetLogger(redisLogger{}) })
}

// redisLogger is the go-redis logger SetRedisLogger installs.
type redisLogger struct{}

func (redisLogger) Printf(ctx context.Context, format string, v ...any) {
	log := redisLog.Load()
	if log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := redisLogLast.Load()
	if now-last < int64(redisLogEvery) || !redisLogLast.CompareAndSwap(last, now) {
		redisDropped.Add(1)
		return
	}
	msg := strings.TrimPrefix(fmt.Sprintf(format, v...), "redis: ")
	log.WarnContext(ctx, "redis client: "+msg, "suppressed", redisDropped.Swap(0))
}
