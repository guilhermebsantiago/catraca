package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// syncBuffer is a bytes.Buffer safe for the pool's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for line := range strings.Lines(s.b.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %q is not JSON: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// failDials makes n calls that each fail to dial, on a client of its own.
func failDials(t *testing.T, n int) {
	t.Helper()
	client := redis.NewClient(&redis.Options{
		Addr:          "127.0.0.1:1",
		MaxRetries:    -1,
		PoolSize:      n,
		DialerRetries: 1,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	})
	defer client.Close()
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := client.Ping(context.Background()).Err(); err == nil {
				t.Error("ping: want a dial error")
			}
		})
	}
	wg.Wait()
}

func TestRedisLoggerIsStructuredAndLimited(t *testing.T) {
	var buf syncBuffer
	SetRedisLogger(slog.New(slog.NewJSONHandler(&buf, nil)).With("component", "redis"))
	t.Cleanup(func() { SetRedisLogger(nil) })
	redisLogLast.Store(0)
	redisDropped.Store(0)

	failDials(t, 40)
	lines := buf.lines(t)
	if len(lines) != 1 {
		t.Fatalf("40 failed dials logged %d lines, want 1: %v", len(lines), lines)
	}
	first := lines[0]
	if first["level"] != "WARN" || first["component"] != "redis" ||
		!strings.Contains(first["msg"].(string), "redis client: connection pool: failed to dial") {
		t.Errorf("first line = %v", first)
	}
	if strings.Contains(first["msg"].(string), "redis: ") {
		t.Errorf("msg keeps go-redis's own prefix: %q", first["msg"])
	}

	time.Sleep(redisLogEvery + 50*time.Millisecond)
	failDials(t, 1)
	lines = buf.lines(t)
	if len(lines) != 2 {
		t.Fatalf("after a second, %d lines, want 2: %v", len(lines), lines)
	}
	// A line counts the lines suppressed before it, some of them racing
	// the first one, so the two lines together count the other 39.
	if got := first["suppressed"].(float64) + lines[1]["suppressed"].(float64); got != 39 {
		t.Errorf("suppressed %v + %v, want 39 in all", first["suppressed"], lines[1]["suppressed"])
	}

	SetRedisLogger(nil)
	time.Sleep(redisLogEvery + 50*time.Millisecond)
	failDials(t, 1)
	if n := len(buf.lines(t)); n != 2 {
		t.Errorf("a nil logger let a line through: %d lines", n)
	}
}
