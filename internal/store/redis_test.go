package store

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

func newTestRedis(t *testing.T, prefix string) (*Redis, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := storetest.Miniredis(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { client.Close() })
	return NewRedis(client, RedisOptions{Prefix: prefix}), mr, client
}

func TestRedisKeysAndTTLs(t *testing.T) {
	s, mr, _ := newTestRedis(t, "app:")
	run(t, s, func(b *Batch) {
		b.Incr("acct", time.Hour, t0, 1)
		b.AddDistinct("acct", "x", 24*time.Hour, t0)
		b.MarkSeen("acct", "1.2.3.4", t0, 30*24*time.Hour)
		b.FirstSeen("acct", t0, 365*24*time.Hour)
		b.FirstSeen("forever", t0, 0)
		b.Set("acct", "v", time.Minute)
		b.Set("forever", "v", 0)
	})
	hourBucket := t0.Unix() / 60
	dayBucket := t0.Unix() / (24 * 60)
	want := map[string]time.Duration{
		"app:c:{acct}:1h0m0s":                        time.Hour + time.Minute,
		"app:d:{acct}:24h0m0s:" + itoa(dayBucket):    24*time.Hour + 24*time.Minute,
		"app:d:{acct}:24h0m0s:b" + itoa(dayBucket/6): 24*time.Hour + 24*time.Minute,
		"app:s:acct":    30 * 24 * time.Hour,
		"app:f:acct":    365 * 24 * time.Hour,
		"app:f:forever": 0,
		"app:v:acct":    time.Minute,
		"app:v:forever": 0,
	}
	keys := mr.Keys()
	for k, ttl := range want {
		if !slices.Contains(keys, k) {
			t.Errorf("missing key %s; have %v", k, keys)
			continue
		}
		if got := mr.TTL(k); got != ttl {
			t.Errorf("TTL(%s) = %v, want %v", k, got, ttl)
		}
	}
	if len(keys) != len(want) {
		t.Errorf("keys = %v, want %d of them", keys, len(want))
	}
	fields, err := mr.HKeys("app:c:{acct}:1h0m0s")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(fields)
	if want := []string{itoa(hourBucket), "n", "s"}; !slices.Equal(fields, want) {
		t.Errorf("counter fields = %v, want %v", fields, want)
	}
}

func TestRedisDefaultPrefix(t *testing.T) {
	s, mr, _ := newTestRedis(t, "")
	run(t, s, func(b *Batch) { b.Set("k", "v", 0) })
	if keys := mr.Keys(); len(keys) != 1 || keys[0] != DefaultPrefix+"v:k" {
		t.Errorf("keys = %v, want [%sv:k]", keys, DefaultPrefix)
	}
}

func TestRedisKeysOfAnOperationShareAHashTag(t *testing.T) {
	r := NewRedis(nil, RedisOptions{})
	for _, key := range []string{"plain", "with}brace", "with{brace", "{tagged}"} {
		for _, o := range []op{
			{kind: opIncr, key: key, span: time.Hour, at: t0.UnixNano()},
			{kind: opAddDistinct, key: key, span: time.Hour, at: t0.UnixNano()},
			{kind: opDistinct, key: key, span: time.Hour, at: t0.Add(17 * time.Minute).UnixNano()},
		} {
			keys := r.keys(&o)
			tag := hashTag(keys[0])
			for _, k := range keys {
				if hashTag(k) != tag {
					t.Errorf("%q: %s and %s are in different slots", key, keys[0], k)
					break
				}
			}
		}
	}
}

func TestHashTag(t *testing.T) {
	for key, want := range map[string]string{
		"plain":        "plain",
		"a{b}c":        "b",
		"a{b}c{d}":     "b",
		"a{}b{c}":      "a{}b{c}",
		"a{b":          "a{b",
		"a}b{c}":       "c",
		"c:{x}y}:1h":   "x",
		"{{tagged}}":   "{tagged",
		"p:c:{k}:1h0m": "k",
	} {
		if got := hashTag(key); got != want {
			t.Errorf("hashTag(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestDistinctKeysCoverTheWindow checks that the blocks and buckets a
// distinct count merges cover each bucket of the window exactly once, and
// nothing else, for every alignment of the window to the blocks.
func TestDistinctKeysCoverTheWindow(t *testing.T) {
	r := NewRedis(nil, RedisOptions{Prefix: "p:"})
	w := time.Hour
	base := "p:d:{k}:1h0m0s:"
	for shift := range 2 * distinctBlock {
		for _, origin := range []time.Time{t0, time.Unix(-3_600_000, 0)} {
			at := origin.Add(time.Duration(shift)*time.Minute + 30*time.Second)
			last := floorDiv(at.UnixNano(), bucketWidth(w))
			covered := make(map[int64]int)
			keys := r.distinctKeys("k", w, at.UnixNano())
			for _, k := range keys {
				rest, ok := strings.CutPrefix(k, base)
				if !ok {
					t.Fatalf("key %s lacks prefix %s", k, base)
				}
				if blk, ok := strings.CutPrefix(rest, "b"); ok {
					n, err := strconv.ParseInt(blk, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					for idx := n * distinctBlock; idx < (n+1)*distinctBlock; idx++ {
						covered[idx]++
					}
					continue
				}
				n, err := strconv.ParseInt(rest, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				covered[n]++
			}
			if len(covered) != Buckets {
				t.Errorf("at %v: %d buckets covered, want %d", at, len(covered), Buckets)
			}
			for idx := last - Buckets + 1; idx <= last; idx++ {
				if covered[idx] != 1 {
					t.Errorf("at %v: bucket %d covered %d times", at, idx, covered[idx])
				}
			}
			if len(keys) > 15 {
				t.Errorf("at %v: %d keys, want at most 15", at, len(keys))
			}
		}
	}
}

type countingHook struct{ commands, pipelines atomic.Int32 }

func (h *countingHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *countingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.commands.Add(1)
		return next(ctx, cmd)
	}
}

func (h *countingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		h.pipelines.Add(1)
		return next(ctx, cmds)
	}
}

func TestRedisBatchIsOneRoundTrip(t *testing.T) {
	s, _, client := newTestRedis(t, "")
	hook := new(countingHook)
	client.AddHook(hook)
	// The first use of a connection sends its handshake through the hooks,
	// and the first batch loads the script.
	run(t, s, func(b *Batch) { b.Get("warm-up") })
	hook.commands.Store(0)
	hook.pipelines.Store(0)
	run(t, s, func(b *Batch) {
		for _, w := range []time.Duration{time.Minute, time.Hour, 24 * time.Hour, week} {
			b.Incr("k", w, t0, 1)
			b.Count("k", w, t0)
			b.AddDistinct("k", "m", w, t0)
			b.Distinct("k", w, t0)
		}
		b.SeenWithin("k", "m", time.Hour, t0)
		b.MarkSeen("k", "m", t0, time.Hour)
		b.FirstSeen("k", t0, time.Hour)
		b.Set("k", "v", 0)
		b.Get("k")
		b.Get("missing")
	})
	if p, c := hook.pipelines.Load(), hook.commands.Load(); p+c != 1 {
		t.Errorf("Do sent %d pipelines and %d single commands, want one round trip", p, c)
	}
}

func TestRedisClusterBatchIsOnePipeline(t *testing.T) {
	mr := storetest.Miniredis(t)
	client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{mr.Addr()}, MaxRetries: -1})
	t.Cleanup(func() { client.Close() })
	s := NewRedis(client, RedisOptions{})
	run(t, s, func(b *Batch) { b.Get("warm-up") })
	hook := new(countingHook)
	client.AddHook(hook)
	var counts []*IntResult
	run(t, s, func(b *Batch) {
		for _, key := range []string{"a", "b", "c"} {
			b.Incr(key, time.Hour, t0, 1)
			counts = append(counts, b.Count(key, time.Hour, t0))
			b.Set(key, "v", 0)
		}
	})
	if p, c := hook.pipelines.Load(), hook.commands.Load(); p != 1 || c != 0 {
		t.Errorf("Do sent %d pipelines and %d single commands, want 1 and 0", p, c)
	}
	for i, r := range counts {
		if r.Val() != 1 {
			t.Errorf("count %d = %d, want 1", i, r.Val())
		}
	}
}

// TestRedisReloadsAFlushedScript checks the NOSCRIPT fallback: after SCRIPT
// FLUSH each batch still runs exactly once, with reads in batch order.
func TestRedisReloadsAFlushedScript(t *testing.T) {
	for _, be := range []struct {
		name string
		new  func(t *testing.T) (*Redis, redis.UniversalClient)
	}{
		{"single", func(t *testing.T) (*Redis, redis.UniversalClient) {
			s, _, client := newTestRedis(t, "")
			return s, client
		}},
		{"cluster", func(t *testing.T) (*Redis, redis.UniversalClient) {
			mr := storetest.Miniredis(t)
			client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{mr.Addr()}, MaxRetries: -1})
			t.Cleanup(func() { client.Close() })
			return NewRedis(client, RedisOptions{}), client
		}},
	} {
		t.Run(be.name, func(t *testing.T) {
			s, client := be.new(t)
			for i := range 3 {
				if err := client.ScriptFlush(context.Background()).Err(); err != nil {
					t.Fatal(err)
				}
				var before, after *IntResult
				run(t, s, func(b *Batch) {
					before = b.Count("k", time.Hour, t0)
					b.Incr("k", time.Hour, t0, 1)
					b.Incr("other", time.Hour, t0, 1)
					after = b.Count("k", time.Hour, t0)
				})
				if before.Val() != int64(i) || after.Val() != int64(i+1) {
					t.Errorf("batch %d after SCRIPT FLUSH: counts %d and %d, want %d and %d", i, before.Val(), after.Val(), i, i+1)
				}
			}
		})
	}
}

// TestRedisReturnsAtTheDeadline checks that Do gives up when its context
// does, while Redis is slow to answer, and that the round trip it abandoned
// still completes on its connection.
func TestRedisReturnsAtTheDeadline(t *testing.T) {
	s, mr, _ := newTestRedis(t, "")
	run(t, s, func(b *Batch) { b.Get("warm-up") })

	var slow atomic.Bool
	mr.Server().SetPreHook(func(c *server.Peer, cmd string, args ...string) bool {
		if slow.CompareAndSwap(true, false) {
			time.Sleep(300 * time.Millisecond)
		}
		return false
	})
	slow.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var b Batch
	b.Incr("k", time.Hour, t0, 1)
	start := time.Now()
	err := s.Do(ctx, &b)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Do = %v, want a deadline error", err)
	}
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("Do took %v, want about the 20ms deadline", took)
	}
	for count(t, s, "k", time.Hour, t0) != 1 {
		if time.Since(start) > 5*time.Second {
			t.Fatal("the abandoned write never applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOpenRedis(t *testing.T) {
	mr := storetest.Miniredis(t)
	s, err := OpenRedis("redis://"+mr.Addr()+"/0", RedisOptions{Prefix: "x:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	run(t, s, func(b *Batch) { b.Set("k", "v", 0) })
	if v, _ := mr.Get("x:v:k"); v != "v" {
		t.Errorf("value = %q, want v", v)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var b Batch
	b.Get("k")
	if err := s.Do(context.Background(), &b); !errors.Is(err, ErrClosed) {
		t.Errorf("Do after Close = %v, want ErrClosed", err)
	}

	if _, err := OpenRedis("http://localhost", RedisOptions{}); err == nil {
		t.Error("OpenRedis accepted an http url")
	}
}

// TestOpenRedisModes checks the client each mode opens and that none of them
// retries: go-redis reports MaxRetries -1 as 0 once some clients are built.
func TestOpenRedisModes(t *testing.T) {
	mr := storetest.Miniredis(t)
	for _, tt := range []struct {
		mode, url string
		single    bool
		retries   func(redis.UniversalClient) int
	}{
		{"", "redis://" + mr.Addr() + "/0?pool_size=7&read_timeout=500ms&dial_timeout=1s", true,
			func(c redis.UniversalClient) int { return c.(*redis.Client).Options().MaxRetries }},
		{RedisSentinel, "redis://localhost:26379/0?master_name=primary&addr=localhost:26380", true,
			func(c redis.UniversalClient) int { return c.(*redis.Client).Options().MaxRetries }},
		{RedisCluster, "redis://" + mr.Addr(), false,
			func(c redis.UniversalClient) int { return c.(*redis.ClusterClient).Options().MaxRetries }},
	} {
		s, err := OpenRedis(tt.url, RedisOptions{Mode: tt.mode})
		if err != nil {
			t.Fatalf("mode %q: %v", tt.mode, err)
		}
		if s.single != tt.single {
			t.Errorf("mode %q: single = %t, want %t", tt.mode, s.single, tt.single)
		}
		if n := tt.retries(s.client); n > 0 {
			t.Errorf("mode %q: the client retries %d times, want none", tt.mode, n)
		}
		if tt.mode == "" {
			if o := s.client.(*redis.Client).Options(); o.PoolSize != 7 || o.ReadTimeout != 500*time.Millisecond || o.DialTimeout != time.Second {
				t.Errorf("query parameters not applied: pool %d, read %v, dial %v", o.PoolSize, o.ReadTimeout, o.DialTimeout)
			}
		}
		if tt.mode != RedisSentinel {
			run(t, s, func(b *Batch) { b.Set("mode-"+tt.mode, "v", 0) })
		}
		s.Close()
	}
}

func TestCheckRedisURL(t *testing.T) {
	for _, tt := range []struct {
		url, mode, want string
	}{
		{"redis://localhost:6379/0", "", ""},
		{"rediss://localhost:6379/0", RedisStandalone, ""},
		{"unix:///run/redis.sock", RedisStandalone, ""},
		{"redis://localhost:26379?master_name=p", RedisSentinel, ""},
		{"redis://localhost:7000?addr=localhost:7001", RedisCluster, ""},
		{"redis://localhost:6379?max_retries=3", "", "max_retries is not supported"},
		{"redis://localhost:7000?max_retries=-1", RedisCluster, "max_retries is not supported"},
		{"redis://localhost:6379?pool_sise=10", "", "unexpected option: pool_sise"},
		{"redis://localhost:26379", RedisSentinel, "sentinel mode needs master_name"},
		{"unix:///run/redis.sock", RedisCluster, "invalid URL scheme: unix"},
		{"redis://localhost:6379", "ring", `redis mode "ring": want standalone, sentinel or cluster`},
		{"redis://:hunter2@local host:6379", "", "not a valid URL"},
	} {
		err := CheckRedisURL(tt.url, tt.mode)
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s (%q): %v", tt.url, tt.mode, err)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s (%q): error = %v, want %q", tt.url, tt.mode, err, tt.want)
		case err != nil && strings.Contains(err.Error(), "hunter2"):
			t.Errorf("%s: the error repeats the password: %v", tt.url, err)
		}
	}
}

// TestOpenRedisDoesNotResendScripts checks that a script call whose reply is
// lost after Redis ran it fails instead of running again. With go-redis's
// default of three retries the client would resend it on the EOF and count
// the event twice.
func TestOpenRedisDoesNotResendScripts(t *testing.T) {
	mr := storetest.Miniredis(t)
	proxy := newReplyDropper(t, mr.Addr())
	s, err := OpenRedis("redis://"+proxy.addr+"/0", RedisOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Loads the script, so the next batch is a single EVALSHA.
	run(t, s, func(b *Batch) { b.Get("warm-up") })

	proxy.drop.Store(true)
	var b Batch
	b.Incr("k", time.Hour, t0, 1)
	if err := s.Do(context.Background(), &b); err == nil {
		t.Fatal("Do succeeded although the reply was lost")
	}
	direct := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1}), RedisOptions{})
	defer direct.client.Close()
	if n := count(t, direct, "k", time.Hour, t0); n != 1 {
		t.Errorf("count = %d after one increment, want 1: the script ran again", n)
	}
}

// replyDropper forwards connections to a Redis server. While drop is set, it
// forwards the next script call and then closes the client's connection
// instead of passing back the reply: Redis ran the script, the client sees
// EOF.
type replyDropper struct {
	addr string
	drop atomic.Bool
}

func newReplyDropper(t *testing.T, target string) *replyDropper {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &replyDropper{addr: ln.Addr().String()}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go p.forward(client, target)
		}
	}()
	return p
}

func (p *replyDropper) forward(client net.Conn, target string) {
	defer client.Close()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()
	var dropping atomic.Bool
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := client.Read(buf)
			if err != nil {
				server.Close()
				return
			}
			if p.drop.Load() && bytes.Contains(bytes.ToUpper(buf[:n]), []byte("EVALSHA")) {
				p.drop.Store(false)
				dropping.Store(true)
			}
			if _, err := server.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if dropping.Load() {
			return
		}
		if _, err := client.Write(buf[:n]); err != nil {
			return
		}
	}
}

func TestNewRedisLeavesTheClientOpen(t *testing.T) {
	s, _, client := newTestRedis(t, "")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Errorf("client closed by the store: %v", err)
	}
}

func TestRedisErrors(t *testing.T) {
	t.Run("server error", func(t *testing.T) {
		s, mr, _ := newTestRedis(t, "")
		mr.SetError("LOADING Redis is loading the dataset in memory")
		var b Batch
		b.Count("k", time.Hour, t0)
		if err := s.Do(context.Background(), &b); err == nil || !strings.Contains(err.Error(), "LOADING") {
			t.Errorf("Do = %v, want the server's error", err)
		}
	})
	t.Run("not a counter", func(t *testing.T) {
		s, mr, _ := newTestRedis(t, "")
		mr.HSet("catraca:c:{k}:1h0m0s", "n", itoa(t0.Unix()/60), "s", "abc")
		var b Batch
		b.Count("k", time.Hour, t0)
		if err := s.Do(context.Background(), &b); err == nil || !strings.Contains(err.Error(), `"abc"`) {
			t.Errorf("Do = %v, want an error about the bad value", err)
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		s, mr, _ := newTestRedis(t, "")
		mr.Set("catraca:s:k", "a string")
		var b Batch
		b.MarkSeen("k", "m", t0, time.Hour)
		if err := s.Do(context.Background(), &b); err == nil || !strings.Contains(err.Error(), "WRONGTYPE") {
			t.Errorf("Do = %v, want WRONGTYPE", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		mr := storetest.Miniredis(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialerRetries: 1})
		defer client.Close()
		s := NewRedis(client, RedisOptions{})
		mr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var b Batch
		b.Incr("k", time.Hour, t0, 1)
		if err := s.Do(ctx, &b); err == nil {
			t.Error("Do succeeded with the server down")
		}
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
