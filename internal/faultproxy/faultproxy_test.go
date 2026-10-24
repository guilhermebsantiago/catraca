package faultproxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// lineServer answers each line it reads with "ok " and the line, and counts
// the lines it acted on.
type lineServer struct {
	addr    string
	applied atomic.Int32
}

func newLineServer(t *testing.T) *lineServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &lineServer{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					s.applied.Add(1)
					if _, err := io.WriteString(c, "ok "+line); err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

// client is a connection through the proxy that sends a line and reads
// the answer.
type client struct {
	t  *testing.T
	nc net.Conn
	r  *bufio.Reader
}

func dial(t *testing.T, p *Proxy) *client {
	t.Helper()
	nc, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	return &client{t: t, nc: nc, r: bufio.NewReader(nc)}
}

// call sends line and returns the answer, or the error that came instead
// within timeout.
func (c *client) call(line string, timeout time.Duration) (string, error) {
	c.t.Helper()
	if err := c.nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		c.t.Fatal(err)
	}
	if _, err := io.WriteString(c.nc, line+"\n"); err != nil {
		return "", err
	}
	s, err := c.r.ReadString('\n')
	return strings.TrimSuffix(s, "\n"), err
}

func (c *client) mustCall(line string) {
	c.t.Helper()
	got, err := c.call(line, 5*time.Second)
	if err != nil || got != "ok "+line {
		c.t.Fatalf("call %q: %q, %v", line, got, err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestForwards(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	c := dial(t, p)
	for _, line := range []string{"a", "b", strings.Repeat("x", 100<<10)} {
		c.mustCall(line)
	}
	if n := p.Conns(); n != 1 {
		t.Errorf("Conns = %d, want 1", n)
	}
}

func TestLatency(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	c := dial(t, p)
	c.mustCall("warm")

	p.SetLatency(300*time.Millisecond, 100*time.Millisecond)
	for range 3 {
		start := time.Now()
		c.mustCall("slow")
		if took := time.Since(start); took < 200*time.Millisecond {
			t.Errorf("a call took %s with 300ms ± 100ms of latency", took)
		}
	}
	p.SetLatency(0, 0)
	start := time.Now()
	c.mustCall("fast")
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Errorf("a call took %s with the latency off", took)
	}
}

// TestLatencyKeepsOrder sends several lines at once under jitter as large
// as the latency: the answers arrive in order.
func TestLatencyKeepsOrder(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	p.SetLatency(20*time.Millisecond, 20*time.Millisecond)
	c := dial(t, p)
	var sent strings.Builder
	for i := range 50 {
		sent.WriteString(strings.Repeat("y", i) + "\n")
	}
	if _, err := io.WriteString(c.nc, sent.String()); err != nil {
		t.Fatal(err)
	}
	c.nc.SetDeadline(time.Now().Add(10 * time.Second))
	for i := range 50 {
		got, err := c.r.ReadString('\n')
		if want := "ok " + strings.Repeat("y", i) + "\n"; err != nil || got != want {
			t.Fatalf("answer %d: %q, %v; want %q", i, got, err, want)
		}
	}
}

func TestBandwidth(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	c := dial(t, p)
	c.mustCall("warm")

	// 4 KiB out and 4 KiB back at 16 KiB/s take half a second.
	p.SetBandwidth(16 << 10)
	start := time.Now()
	c.mustCall(strings.Repeat("z", 4<<10))
	if took := time.Since(start); took < 400*time.Millisecond {
		t.Errorf("8 KiB at 16 KiB/s took %s", took)
	}
	p.SetBandwidth(0)
	start = time.Now()
	c.mustCall(strings.Repeat("z", 4<<10))
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("8 KiB without a limit took %s", took)
	}
}

func TestBlackhole(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	idle := dial(t, p)
	idle.mustCall("before")
	busy := dial(t, p)
	busy.mustCall("before")

	p.SetBlackhole(true)
	// A new connection is accepted, and never answered.
	fresh := dial(t, p)
	if got, err := fresh.call("lost", 300*time.Millisecond); !isTimeout(err) {
		t.Errorf("new connection in the blackhole: %q, %v; want a timeout", got, err)
	}
	if got, err := busy.call("lost", 300*time.Millisecond); !isTimeout(err) {
		t.Errorf("open connection in the blackhole: %q, %v; want a timeout", got, err)
	}
	applied := s.applied.Load()

	p.SetBlackhole(false)
	// The connections that lost bytes stay lost; the idle one and new ones
	// work again.
	for name, c := range map[string]*client{"new in the blackhole": fresh, "busy in the blackhole": busy} {
		if got, err := c.call("after", 300*time.Millisecond); !isTimeout(err) {
			t.Errorf("%s, after: %q, %v; want a timeout", name, got, err)
		}
	}
	idle.mustCall("after")
	dial(t, p).mustCall("after")
	if got := s.applied.Load(); got != applied+2 {
		t.Errorf("the server got %d lines after the blackhole, want 2: the blackhole let some through", got-applied)
	}
}

func TestRefuse(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	open := dial(t, p)
	open.mustCall("before")

	p.SetRefuse(true)
	if nc, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second); err == nil {
		nc.Close()
		t.Fatal("dial succeeded while refusing")
	}
	// Refusing new connections leaves the open one alone.
	open.mustCall("during")

	p.SetRefuse(false)
	dial(t, p).mustCall("after")
}

func TestReset(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	open := dial(t, p)
	open.mustCall("before")

	p.SetReset(true)
	if got, err := open.call("x", 5*time.Second); err == nil || isTimeout(err) {
		t.Errorf("open connection after SetReset: %q, %v; want it reset", got, err)
	}
	if got, err := dial(t, p).call("x", 5*time.Second); err == nil || isTimeout(err) {
		t.Errorf("new connection while resetting: %q, %v; want it reset", got, err)
	}
	p.SetReset(false)
	dial(t, p).mustCall("after")
}

func TestResetConns(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	a, b := dial(t, p), dial(t, p)
	a.mustCall("before")
	b.mustCall("before")
	p.ResetConns()
	for _, c := range []*client{a, b} {
		if got, err := c.call("x", 5*time.Second); err == nil || isTimeout(err) {
			t.Errorf("after ResetConns: %q, %v; want the connection reset", got, err)
		}
	}
	dial(t, p).mustCall("after")
	eventually(t, func() bool { return p.Conns() == 1 })
}

// TestDropReply checks that the server acts on the request whose reply is
// lost, once, and that only that request is affected.
func TestDropReply(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	c := dial(t, p)
	c.mustCall("first")

	p.DropReply("APPLY")
	c.mustCall("read") // does not match
	before := s.applied.Load()
	if got, err := c.call("please apply this", 5*time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("matching request: %q, %v; want EOF", got, err)
	}
	if got := s.applied.Load() - before; got != 1 {
		t.Errorf("the server acted on the request %d times, want once", got)
	}
	// It fired once.
	dial(t, p).mustCall("apply again")
}

func TestTargetDown(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	p := New(t, ln.Addr().String())
	if got, err := dial(t, p).call("x", 10*time.Second); err == nil || isTimeout(err) {
		t.Errorf("call with the target down: %q, %v; want the connection reset", got, err)
	}
}

func TestHeal(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	p.SetLatency(time.Second, 0)
	p.SetBandwidth(1)
	p.SetBlackhole(true)
	p.SetReset(true)
	p.SetRefuse(true)
	p.DropReply("ok")
	p.Heal()
	start := time.Now()
	dial(t, p).mustCall("ok")
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Errorf("a call after Heal took %s", took)
	}
}

// TestCloseStopsEverything closes a proxy with connections in every state
// and checks that Close waits for their goroutines.
func TestCloseStopsEverything(t *testing.T) {
	t.Parallel()
	s := newLineServer(t)
	p := New(t, s.addr)
	dial(t, p).mustCall("idle")
	slow := dial(t, p)
	p.SetLatency(time.Hour, 0)
	if _, err := io.WriteString(slow.nc, "held\n"); err != nil {
		t.Fatal(err)
	}
	p.SetBlackhole(true)
	if _, err := io.WriteString(dial(t, p).nc, "swallowed\n"); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return p.Conns() == 3 })

	done := make(chan struct{})
	go func() {
		p.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	if n := p.Conns(); n != 0 {
		t.Errorf("Conns = %d after Close", n)
	}
	p.Close()
}

func eventually(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met after 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
