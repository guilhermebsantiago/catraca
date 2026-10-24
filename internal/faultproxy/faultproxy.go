// Package faultproxy is a TCP proxy for tests that puts network faults
// between a client and the server it talks to, such as Catraca and its
// Redis, Postgres or a webhook receiver: latency with jitter, slow
// bandwidth, a blackhole that accepts connections and never answers,
// connections reset or refused, and a reply lost after the server acted on
// its request. Each fault is turned on and off while the proxy runs, so a
// test can break a dependency in the middle of a run and watch the client
// recover.
//
// It moves bytes without parsing them, except to recognize the request
// whose reply DropReply loses, so it serves any protocol over TCP. It runs
// in the test's process and imports nothing from the module, so the tests
// of any package can use it.
package faultproxy

import (
	"bytes"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// bufSize is how much a pipe reads at once.
const bufSize = 32 << 10

// dialTimeout bounds the connection to the target.
const dialTimeout = 5 * time.Second

// Proxy forwards the connections it accepts on a local address to a target
// address, with the faults its methods turn on. It is safe for concurrent
// use.
type Proxy struct {
	tb     testing.TB
	target string
	addr   string

	mu sync.Mutex
	f  faults
	// ln is nil while connections are refused.
	ln     net.Listener
	conns  map[*conn]struct{}
	closed bool
	// wg counts the accept loop and the goroutines of every connection, so
	// Close returns once they are gone.
	wg sync.WaitGroup
}

// faults are the faults turned on, read by each connection for each chunk
// it forwards.
type faults struct {
	latency, jitter time.Duration
	// bandwidth is in bytes per second each way, 0 for no limit.
	bandwidth int
	blackhole bool
	reset     bool
	// dropReply is the lower-cased pattern of the request whose reply is
	// lost, "" when DropReply is not armed.
	dropReply string
}

// New starts a proxy on a free port of 127.0.0.1 that forwards to target,
// host:port, with no fault turned on. It is closed when the test ends.
func New(tb testing.TB, target string) *Proxy {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("faultproxy: %v", err)
	}
	p := &Proxy{tb: tb, target: target, addr: ln.Addr().String(), ln: ln, conns: make(map[*conn]struct{})}
	p.serve(ln)
	tb.Cleanup(p.Close)
	return p
}

// Addr is the address clients connect to, host:port. It stays the same
// while connections are refused and after.
func (p *Proxy) Addr() string { return p.addr }

// SetLatency delays every reply, each chunk of bytes from the target, by
// latency plus or minus up to jitter, so a request and its reply take about
// latency longer. Chunks keep their order: one never overtakes the one
// before it. Zero turns it off.
func (p *Proxy) SetLatency(latency, jitter time.Duration) {
	p.update(func(f *faults) { f.latency, f.jitter = latency, jitter })
}

// SetBandwidth limits each connection to bytesPerSecond each way. Zero
// turns the limit off.
func (p *Proxy) SetBandwidth(bytesPerSecond int) {
	p.update(func(f *faults) { f.bandwidth = max(bytesPerSecond, 0) })
}

// SetBlackhole turns the blackhole on or off. While it is on, new
// connections are accepted and never reach the target, and the bytes sent
// either way on open connections are lost, as when a network drops every
// packet: clients wait until their own timeouts. A connection that lost
// bytes is out of step with its server, so it stays blackholed once the
// blackhole is off, as a TCP connection whose packets were dropped long
// enough is dead; new connections, and those that sent nothing meanwhile,
// work again.
func (p *Proxy) SetBlackhole(on bool) {
	p.update(func(f *faults) { f.blackhole = on })
}

// SetReset turns resets on or off. Turning them on resets every open
// connection, and while they are on each new connection is reset as soon
// as it is accepted, as by a server that is up but cannot serve: clients
// see "connection reset by peer" at once.
func (p *Proxy) SetReset(on bool) {
	p.update(func(f *faults) { f.reset = on })
	if on {
		p.ResetConns()
	}
}

// ResetConns resets every open connection now, both ways, as a server that
// restarts or a firewall that forgets its flows does. New connections work
// as before.
func (p *Proxy) ResetConns() {
	p.mu.Lock()
	conns := make([]*conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		c.close(true)
	}
}

// SetRefuse turns refusal on or off. While it is on nothing listens on the
// proxy's address, so dials fail with "connection refused", as when the
// server is down; open connections stay open, unless ResetConns closes
// them too, as a crash would. Turning it off listens on the same address
// again. Call it from the test's goroutine: it fails the test when the
// address cannot be had back.
func (p *Proxy) SetRefuse(on bool) {
	p.tb.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if on {
		if p.ln != nil {
			p.ln.Close()
			p.ln = nil
		}
		return
	}
	if p.ln != nil {
		return
	}
	// The port was ours a moment ago, but the system may take a moment to
	// let it go.
	var (
		ln  net.Listener
		err error
	)
	for start := time.Now(); time.Since(start) < 5*time.Second; time.Sleep(50 * time.Millisecond) {
		if ln, err = net.Listen("tcp", p.addr); err == nil {
			break
		}
	}
	if err != nil {
		p.tb.Fatalf("faultproxy: listen on %s again: %v", p.addr, err)
	}
	p.ln = ln
	p.serve(ln)
}

// DropReply arms a lost reply: the next request whose bytes contain
// pattern, ignoring ASCII case, is forwarded to the target, and when the
// target's reply comes back the proxy closes the connection instead of
// passing it on. The server acted on the request; the client sees EOF and
// cannot tell whether it did. The close is orderly rather than a reset
// because EOF is what clients such as go-redis retry on, which is the case
// worth testing. It fires once; call it again for another.
func (p *Proxy) DropReply(pattern string) {
	p.update(func(f *faults) { f.dropReply = string(bytes.ToLower([]byte(pattern))) })
}

// Heal turns every fault off and listens again if connections were
// refused. Connections a blackhole or a lost reply broke stay broken.
func (p *Proxy) Heal() {
	p.tb.Helper()
	p.update(func(f *faults) { *f = faults{} })
	p.SetRefuse(false)
}

// Conns returns how many connections are open through the proxy.
func (p *Proxy) Conns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// Close stops the proxy: it stops listening, resets every connection and
// waits for its goroutines to return. It is safe to call more than once.
func (p *Proxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	if p.ln != nil {
		p.ln.Close()
		p.ln = nil
	}
	p.mu.Unlock()
	p.ResetConns()
	p.wg.Wait()
}

func (p *Proxy) update(change func(*faults)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(&p.f)
}

func (p *Proxy) faults() faults {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.f
}

// serve accepts connections on ln until it is closed.
func (p *Proxy) serve(ln net.Listener) {
	p.wg.Go(func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			p.accept(nc)
		}
	})
}

// accept starts forwarding a new connection, or applies the faults that
// keep it from reaching the target.
func (p *Proxy) accept(client net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		client.Close()
		return
	}
	f := p.f
	c := &conn{p: p, client: client, done: make(chan struct{})}
	p.conns[c] = struct{}{}
	// Added under the lock, so Close, which takes it first, either sees
	// the connection or keeps it from being added.
	p.wg.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wg.Done()
		switch {
		case f.reset:
			c.close(true)
		case f.blackhole:
			c.dead.Store(true)
			c.swallow()
		default:
			c.forward()
		}
	}()
}

// takeDrop reports whether b is the request DropReply is armed for, and
// disarms it if so.
func (p *Proxy) takeDrop(b []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f.dropReply == "" || !bytes.Contains(bytes.ToLower(b), []byte(p.f.dropReply)) {
		return false
	}
	p.f.dropReply = ""
	return true
}

func (p *Proxy) forget(c *conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
}

// conn is one client connection and, once dialed, its connection to the
// target.
type conn struct {
	p      *Proxy
	client net.Conn

	mu     sync.Mutex
	server net.Conn
	closed bool
	// done is closed with the connection, to stop the waits of its pipes.
	done chan struct{}

	// dead is set once the connection lost bytes to the blackhole: it
	// loses everything from then on.
	dead atomic.Bool
	// dropping is set when the request DropReply was armed for has gone to
	// the target: its reply closes the connection.
	dropping atomic.Bool
}

// forward dials the target and copies bytes both ways until either side
// closes, applying the faults.
func (c *conn) forward() {
	server, err := net.DialTimeout("tcp", c.p.target, dialTimeout)
	if err != nil {
		// The target is down: the client sees its connection reset.
		c.close(true)
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		server.Close()
		return
	}
	c.server = server
	c.mu.Unlock()

	replies := make(chan chunk, 64)
	var wg sync.WaitGroup
	wg.Go(func() { c.requests(server) })
	wg.Go(func() { c.readReplies(server, replies) })
	wg.Go(func() { c.writeReplies(replies) })
	wg.Wait()
}

// swallow reads what a blackholed connection sends, and drops it, until it
// closes.
func (c *conn) swallow() {
	defer c.close(false)
	buf := make([]byte, bufSize)
	for {
		if _, err := c.client.Read(buf); err != nil {
			return
		}
	}
}

// requests copies the client's bytes to the target.
func (c *conn) requests(server net.Conn) {
	defer c.close(false)
	buf := make([]byte, bufSize)
	for {
		n, err := c.client.Read(buf)
		if n > 0 {
			f := c.p.faults()
			if f.blackhole || c.dead.Load() {
				c.dead.Store(true)
			} else {
				if c.p.takeDrop(buf[:n]) {
					c.dropping.Store(true)
				}
				if c.write(server, buf[:n], f.bandwidth) != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// chunk is a piece of a reply and when it is due at the client.
type chunk struct {
	b   []byte
	due time.Time
}

// readReplies reads the target's bytes and queues them for writeReplies
// with the time each is due, which is how latency delays them without
// holding up the reads.
func (c *conn) readReplies(server net.Conn, replies chan<- chunk) {
	defer close(replies)
	buf := make([]byte, bufSize)
	var last time.Time
	for {
		n, err := server.Read(buf)
		if n > 0 {
			f := c.p.faults()
			switch {
			case f.blackhole || c.dead.Load():
				c.dead.Store(true)
			case c.dropping.Load():
				c.close(false)
				return
			default:
				due := time.Now().Add(f.delay())
				if due.Before(last) {
					due = last
				}
				last = due
				select {
				case replies <- chunk{b: bytes.Clone(buf[:n]), due: due}:
				case <-c.done:
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// writeReplies writes the queued replies to the client as each comes due,
// and closes the connection once the target has closed its side and every
// reply is written.
func (c *conn) writeReplies(replies <-chan chunk) {
	defer c.close(false)
	for r := range replies {
		if !c.sleep(time.Until(r.due)) {
			return
		}
		if c.write(c.client, r.b, c.p.faults().bandwidth) != nil {
			return
		}
	}
}

// write writes b to dst, at most bandwidth bytes a second when it is
// positive: a tenth of a second's worth at a time, each followed by the
// time it takes at that rate.
func (c *conn) write(dst net.Conn, b []byte, bandwidth int) error {
	if bandwidth <= 0 {
		_, err := dst.Write(b)
		return err
	}
	step := max(1, bandwidth/10)
	for len(b) > 0 {
		n := min(len(b), step)
		if _, err := dst.Write(b[:n]); err != nil {
			return err
		}
		b = b[n:]
		if !c.sleep(time.Duration(n) * time.Second / time.Duration(bandwidth)) {
			return net.ErrClosed
		}
	}
	return nil
}

// sleep waits for d and reports whether it did, or returns false as soon as
// the connection closes.
func (c *conn) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.done:
		return false
	}
}

// close closes both sides of the connection, with a reset (RST) rather
// than an orderly close when reset is set. It is safe to call more than
// once.
func (c *conn) close(reset bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	server := c.server
	c.mu.Unlock()
	close(c.done)
	for _, nc := range []net.Conn{c.client, server} {
		if nc == nil {
			continue
		}
		if tc, ok := nc.(*net.TCPConn); ok && reset {
			// A zero linger makes Close send a reset and drop what is
			// unsent.
			_ = tc.SetLinger(0)
		}
		nc.Close()
	}
	c.p.forget(c)
}

// delay returns how long to hold a reply: the latency, moved by a uniform
// amount within the jitter either way, never below zero.
func (f faults) delay() time.Duration {
	d := f.latency
	if f.jitter > 0 {
		d += time.Duration(rand.Int64N(2*int64(f.jitter)+1)) - f.jitter
	}
	return max(d, 0)
}
