// Package storetest provides Redis servers for tests of the Redis store and
// of code built on it: an in-process miniredis, and a real server when
// CATRACA_TEST_REDIS_URL points at one.
package storetest

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
)

// unionKey is a scratch key for computing PFCOUNT unions.
const unionKey = "storetest:pfcount-union"

// Miniredis starts a miniredis server that is stopped when the test ends.
//
// miniredis (as of v2.40.0) answers PFCOUNT over several keys with the sum of
// their counts, while Redis answers with the size of their union, which is
// what distinct counts over a window rely on. The server returned here
// answers such calls with the union, from clients and from Lua scripts alike.
func Miniredis(tb testing.TB) *miniredis.Miniredis {
	tb.Helper()
	m := miniredis.RunT(tb)
	srv := m.Server()
	srv.SetPreHook(func(c *server.Peer, cmd string, args ...string) bool {
		if cmd != "PFCOUNT" || len(args) < 2 {
			return false
		}
		n, err := union(srv, c, args)
		if err != nil {
			c.WriteError(err.Error())
			return true
		}
		c.WriteInt(n)
		return true
	})
	return m
}

// union merges keys into unionKey, counts it and deletes it. The commands run
// as the calling peer would run them, rather than through Miniredis's own
// methods, which take a lock that a running Lua script already holds.
func union(srv *server.Server, c *server.Peer, keys []string) (int, error) {
	run := func(args ...string) (any, error) {
		var buf bytes.Buffer
		w := bufio.NewWriter(&buf)
		p := server.NewPeer(w)
		p.Ctx = c.Ctx
		srv.Dispatch(p, args)
		if err := w.Flush(); err != nil {
			return nil, err
		}
		return server.ParseReply(bufio.NewReader(&buf))
	}
	defer run("DEL", unionKey)
	if _, err := run(append([]string{"PFMERGE", unionKey}, keys...)...); err != nil {
		return 0, err
	}
	res, err := run("PFCOUNT", unionKey)
	if err != nil {
		return 0, err
	}
	n, ok := res.(int)
	if !ok {
		return 0, fmt.Errorf("storetest: PFCOUNT returned %T", res)
	}
	return n, nil
}
