// Package storetest provides an in-process Redis server for tests of the
// Redis store and of code built on it.
package storetest

import (
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
// answers such calls with the union.
func Miniredis(tb testing.TB) *miniredis.Miniredis {
	tb.Helper()
	m := miniredis.RunT(tb)
	m.Server().SetPreHook(func(c *server.Peer, cmd string, args ...string) bool {
		if cmd != "PFCOUNT" || len(args) < 2 {
			return false
		}
		m.Del(unionKey)
		defer m.Del(unionKey)
		if err := m.PfMerge(unionKey, args...); err != nil {
			c.WriteError(err.Error())
			return true
		}
		n, err := m.PfCount(unionKey)
		if err != nil {
			c.WriteError(err.Error())
			return true
		}
		c.WriteInt(n)
		return true
	})
	return m
}
