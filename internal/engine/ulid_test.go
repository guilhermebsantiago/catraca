package engine

import (
	"strings"
	"testing"
	"time"
)

// decodeULIDTime reads the millisecond timestamp from the first 10 characters.
func decodeULIDTime(t *testing.T, id string) time.Time {
	t.Helper()
	var ms int64
	for _, c := range id[:10] {
		i := strings.IndexRune(crockford, c)
		if i < 0 {
			t.Fatalf("id %q has a character outside the alphabet", id)
		}
		ms = ms<<5 | int64(i)
	}
	return time.UnixMilli(ms).UTC()
}

func TestULIDFormat(t *testing.T) {
	var s idSource
	at := time.Date(2026, 10, 15, 12, 34, 56, 789_000_000, time.UTC)
	id := s.next(at)
	if len(id) != 26 {
		t.Fatalf("id %q has %d characters, want 26", id, len(id))
	}
	for _, c := range id {
		if !strings.ContainsRune(crockford, c) {
			t.Fatalf("id %q has %q, outside the Crockford alphabet", id, c)
		}
	}
	if id[0] > '7' {
		t.Errorf("id %q overflows 128 bits", id)
	}
	if got := decodeULIDTime(t, id); !got.Equal(at) {
		t.Errorf("timestamp = %s, want %s", got, at)
	}
}

func TestULIDEncoding(t *testing.T) {
	if got := encodeULID(0, 0); got != "00000000000000000000000000" {
		t.Errorf("zero = %s", got)
	}
	if got := encodeULID(^uint64(0), ^uint64(0)); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Errorf("max = %s", got)
	}
	if got := encodeULID(0, 31); got != "0000000000000000000000000Z" {
		t.Errorf("31 = %s", got)
	}
}

func TestULIDsIncrease(t *testing.T) {
	var s idSource
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	steps := []time.Duration{0, 0, 0, time.Millisecond, 0, -time.Hour, 0, time.Second}
	prev := ""
	seen := map[string]bool{}
	for i, step := range steps {
		at = at.Add(step)
		id := s.next(at)
		if id <= prev {
			t.Fatalf("id %d = %s is not after %s (clock step %s)", i, id, prev, step)
		}
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
		prev = id
	}
}

func TestULIDRandomPartCarries(t *testing.T) {
	s := idSource{ms: 1000, randHi: 0, randLo: ^uint64(0)}
	a := s.next(time.UnixMilli(1000))
	if s.randHi != 1 || s.randLo != 0 {
		t.Errorf("after carry: hi=%d lo=%d", s.randHi, s.randLo)
	}
	s = idSource{ms: 1000, randHi: ^uint16(0), randLo: ^uint64(0)}
	b := s.next(time.UnixMilli(1000))
	if s.ms != 1001 {
		t.Errorf("exhausting a millisecond did not move to the next: ms=%d", s.ms)
	}
	if a == b {
		t.Error("carry produced equal ids")
	}
}

func BenchmarkULID(b *testing.B) {
	var s idSource
	now := time.Now()
	for b.Loop() {
		s.next(now)
	}
}
