package monotime

import (
	"testing"
	"time"
)

func TestNowResolvesMicroseconds(t *testing.T) {
	start := Now()
	time.Sleep(2 * time.Millisecond)
	if got := Since(start); got < time.Millisecond || got > time.Second {
		t.Fatalf("Since after a 2 ms sleep = %s", got)
	}
	// A tight loop must observe the clock advance by less than 100 µs at
	// least once: a clock with half-millisecond steps never does.
	prev := Now()
	for range 1_000_000 {
		now := Now()
		if d := now - prev; d > 0 && d < 100*time.Microsecond {
			return
		}
		prev = now
	}
	t.Fatal("the clock never advanced by less than 100 µs")
}

// A decision reads the clock a few times, so a reading must not allocate.
func TestNowDoesNotAllocate(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() { _ = Now() }); n != 0 {
		t.Fatalf("Now allocates %v times per reading", n)
	}
}

func BenchmarkNow(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = Now()
	}
}
