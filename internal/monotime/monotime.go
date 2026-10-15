// Package monotime reads a high-resolution monotonic clock for measuring
// short intervals such as a decision's latency.
//
// Go's monotonic clock is fine for this on Linux and macOS, but on Windows
// it advances in steps of about half a millisecond, so a decision that takes
// 200 µs reads as 0 or 500 µs there. On Windows this package reads the
// performance counter instead.
package monotime

import "time"

// Since returns the time elapsed since a reading of Now.
func Since(start time.Duration) time.Duration { return Now() - start }
