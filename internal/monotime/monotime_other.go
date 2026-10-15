//go:build !windows

package monotime

import "time"

var epoch = time.Now()

// Now returns a monotonic clock reading, meaningful only relative to
// another reading in the same process.
func Now() time.Duration { return time.Since(epoch) }
