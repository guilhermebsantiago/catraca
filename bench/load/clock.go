//go:build !windows

package main

import "time"

var epoch = time.Now()

// now is a monotonic clock reading for measuring latency.
func now() time.Duration { return time.Since(epoch) }
