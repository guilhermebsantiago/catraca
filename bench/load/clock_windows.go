package main

import (
	"syscall"
	"time"
	"unsafe"
)

// Go's monotonic clock on Windows ticks too coarsely to time a request that
// takes a few hundred microseconds, so latency is read from the performance
// counter instead.
var (
	kernel32  = syscall.NewLazyDLL("kernel32.dll")
	qpc       = kernel32.NewProc("QueryPerformanceCounter")
	qpf       = kernel32.NewProc("QueryPerformanceFrequency")
	frequency = func() int64 {
		var f int64
		if r, _, _ := qpf.Call(uintptr(unsafe.Pointer(&f))); r == 0 || f == 0 {
			panic("load: no performance counter")
		}
		return f
	}()
)

// now is a monotonic clock reading for measuring latency.
func now() time.Duration {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	return time.Duration(c/frequency)*time.Second + time.Duration(c%frequency)*time.Second/time.Duration(frequency)
}
