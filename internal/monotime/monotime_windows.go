package monotime

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	qpf      = kernel32.NewProc("QueryPerformanceFrequency")
	// frequency is zero if the counter is unavailable, which Windows
	// documents cannot happen on XP or later; Now then falls back to Go's
	// clock.
	frequency = func() int64 {
		var f int64
		if r, _, _ := qpf.Call(uintptr(unsafe.Pointer(&f))); r == 0 {
			return 0
		}
		return f
	}()
	epoch = time.Now()
)

// Now returns a monotonic clock reading, meaningful only relative to
// another reading in the same process.
func Now() time.Duration {
	if frequency == 0 {
		return time.Since(epoch)
	}
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	return time.Duration(c/frequency)*time.Second + time.Duration(c%frequency)*time.Second/time.Duration(frequency)
}
