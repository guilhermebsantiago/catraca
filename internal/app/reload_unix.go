//go:build unix

package app

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyReload sends SIGHUP to ch, the conventional signal for reloading a
// daemon's configuration.
func notifyReload(ch chan<- os.Signal) bool {
	signal.Notify(ch, syscall.SIGHUP)
	return true
}
