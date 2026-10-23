package app

import "time"

// HoldDrain makes a's drain last until release is closed, whatever
// server.drain_delay says, so tests can look at a draining server without
// racing its delay.
func HoldDrain(a *App, release <-chan struct{}) {
	a.drainEnd = func(time.Duration) <-chan time.Time {
		end := make(chan time.Time)
		go func() {
			<-release
			close(end)
		}()
		return end
	}
}
