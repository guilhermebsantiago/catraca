package app

import (
	"context"
	"time"
)

// CheckRules is one look of the ruleset watch at now, so tests drive the
// watch without its timer.
func CheckRules(a *App, now time.Time) time.Duration {
	return a.rulesets.check(context.Background(), now)
}

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
