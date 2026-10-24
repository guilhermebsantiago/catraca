package hooks

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

// leaseMargin is how much longer than its hook's timeout a claimed delivery
// stays reserved, so it is not claimed twice while its attempt still runs.
const leaseMargin = 30 * time.Second

// claimTimeout bounds a claim of deliveries and a refresh of the backlog.
// A query on a connection the network dropped without a reset waits until
// TCP gives up on it, a quarter of an hour on Linux, and a claim that waits
// stops every hook's deliveries, since one goroutine claims for them all.
const claimTimeout = 10 * time.Second

// Run delivers due deliveries until ctx is done, then waits for the attempts
// in flight (each bounded by its hook's timeout) and for the outbox writes
// Dispatch left running (bounded by EnqueueTimeout), and returns nil. Run
// one per process; with Postgres, several processes can run it at once.
//
// Deliveries are attempted as soon as a worker is free, without waiting for
// the others in flight. Each hook claims its own due deliveries, oldest
// first, up to its Concurrency, and when there are more due deliveries than
// free workers, the hooks with the fewest attempts in flight go first. So a
// hook whose endpoint is slow, or down and timing out, holds at most its own
// Concurrency of the workers, and the other hooks keep delivering.
func (d *Dispatcher) Run(ctx context.Context) error {
	s := d.newScheduler()
	maintained := make(chan struct{})
	go func() {
		defer close(maintained)
		d.maintain(ctx)
	}()
	poll := time.NewTicker(d.cfg.PollInterval)
	defer poll.Stop()
	for {
		s.fill(ctx)
		select {
		case <-ctx.Done():
			s.attempts.Wait()
			<-maintained
			d.writing.Wait()
			return nil
		case l := <-s.finished:
			l.busy--
			s.free++
		case <-d.wake:
			s.wantAll()
		case <-poll.C:
			s.paused = false
			s.wantAll()
		}
	}
}

// scheduler is Run's state: which hooks have attempts in flight, and how
// many workers are free. Only Run's goroutine uses it, except finished,
// which the attempts report on.
type scheduler struct {
	d     *Dispatcher
	lanes []*lane
	free  int
	// next rotates which hook goes first among those equally busy, so they
	// take turns at the workers that come free.
	next int
	// paused stops claiming after a claim failed, until the next poll.
	paused bool
	// finished receives the lane of each attempt that ends. It holds one
	// per worker, so an attempt never waits to report.
	finished chan *lane
	attempts sync.WaitGroup
}

// lane is one hook's share of the workers.
type lane struct {
	hook Hook
	busy int
	// more is set when the hook may have due deliveries beyond those it
	// claimed: after a wake-up, a poll, or a claim that got all it asked
	// for.
	more bool
}

func (d *Dispatcher) newScheduler() *scheduler {
	s := &scheduler{d: d, free: d.cfg.Workers, finished: make(chan *lane, d.cfg.Workers)}
	for _, name := range d.names {
		s.lanes = append(s.lanes, &lane{hook: d.hooks[name], more: true})
	}
	return s
}

func (s *scheduler) wantAll() {
	for _, l := range s.lanes {
		l.more = true
	}
}

// fill claims due deliveries for the hooks that have room, the least busy
// first, while workers are free, and starts their attempts.
func (s *scheduler) fill(ctx context.Context) {
	if s.paused || s.free == 0 || len(s.lanes) == 0 || ctx.Err() != nil {
		return
	}
	var ready []*lane
	for i := range s.lanes {
		l := s.lanes[(s.next+i)%len(s.lanes)]
		if l.more && l.busy < l.hook.Concurrency {
			ready = append(ready, l)
		}
	}
	s.next = (s.next + 1) % len(s.lanes)
	slices.SortStableFunc(ready, func(a, b *lane) int { return cmp.Compare(a.busy, b.busy) })
	for _, l := range ready {
		if s.free == 0 {
			return
		}
		n := min(l.hook.Concurrency-l.busy, s.free)
		ds, err := s.d.claim(ctx, l.hook, n)
		if err != nil {
			if ctx.Err() == nil {
				s.paused = true
				s.d.log.Error("hooks: claim deliveries; trying again at the next poll", "hook", l.hook.Name, "err", err)
			}
			return
		}
		l.more = len(ds) == n
		for _, del := range ds {
			l.busy++
			s.free--
			s.attempts.Go(func() {
				s.d.deliver(ctx, l.hook, del)
				s.finished <- l
			})
		}
	}
}

// claim leases up to n of h's due deliveries, leaving those past its max age
// to refresh.
func (d *Dispatcher) claim(ctx context.Context, h Hook, n int) ([]audit.Delivery, error) {
	ctx, cancel := context.WithTimeout(ctx, d.claimTimeout)
	defer cancel()
	now := d.now()
	return d.outbox.Claim(ctx, audit.ClaimRequest{
		Effect:      h.Name,
		Now:         now,
		Limit:       n,
		Lease:       h.Timeout + leaseMargin,
		QueuedAfter: now.Add(-h.MaxAge),
	})
}

// deliver makes one attempt and records its outcome. The attempt and the
// outbox update are not canceled with ctx, so a shutdown lets them finish.
func (d *Dispatcher) deliver(ctx context.Context, h Hook, del audit.Delivery) {
	ctx = context.WithoutCancel(ctx)
	log := d.log.With("decision_id", del.DecisionID, "effect", del.Effect, "attempt", del.Attempts)

	status, retryAfter, err := d.send(ctx, h, del)
	a := audit.Attempt{At: d.now(), StatusCode: status}
	if err == nil {
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.MarkDelivered(ctx, del.ID, a) })
		d.delivered.Add(1)
		log.Debug("hooks: delivered", "status", status)
		return
	}
	a.Error = err.Error()
	next := a.At.Add(d.backoff(del.Attempts, retryAfter))
	switch {
	case del.Attempts >= h.MaxAttempts:
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.MarkDead(ctx, del.ID, a) })
		d.dead.Add(1)
		log.Error("hooks: delivery dead after max attempts", "status", status, "err", err)
	case next.After(del.QueuedAt().Add(h.MaxAge)):
		// Waiting for an attempt that would be given up as too old only
		// hides the failure for longer.
		a.Error += fmt.Sprintf("; given up: the next attempt would be past max_age (%s)", h.MaxAge)
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.MarkDead(ctx, del.ID, a) })
		d.dead.Add(1)
		log.Error("hooks: delivery dead: the next attempt would be past max_age", "status", status, "max_age", h.MaxAge, "err", err)
	default:
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.Retry(ctx, del.ID, a, next) })
		d.retried.Add(1)
		log.Warn("hooks: delivery failed, will retry", "status", status, "next_attempt", next, "err", err)
	}
}

// settleTimeout bounds an outbox update after an attempt.
const settleTimeout = 10 * time.Second

// settle records an attempt's outcome in the outbox. If that fails, the
// delivery's lease expires and it is attempted again, which the idempotency
// key makes safe, so the error is only logged.
func (d *Dispatcher) settle(ctx context.Context, log *slog.Logger, update func(context.Context) error) {
	ctx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()
	if err := update(ctx); err != nil {
		log.Error("hooks: record delivery outcome", "err", err)
	}
}

// maintain refreshes the backlog every BacklogInterval until ctx is done.
func (d *Dispatcher) maintain(ctx context.Context) {
	t := time.NewTicker(d.cfg.BacklogInterval)
	defer t.Stop()
	for {
		d.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refresh gives up the deliveries that outlived their hook's max age
// waiting, and those of effects no hook carries out once they outlive
// Config.MaxAge, then counts what waits for each hook. Claim skips expired
// deliveries, so they wait here instead of taking workers.
func (d *Dispatcher) refresh(ctx context.Context) {
	// ctx ends when Run stops, which is not worth a log line; qctx also
	// ends at the timeout, which is.
	qctx, cancel := context.WithTimeout(ctx, d.claimTimeout)
	defer cancel()
	now := d.now()
	backlog, err := d.outbox.Backlog(qctx, now)
	if err != nil {
		if ctx.Err() == nil {
			d.log.Error("hooks: count the outbox backlog", "err", err)
		}
		return
	}
	expired := false
	for _, b := range backlog {
		h, configured := d.hooks[b.Effect]
		maxAge, reason := d.cfg.MaxAge, ""
		if configured {
			maxAge = h.MaxAge
			reason = fmt.Sprintf("not delivered within max_age (%s)", maxAge)
		} else {
			reason = fmt.Sprintf("no hook carries out effect %q, and the delivery is older than %s", b.Effect, maxAge)
		}
		cutoff := now.Add(-maxAge)
		if !b.Oldest.Before(cutoff) {
			continue
		}
		n, err := d.outbox.Expire(qctx, b.Effect, cutoff, audit.Attempt{At: now, Error: reason})
		if n > 0 {
			expired = true
			d.expired.Add(uint64(n))
			d.dead.Add(uint64(n))
			d.log.Error("hooks: gave up deliveries that waited longer than max_age", "hook", b.Effect,
				"count", n, "max_age", maxAge, "hook_configured", configured)
		}
		if err != nil && ctx.Err() == nil {
			d.log.Error("hooks: give up expired deliveries", "hook", b.Effect, "err", err)
		}
	}
	if expired {
		if backlog, err = d.outbox.Backlog(qctx, now); err != nil {
			if ctx.Err() == nil {
				d.log.Error("hooks: count the outbox backlog", "err", err)
			}
			return
		}
	}

	// Every hook has a row, so a hook with nothing waiting reports zero,
	// followed by the effects no hook carries out.
	byEffect := make(map[string]audit.Backlog, len(backlog))
	for _, b := range backlog {
		byEffect[b.Effect] = b
	}
	out := make([]audit.Backlog, 0, len(d.names)+len(backlog))
	for _, name := range d.names {
		b := byEffect[name]
		b.Effect = name
		out = append(out, b)
	}
	for _, b := range backlog {
		if !d.Configured(b.Effect) {
			out = append(out, b)
		}
	}
	d.backlog.Store(&out)
}

// Backlog returns what waited in the outbox at Run's last count, every
// BacklogInterval: a row per configured hook, in configuration order, then
// one per effect with pending deliveries and no hook. It is nil until Run
// has counted once. With several instances, each counts the whole outbox.
func (d *Dispatcher) Backlog() []audit.Backlog {
	p := d.backlog.Load()
	if p == nil {
		return nil
	}
	return slices.Clone(*p)
}
