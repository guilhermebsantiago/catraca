package engine

import (
	"context"
	"sync"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

type recordJob struct {
	ctx context.Context
	ev  event.Event
	d   decision.Decision
}

// recordQueue feeds a Recorder from one goroutine, so Decide never waits on
// the audit log.
type recordQueue struct {
	rec       Recorder
	jobs      chan recordJob
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newRecordQueue(rec Recorder, size int) *recordQueue {
	q := &recordQueue{
		rec:  rec,
		jobs: make(chan recordJob, size),
		quit: make(chan struct{}),
		done: make(chan struct{}),
	}
	go q.run()
	return q
}

// push queues j, or reports false when the queue is full or closed.
func (q *recordQueue) push(j recordJob) bool {
	select {
	case <-q.quit:
		return false
	default:
	}
	select {
	case q.jobs <- j:
		return true
	default:
		return false
	}
}

func (q *recordQueue) run() {
	defer close(q.done)
	for {
		select {
		case j := <-q.jobs:
			q.rec.Record(j.ctx, j.ev, j.d)
		case <-q.quit:
			for {
				select {
				case j := <-q.jobs:
					q.rec.Record(j.ctx, j.ev, j.d)
				default:
					return
				}
			}
		}
	}
}

func (q *recordQueue) close(ctx context.Context) error {
	q.closeOnce.Do(func() { close(q.quit) })
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
