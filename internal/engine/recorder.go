package engine

import (
	"context"
	"sync"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// recordJob is a decision for the Recorder or, when synced is set, a marker
// that sync sends through the queue behind the decisions already in it.
type recordJob struct {
	ctx context.Context
	ev  event.Event
	d   decision.Decision
	// synced is closed by the queue's goroutine when it reaches the job,
	// once every job queued before it has been handed to the Recorder.
	synced chan struct{}
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

// sync returns once every job pushed before the call has been handed to the
// Recorder, or with ctx's error when ctx ends first. The marker it sends
// waits for room in a full queue rather than being dropped, which is fine
// for a caller that reads the audit log: it is not on the decision path.
func (q *recordQueue) sync(ctx context.Context) error {
	synced := make(chan struct{})
	select {
	case q.jobs <- recordJob{synced: synced}:
	case <-q.quit:
		// close hands over what is queued before the goroutine ends.
		synced = q.done
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-synced:
		return nil
	case <-q.done:
		// The goroutine drained the queue and ended; a marker sent as it
		// ended is never reached, but nothing is left before it either.
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *recordQueue) run() {
	defer close(q.done)
	for {
		select {
		case j := <-q.jobs:
			q.handle(j)
		case <-q.quit:
			for {
				select {
				case j := <-q.jobs:
					q.handle(j)
				default:
					return
				}
			}
		}
	}
}

func (q *recordQueue) handle(j recordJob) {
	if j.synced != nil {
		close(j.synced)
		return
	}
	q.rec.Record(j.ctx, j.ev, j.d)
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
