package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// DefaultMaxInflight is Admission.MaxInflight when it is zero.
const DefaultMaxInflight = 256

// Admission bounds the work in flight, so that when the store slows down or
// saturates, the server sheds what it cannot serve in time instead of
// piling up requests and latency.
//
// Decisions on POST /v1/decide and POST /v1/events share one set of slots,
// taken once the body is read. A request that finds none waits up to Wait
// for one, in arrival order, and is then shed: decided at once without the
// store (Decider.DecideWithoutStore), so it is degraded exactly as if the
// store had missed the deadline. Sends and account events get that
// degraded decision, which the platform acts on as usual: an error status
// before a send would stop good senders or turn into retries that add to
// the load. A feedback event is answered 503 overloaded with Retry-After
// instead, since a degraded decision would not count it and the caller can
// send it again, and a key_leak event fails like a leak the store did not
// take, 503 with Retry-After.
//
// The feedback endpoints have slots of their own, the same number, so a
// flood of decisions never sheds feedback and a burst of feedback never
// takes slots from sends. Beyond them a request is answered 503 with
// Retry-After, which providers retry. Secret scanning, labels and the other
// routes are not limited: they are rare, and none of them waits on the
// store in the request.
type Admission struct {
	// MaxInflight is the most decisions in flight at once, and apart, the
	// most feedback requests. Zero means DefaultMaxInflight.
	MaxInflight int
	// Wait is how long a request over the limit waits for a slot before it
	// is shed. Zero sheds it at once.
	Wait time.Duration
	// Static keeps the decision limit at MaxInflight. Otherwise the limit
	// adapts to how fast decisions finish; see limiter.
	Static bool
	// Deadline is the engine's deadline: a decision that takes half of it or
	// more means the store is falling behind, and lowers the adaptive
	// limit. Zero means engine.DefaultDeadline.
	Deadline time.Duration
}

// How the adaptive limit moves; see limiter.
const (
	limitDecrease = 0.8
	minLimit      = 1
)

// outcome is what a request that held a slot says about capacity.
type outcome int

const (
	// outcomeNone says nothing: an error, a decision degraded without a
	// wait (the store failed fast, or its breaker is open), or a route
	// that is not adaptive.
	outcomeNone outcome = iota
	// outcomeOK is a decision made with every signal, in time.
	outcomeOK
	// outcomeSlow is a decision that took half the deadline or more.
	outcomeSlow
)

// limiter bounds the requests in flight on a group of routes. A request over
// the limit waits up to wait for a slot, in arrival order, and is shed when
// none frees up.
//
// An adaptive limiter moves its limit between 1 and max, additive increase
// and multiplicative decrease as in TCP. It starts at max, so it sheds
// nothing until decisions slow down. When a decision admitted since the
// last decrease takes half the deadline or more, the store (or the server)
// is falling behind, and the limit drops by a fifth: fewer decisions at
// once get their signals in time while the rest are shed without a round
// trip, instead of every decision waiting out the deadline and degrading
// anyway. Half the deadline, not all of it, leaves room for the spread of a
// loaded store's latency, so the decisions let in rarely miss it; past the
// store's capacity, fewer at once does not lower the rate it serves, only
// how long each waits. Decreasing once per round, rather than for every
// slow decision, keeps the burst of timeouts one stall causes from
// collapsing the limit. While at least half the slots are busy, each
// decision that finishes in time with its signals raises the limit by
// 1/limit, about one per limit's worth of decisions, so it climbs back as
// traffic needs it and stays where it is when traffic is light.
//
// A static limit is a backstop for memory and goroutines. It sheds only
// when the slots are full, and the right number depends on how fast the
// store is and how many instances share it, which the adaptive limit
// measures instead.
type limiter struct {
	adaptive bool
	max      float64
	wait     time.Duration
	// after is time.After, or a channel a test controls.
	after func(time.Duration) <-chan time.Time
	gauge prometheus.Gauge

	mu       sync.Mutex
	limit    float64
	inflight int
	// round counts the decreases, so each round decreases once.
	round uint64
	queue []*waiter
}

// ticket is a slot, with what release needs to know about when it was
// taken.
type ticket struct {
	round uint64
	// busy is set when at least half the slots were in use.
	busy bool
}

type waiter struct {
	ready   chan struct{}
	t       ticket
	granted bool
}

func newLimiter(maxInflight int, wait time.Duration, adaptive bool, gauge prometheus.Gauge) *limiter {
	l := &limiter{
		adaptive: adaptive,
		max:      float64(maxInflight),
		wait:     wait,
		after:    time.After,
		gauge:    gauge,
		limit:    float64(maxInflight),
	}
	gauge.Set(float64(l.slots()))
	return l
}

// slots is the limit as a number of requests, with l.mu held.
func (l *limiter) slots() int { return max(int(l.limit), minLimit) }

// acquire takes a slot, waiting up to l.wait for one, and reports whether
// it got one. A request whose context ends while it waits gets none.
func (l *limiter) acquire(ctx context.Context) (ticket, bool) {
	l.mu.Lock()
	if len(l.queue) == 0 && l.inflight < l.slots() {
		t := l.admit()
		l.mu.Unlock()
		return t, true
	}
	if l.wait <= 0 {
		l.mu.Unlock()
		return ticket{}, false
	}
	w := &waiter{ready: make(chan struct{})}
	l.queue = append(l.queue, w)
	l.mu.Unlock()

	select {
	case <-w.ready:
		return w.t, true
	case <-l.after(l.wait):
	case <-ctx.Done():
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if w.granted {
		// A slot came as the wait ended; it is this request's.
		return w.t, true
	}
	l.queue = slices.DeleteFunc(l.queue, func(q *waiter) bool { return q == w })
	return ticket{}, false
}

// admit takes a slot, with l.mu held.
func (l *limiter) admit() ticket {
	l.inflight++
	return ticket{round: l.round, busy: float64(l.inflight) >= l.limit/2}
}

// release returns t's slot, adapts the limit to o, and hands free slots to
// the requests waiting, first come first served.
func (l *limiter) release(t ticket, o outcome) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inflight--
	if l.adaptive {
		switch {
		case o == outcomeSlow && t.round == l.round:
			l.limit = max(l.limit*limitDecrease, minLimit)
			l.round++
		case o == outcomeOK && t.busy:
			l.limit = min(l.limit+1/l.limit, l.max)
		}
		l.gauge.Set(float64(l.slots()))
	}
	for len(l.queue) > 0 && l.inflight < l.slots() {
		w := l.queue[0]
		l.queue = slices.Delete(l.queue, 0, 1)
		w.t, w.granted = l.admit(), true
		close(w.ready)
	}
}

// admissionMetrics are shared by both groups of routes.
type admissionMetrics struct {
	inflight *prometheus.GaugeVec
	shed     *prometheus.CounterVec
	limit    *prometheus.GaugeVec
}

// The routes admission covers, the values of their route label.
const (
	routeDecide          = "POST /v1/decide"
	routeEvents          = "POST /v1/events"
	routeFeedback        = "POST /v1/feedback"
	routeFeedbackSES     = "POST /v1/feedback/ses"
	routeFeedbackUseSend = "POST /v1/feedback/usesend"
)

func newAdmissionMetrics() admissionMetrics {
	m := admissionMetrics{
		inflight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "catraca_admission_inflight",
			Help: "Requests holding an admission slot, by route: decisions on /v1/decide and /v1/events, and feedback requests.",
		}, []string{"route"}),
		shed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_admission_shed_total",
			Help: "Requests that found no admission slot in time, by route: decided without the store, or answered 503 with Retry-After.",
		}, []string{"route"}),
		limit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "catraca_admission_limit",
			Help: "How many requests may hold a slot at once, by group: decisions (adaptive unless server.inflight_limit is static) and feedback.",
		}, []string{"group"}),
	}
	for _, r := range []string{routeDecide, routeEvents, routeFeedback, routeFeedbackSES, routeFeedbackUseSend} {
		m.inflight.WithLabelValues(r)
		m.shed.WithLabelValues(r)
	}
	return m
}

func (m admissionMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.inflight, m.shed, m.limit}
}

// routeOf returns the route pattern of r, as the metrics label it.
func routeOf(r *http.Request) string {
	if ri := infoFrom(r.Context()); ri != nil {
		return ri.route
	}
	return "unmatched"
}

// decideAdmitted decides ev in a decision slot, or, when none frees up in
// time, sheds it: see Admission. It returns false when it answered the
// request itself.
func (s *Server) decideAdmitted(w http.ResponseWriter, r *http.Request, ev event.Event) (decision.Decision, bool, error) {
	route := routeOf(r)
	t, ok := s.decisions.acquire(r.Context())
	if ok {
		d, err := s.decideInSlot(r.Context(), route, t, ev)
		return d, true, err
	}
	s.admission.shed.WithLabelValues(route).Inc()
	annotate(r, slog.Bool("shed", true))
	if ev.Type == event.Feedback {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "overloaded",
			"too many events are being decided; send this one again after Retry-After")
		return decision.Decision{}, false, nil
	}
	d, err := s.decider.DecideWithoutStore(r.Context(), ev)
	return d, true, err
}

// decideInSlot decides ev in the slot t, and releases it with what the
// decision says about capacity.
func (s *Server) decideInSlot(ctx context.Context, route string, t ticket, ev event.Event) (d decision.Decision, err error) {
	inflight := s.admission.inflight.WithLabelValues(route)
	inflight.Inc()
	defer func() {
		inflight.Dec()
		s.decisions.release(t, s.outcomeOf(d, err))
	}()
	return s.decider.Decide(ctx, ev)
}

// outcomeOf says what a decision made in a slot tells about capacity.
func (s *Server) outcomeOf(d decision.Decision, err error) outcome {
	switch {
	case err != nil:
		return outcomeNone
	case time.Duration(d.LatencyMicros)*time.Microsecond >= s.deadline/2:
		return outcomeSlow
	case d.Degraded:
		return outcomeNone
	}
	return outcomeOK
}

// feedbackPrefetch is how much of a feedback body is read before the
// request takes a slot: more than the feedback handlers accept, 1 MiB, so
// that a sender that trickles its body holds a connection rather than a
// slot. A larger body streams on to the handler, which refuses it.
const feedbackPrefetch = 1<<20 + 1

// admitFeedback serves h, a feedback endpoint, in a feedback slot, and
// answers 503 with Retry-After when none frees up in time. A nil h stays
// nil, for routes that are not configured.
func (s *Server) admitFeedback(route string, h http.Handler) http.Handler {
	if h == nil {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		head, err := io.ReadAll(io.LimitReader(r.Body, feedbackPrefetch))
		var rest io.Reader = r.Body
		if err != nil {
			// The handler reads the same error and answers it as before.
			rest = errReader{err}
		}
		r.Body = prefetched{Reader: io.MultiReader(bytes.NewReader(head), rest), Closer: r.Body}

		t, ok := s.feedback.acquire(r.Context())
		if !ok {
			s.admission.shed.WithLabelValues(route).Inc()
			annotate(r, slog.Bool("shed", true))
			w.Header().Set("Retry-After", "1")
			// The provider routes answer in the format providers expect.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "too many feedback requests in flight; retry later"})
			return
		}
		inflight := s.admission.inflight.WithLabelValues(route)
		inflight.Inc()
		defer func() {
			inflight.Dec()
			s.feedback.release(t, outcomeNone)
		}()
		h.ServeHTTP(w, r)
	})
}

// prefetched is a request body whose start was read ahead.
type prefetched struct {
	io.Reader
	io.Closer
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// newAdmission builds the limiters and metrics a describes.
func (s *Server) newAdmission(a Admission, reg prometheus.Registerer) error {
	if a.MaxInflight < 0 || a.Wait < 0 || a.Deadline < 0 {
		return errors.New("api: Options.Admission fields must not be negative")
	}
	n := a.MaxInflight
	if n == 0 {
		n = DefaultMaxInflight
	}
	s.deadline = a.Deadline
	if s.deadline == 0 {
		s.deadline = engine.DefaultDeadline
	}
	s.admission = newAdmissionMetrics()
	s.decisions = newLimiter(n, a.Wait, !a.Static, s.admission.limit.WithLabelValues("decisions"))
	s.feedback = newLimiter(n, a.Wait, false, s.admission.limit.WithLabelValues("feedback"))
	if reg == nil {
		return nil
	}
	for _, c := range s.admission.collectors() {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}
