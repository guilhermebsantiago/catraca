package senderauth

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/store"
)

// Defaults for the zero values of Options.
const (
	DefaultTTL         = time.Hour
	DefaultNegativeTTL = 5 * time.Minute
	DefaultTimeout     = 5 * time.Second
	DefaultWorkers     = 4
	DefaultQueueSize   = 1024
)

// maxTracked bounds the domains the per-domain rate limit remembers, about
// 10 MB at most.
const maxTracked = 100_000

// Options configure a Refresher. Store and Checker are required.
type Options struct {
	// Store is where results are cached: the signal catalog's store.
	Store   store.Store
	Checker *Checker
	// TTL is how long a result is cached; NegativeTTL, shorter, how long
	// one with a missing record or a failed lookup is. A domain is also
	// looked up at most once per NegativeTTL by each Refresher.
	TTL, NegativeTTL time.Duration
	// Timeout bounds the check of one domain, every lookup included, and
	// then the write of its result.
	Timeout time.Duration
	// Workers is how many domains are checked at once.
	Workers int
	// QueueSize is how many domains may wait for a worker. A domain that
	// finds the queue full is dropped, and counted; the next send from it
	// queues it again.
	QueueSize int
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// Registerer receives the metrics; nil keeps them unregistered.
	Registerer prometheus.Registerer
	// Logger receives failures to write results. Nil discards them.
	Logger *slog.Logger
}

// Refresher looks sender domains up in the background and caches the
// results. The signal catalog tells it of every cache read, through Hit and
// Miss, and a miss queues the domain. Nothing it does blocks the caller.
//
// Each domain is looked up by one worker at a time, and at most once per
// NegativeTTL: a domain that is queued or being looked up is not queued
// again, so a burst of sends from a domain nobody cached yet costs one
// check, and a domain whose result cannot be written does not make every
// send look it up again.
type Refresher struct {
	checker              *Checker
	store                store.Store
	ttl, negTTL, timeout time.Duration
	workers              int
	now                  func() time.Time
	log                  *slog.Logger
	m                    *metrics
	queue                chan string
	// put writes a result; tests replace it.
	put func(ctx context.Context, domain string, r Result, ttl time.Duration) error
	// done, when set, is called once a worker is done with a domain; tests
	// set it.
	done func(domain string)

	mu sync.Mutex
	// pending holds the domains queued or being looked up.
	pending map[string]bool
	// queued holds when each domain was last queued.
	queued  map[string]time.Time
	started bool
	closed  bool

	// ctx is canceled by Close, which ends the lookups in flight.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRefresher returns a Refresher. Start starts its workers.
func NewRefresher(opts Options) (*Refresher, error) {
	if opts.Store == nil || opts.Checker == nil || opts.Checker.Resolver == nil {
		return nil, errors.New("senderauth: Options.Store and a Checker with a Resolver are required")
	}
	if opts.TTL < 0 || opts.NegativeTTL < 0 || opts.Timeout < 0 || opts.Workers < 0 || opts.QueueSize < 0 {
		return nil, errors.New("senderauth: Options.TTL, NegativeTTL, Timeout, Workers and QueueSize must not be negative")
	}
	m, err := newMetrics(opts.Registerer)
	if err != nil {
		return nil, err
	}
	r := &Refresher{
		checker: opts.Checker,
		store:   opts.Store,
		ttl:     cmp.Or(opts.TTL, DefaultTTL),
		negTTL:  cmp.Or(opts.NegativeTTL, DefaultNegativeTTL),
		timeout: cmp.Or(opts.Timeout, DefaultTimeout),
		workers: cmp.Or(opts.Workers, DefaultWorkers),
		now:     opts.Now,
		log:     opts.Logger,
		m:       m,
		queue:   make(chan string, cmp.Or(opts.QueueSize, DefaultQueueSize)),
		pending: map[string]bool{},
		queued:  map[string]time.Time{},
	}
	r.negTTL = min(r.negTTL, r.ttl)
	if r.now == nil {
		r.now = time.Now
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	r.put = func(ctx context.Context, domain string, res Result, ttl time.Duration) error {
		return Put(ctx, r.store, domain, res, ttl)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	m.queued.Set(0)
	return r, nil
}

// Start starts the workers. It does nothing after the first call or after
// Close.
func (r *Refresher) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.closed {
		return
	}
	r.started = true
	for range r.workers {
		r.wg.Go(r.work)
	}
}

// Close stops the workers, canceling the lookups in flight, whose results
// are not written, and drops the queued domains. It waits for the workers
// until ctx ends.
func (r *Refresher) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Hit counts a cache read that found the domain.
func (r *Refresher) Hit() { r.m.hit.Inc() }

// Miss counts a cache read that found nothing usable for domain, and queues
// it for a lookup.
func (r *Refresher) Miss(domain string) {
	r.m.miss.Inc()
	r.Enqueue(domain)
}

// Enqueue queues domain, normalized, for a lookup, unless it is queued or
// being looked up already, was queued less than NegativeTTL ago, or the
// Refresher is closed. It never blocks: when the queue is full the domain
// is dropped and counted. It reports whether the domain was queued.
func (r *Refresher) Enqueue(domain string) bool {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return false
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.pending[domain] {
		return false
	}
	if at, ok := r.queued[domain]; ok && now.Sub(at) < r.negTTL {
		return false
	}
	if len(r.queued) >= maxTracked {
		for d, at := range r.queued {
			if now.Sub(at) >= r.negTTL {
				delete(r.queued, d)
			}
		}
		if len(r.queued) >= maxTracked {
			r.m.dropped.Inc()
			return false
		}
	}
	select {
	case r.queue <- domain:
	default:
		r.m.dropped.Inc()
		return false
	}
	r.pending[domain] = true
	r.queued[domain] = now
	r.m.queued.Set(float64(len(r.queue)))
	return true
}

func (r *Refresher) work() {
	for {
		select {
		case <-r.ctx.Done():
			return
		case domain := <-r.queue:
			r.m.queued.Set(float64(len(r.queue)))
			r.refresh(domain)
			r.mu.Lock()
			delete(r.pending, domain)
			r.mu.Unlock()
			if r.done != nil {
				r.done(domain)
			}
		}
	}
}

// refresh checks domain and caches the result.
func (r *Refresher) refresh(domain string) {
	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	start := time.Now()
	rep := r.checker.Check(ctx, domain)
	cancel()
	r.m.duration.Observe(time.Since(start).Seconds())
	if r.ctx.Err() != nil {
		// Closing cut the check short: its unknowns say nothing about the
		// domain.
		return
	}
	res := rep.Result(r.now())
	r.m.lookups.WithLabelValues("spf", res.SPF).Inc()
	r.m.lookups.WithLabelValues("dkim", res.DKIM).Inc()
	r.m.lookups.WithLabelValues("dmarc", res.DMARCPolicy).Inc()
	ttl := r.ttl
	if res.negative(len(r.checker.Selectors) > 0) {
		ttl = r.negTTL
	}
	wctx, wcancel := context.WithTimeout(r.ctx, r.timeout)
	defer wcancel()
	if err := r.put(wctx, domain, res, ttl); err != nil {
		r.m.writeErrors.Inc()
		r.log.Warn("sender authentication result could not be cached", "domain", domain, "error", err)
	}
}

// Put caches res as domain's result in s, for ttl.
func Put(ctx context.Context, s store.Store, domain string, res Result, ttl time.Duration) error {
	var b store.Batch
	b.Set(CacheKey(domain), res.encode(), ttl)
	return s.Do(ctx, &b)
}

// Get reads domain's cached result from s. It returns false when nothing
// readable is cached.
func Get(ctx context.Context, s store.Store, domain string) (Result, bool, error) {
	var b store.Batch
	v := b.Get(CacheKey(domain))
	if err := s.Do(ctx, &b); err != nil {
		return Result{}, false, err
	}
	if !v.Found() {
		return Result{}, false, nil
	}
	res, ok := DecodeResult(v.Val())
	return res, ok, nil
}

type metrics struct {
	lookups     *prometheus.CounterVec
	hit, miss   prometheus.Counter
	dropped     prometheus.Counter
	writeErrors prometheus.Counter
	duration    prometheus.Histogram
	queued      prometheus.Gauge
}

// lookupOutcomes are the states each kind of check can end in.
var lookupOutcomes = map[string][]string{
	"spf":   {Found, Missing, Invalid, Unknown},
	"dkim":  {Found, Revoked, Missing, Invalid, Unknown},
	"dmarc": {PolicyNone, PolicyQuarantine, PolicyReject, Missing, Invalid, Unknown},
}

func newMetrics(reg prometheus.Registerer) (*metrics, error) {
	cache := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "catraca_sender_auth_cache_reads_total",
		Help: "Reads of the sender authentication cache by sends, by result: hit, or miss (nothing readable cached; the domain is queued).",
	}, []string{"result"})
	m := &metrics{
		lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "catraca_sender_auth_lookups_total",
			Help: "Sender domain checks, by kind (spf, dkim, dmarc) and the state found.",
		}, []string{"kind", "outcome"}),
		hit:  cache.WithLabelValues("hit"),
		miss: cache.WithLabelValues("miss"),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "catraca_sender_auth_queue_dropped_total",
			Help: "Sender domains not queued for a lookup because the queue was full.",
		}),
		writeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "catraca_sender_auth_write_errors_total",
			Help: "Sender domain checks whose result could not be written to the store.",
		}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "catraca_sender_auth_lookup_duration_seconds",
			Help:    "Time to check one sender domain, every DNS lookup included.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}),
		queued: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "catraca_sender_auth_queued",
			Help: "Sender domains waiting for a lookup.",
		}),
	}
	for kind, outcomes := range lookupOutcomes {
		for _, o := range outcomes {
			m.lookups.WithLabelValues(kind, o)
		}
	}
	if reg == nil {
		return m, nil
	}
	for _, c := range []prometheus.Collector{m.lookups, cache, m.dropped, m.writeErrors, m.duration, m.queued} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}
