// Package hooks calls the platform's webhooks for the effects of enforced
// rules, such as revoking an API key or suspending an account.
//
// Dispatch writes one delivery per effect to a durable outbox before it
// returns; Run delivers them. Each request is signed with HMAC-SHA256 (see
// Sign and Verify), carries an idempotency key that is the same on every
// attempt, and is retried with exponential backoff and jitter until it gets a
// 2xx response or runs out of attempts.
package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// Hook is a webhook that carries out one effect.
type Hook struct {
	// Name is the effect the hook carries out, as rules list it under
	// effects, for example "revoke_key".
	Name string
	// URL receives a POST with a JSON Payload. http or https.
	URL string
	// Secret keys the request signature. Required.
	Secret string
	// Timeout bounds one attempt. Default 10s.
	Timeout time.Duration
	// Headers are added to every request, for example an Authorization
	// header. They cannot replace the Catraca-* headers.
	Headers map[string]string
}

// Config configures a Dispatcher. Zero values take the defaults.
type Config struct {
	Hooks []Hook
	// MaxAttempts is how many times a delivery is tried before it is marked
	// dead. Default 15, which with the default backoff keeps retrying for
	// 45 to 90 minutes.
	MaxAttempts int
	// MinBackoff is the wait after the first failed attempt; it doubles with
	// each further failure, up to MaxBackoff. Each wait is jittered to
	// between half and all of its value. Defaults 2s and 15m.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// PollInterval is how often Run looks for due deliveries when Dispatch
	// has not woken it. Default 2s.
	PollInterval time.Duration
	// Concurrency is how many deliveries are attempted at once. Default 4.
	Concurrency int
	// EnqueueTimeout bounds the outbox write in Dispatch. Default 5s.
	EnqueueTimeout time.Duration
	// Client sends the requests. The default client does not follow
	// redirects: a 3xx response is a failed attempt.
	Client *http.Client
	// Logger receives delivery failures. Default slog.Default().
	Logger *slog.Logger
}

const defaultHookTimeout = 10 * time.Second

func (c Config) withDefaults() Config {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 15
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = 2 * time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 15 * time.Minute
	}
	c.MaxBackoff = max(c.MaxBackoff, c.MinBackoff)
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.EnqueueTimeout <= 0 {
		c.EnqueueTimeout = 5 * time.Second
	}
	if c.Client == nil {
		c.Client = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Payload is the JSON body of a delivery.
type Payload struct {
	Effect     string          `json:"effect"`
	DecisionID string          `json:"decision_id"`
	EventID    string          `json:"event_id,omitempty"`
	EventType  event.Type      `json:"event_type"`
	AccountID  string          `json:"account_id"`
	APIKeyID   string          `json:"api_key_id,omitempty"`
	Action     decision.Action `json:"action"`
	// RuleIDs are the enforced rules that matched and list this effect;
	// Reasons are their reasons, in the same order.
	RuleIDs []string `json:"rule_ids"`
	Reasons []string `json:"reasons"`
	// Time is when the decision was made.
	Time time.Time `json:"time"`
}

// Stats counts what the dispatcher did since it was created. Export them as
// metrics.
type Stats struct {
	// Enqueued deliveries were written to the outbox; a repeated
	// (decision, effect) is not counted again.
	Enqueued uint64
	// EnqueueErrors are deliveries Dispatch could not write.
	EnqueueErrors uint64
	// Delivered deliveries got a 2xx response.
	Delivered uint64
	// Retried counts failed attempts that will be tried again.
	Retried uint64
	// Dead deliveries were given up.
	Dead uint64
}

// Dispatcher enqueues and delivers effect webhooks. It is safe for
// concurrent use.
type Dispatcher struct {
	outbox audit.Outbox
	cfg    Config
	hooks  map[string]Hook
	log    *slog.Logger
	// now is the clock for scheduling and signing; tests replace it.
	now func() time.Time
	// lease is how long a claimed delivery is reserved for its attempt.
	lease time.Duration
	wake  chan struct{}

	enqueued      atomic.Uint64
	enqueueErrors atomic.Uint64
	delivered     atomic.Uint64
	retried       atomic.Uint64
	dead          atomic.Uint64
}

// New returns a Dispatcher that writes to and delivers from outbox, usually
// an *audit.DB. It checks the hooks: each needs a unique name, an http(s)
// URL and a secret.
func New(outbox audit.Outbox, cfg Config) (*Dispatcher, error) {
	if outbox == nil {
		return nil, errors.New("hooks: nil outbox")
	}
	cfg = cfg.withDefaults()
	d := &Dispatcher{
		outbox: outbox,
		cfg:    cfg,
		hooks:  make(map[string]Hook, len(cfg.Hooks)),
		log:    cfg.Logger,
		now:    time.Now,
		wake:   make(chan struct{}, 1),
	}
	var longest time.Duration
	for _, h := range cfg.Hooks {
		if err := validateHook(h); err != nil {
			return nil, err
		}
		if _, dup := d.hooks[h.Name]; dup {
			return nil, fmt.Errorf("hooks: hook %q is configured twice", h.Name)
		}
		if h.Timeout == 0 {
			h.Timeout = defaultHookTimeout
		}
		longest = max(longest, h.Timeout)
		d.hooks[h.Name] = h
	}
	// The lease outlasts the slowest attempt, so a delivery is not claimed
	// twice while its first attempt is still running.
	d.lease = longest + 30*time.Second
	return d, nil
}

func validateHook(h Hook) error {
	if h.Name == "" {
		return errors.New("hooks: a hook has no name")
	}
	u, err := url.Parse(h.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("hooks: hook %q: url must be an absolute http or https URL, got %q", h.Name, h.URL)
	}
	if h.Secret == "" {
		return fmt.Errorf("hooks: hook %q: secret is required", h.Name)
	}
	if h.Timeout < 0 {
		return fmt.Errorf("hooks: hook %q: negative timeout", h.Name)
	}
	return nil
}

// Configured reports whether a hook carries out effect. Use it to check that
// every effect named in a ruleset has a hook.
func (d *Dispatcher) Configured(effect string) bool {
	_, ok := d.hooks[effect]
	return ok
}

// Stats returns the dispatcher's counters.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		Enqueued:      d.enqueued.Load(),
		EnqueueErrors: d.enqueueErrors.Load(),
		Delivered:     d.delivered.Load(),
		Retried:       d.retried.Load(),
		Dead:          d.dead.Load(),
	}
}

// Dispatch writes a delivery to the outbox for each effect of dec's enforced
// matches that has a hook, then wakes Run. Effects without a hook are
// skipped. Dispatching the same decision again adds nothing.
//
// Once Dispatch returns, the deliveries survive a restart. It blocks for the
// outbox write, at most EnqueueTimeout, even if ctx is canceled first: the
// decision has been made and its effects must not be lost. Failures are
// logged and counted, not returned, because the decision stands either way.
func (d *Dispatcher) Dispatch(ctx context.Context, ev event.Event, dec decision.Decision) {
	var ds []audit.Delivery
	now := d.now()
	for _, effect := range dec.Effects() {
		if !d.Configured(effect) {
			d.log.Debug("hooks: no hook for effect", "effect", effect, "decision_id", dec.ID)
			continue
		}
		body, err := json.Marshal(newPayload(effect, ev, dec))
		if err != nil {
			d.enqueueErrors.Add(1)
			d.log.Error("hooks: encode payload", "effect", effect, "decision_id", dec.ID, "err", err)
			continue
		}
		ds = append(ds, audit.Delivery{DecisionID: dec.ID, Effect: effect, Payload: body, CreatedAt: now})
	}
	if len(ds) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.cfg.EnqueueTimeout)
	defer cancel()
	n, err := d.outbox.Enqueue(ctx, ds)
	if err != nil {
		d.enqueueErrors.Add(uint64(len(ds)))
		d.log.Error("hooks: enqueue deliveries", "decision_id", dec.ID, "count", len(ds), "err", err)
		return
	}
	d.enqueued.Add(uint64(n))
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func newPayload(effect string, ev event.Event, dec decision.Decision) Payload {
	p := Payload{
		Effect:     effect,
		DecisionID: dec.ID,
		EventID:    dec.EventID,
		EventType:  ev.Type,
		AccountID:  ev.AccountID,
		APIKeyID:   ev.APIKeyID,
		Action:     dec.Action,
		RuleIDs:    []string{},
		Reasons:    []string{},
		Time:       dec.Time,
	}
	if p.EventID == "" {
		p.EventID = ev.ID
	}
	for _, m := range dec.Matches {
		for _, e := range m.Effects {
			if e == effect {
				p.RuleIDs = append(p.RuleIDs, m.RuleID)
				p.Reasons = append(p.Reasons, m.Reason)
				break
			}
		}
	}
	return p
}

// Run delivers due deliveries until ctx is done, then waits for the attempts
// in flight (each bounded by its hook's timeout) and returns nil. Run one
// per process; with Postgres, several processes can run it at once.
func (d *Dispatcher) Run(ctx context.Context) error {
	timer := time.NewTimer(d.cfg.PollInterval)
	defer timer.Stop()
	for {
		n, err := d.deliverDue(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			d.log.Error("hooks: claim deliveries", "err", err)
		} else if n == d.cfg.Concurrency {
			continue // a full batch: more may be due
		}
		timer.Reset(d.cfg.PollInterval)
		select {
		case <-ctx.Done():
			return nil
		case <-d.wake:
		case <-timer.C:
		}
	}
}

// deliverDue claims up to Concurrency due deliveries, attempts them in
// parallel and returns how many it claimed.
func (d *Dispatcher) deliverDue(ctx context.Context) (int, error) {
	ds, err := d.outbox.Claim(ctx, d.now(), d.cfg.Concurrency, d.lease)
	if err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	for _, del := range ds {
		wg.Go(func() { d.deliver(ctx, del) })
	}
	wg.Wait()
	return len(ds), nil
}

// deliver makes one attempt and records its outcome. The attempt and the
// outbox update are not canceled with ctx, so a shutdown lets them finish.
func (d *Dispatcher) deliver(ctx context.Context, del audit.Delivery) {
	ctx = context.WithoutCancel(ctx)
	log := d.log.With("decision_id", del.DecisionID, "effect", del.Effect, "attempt", del.Attempts)

	h, ok := d.hooks[del.Effect]
	if !ok {
		// The hook was removed from the configuration after the delivery
		// was enqueued.
		a := audit.Attempt{At: d.now(), Error: "no hook configured for effect " + strconv.Quote(del.Effect)}
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.MarkDead(ctx, del.ID, a) })
		d.dead.Add(1)
		log.Error("hooks: delivery dead: no hook configured")
		return
	}

	status, retryAfter, err := d.send(ctx, h, del)
	a := audit.Attempt{At: d.now(), StatusCode: status}
	switch {
	case err == nil:
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.MarkDelivered(ctx, del.ID, a) })
		d.delivered.Add(1)
		log.Debug("hooks: delivered", "status", status)
	case del.Attempts >= d.cfg.MaxAttempts:
		a.Error = err.Error()
		d.settle(ctx, log, func(ctx context.Context) error { return d.outbox.MarkDead(ctx, del.ID, a) })
		d.dead.Add(1)
		log.Error("hooks: delivery dead after max attempts", "status", status, "err", err)
	default:
		a.Error = err.Error()
		next := a.At.Add(d.backoff(del.Attempts, retryAfter))
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

// maxSnippet bounds how much of an error response is kept.
const maxSnippet = 512

// send makes one HTTP attempt. It returns the response status (0 without a
// response), the server's Retry-After, and an error unless the status is 2xx.
func (d *Dispatcher) send(ctx context.Context, h Hook, del audit.Delivery) (int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(del.Payload))
	if err != nil {
		return 0, 0, err
	}
	for k, v := range h.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Catraca-Hooks/1")
	req.Header.Set(SignatureHeader, Sign(h.Secret, d.now(), del.Payload))
	req.Header.Set(IdempotencyKeyHeader, del.DecisionID+":"+del.Effect)
	req.Header.Set(AttemptHeader, strconv.Itoa(del.Attempts))

	resp, err := d.cfg.Client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxSnippet))
	// Drain a little more so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, 0, nil
	}
	msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if s := strings.TrimSpace(string(snippet)); s != "" {
		msg += ": " + s
	}
	return resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After"), d.now()), errors.New(msg)
}

// backoff returns the wait before the attempt after attempt number attempt:
// MinBackoff doubled per failure up to MaxBackoff, with equal jitter (half
// fixed, half random) so receivers recovering from an outage are not hit by
// every retry at once. A longer Retry-After from the server wins, still
// capped at MaxBackoff.
func (d *Dispatcher) backoff(attempt int, retryAfter time.Duration) time.Duration {
	b := d.cfg.MaxBackoff
	if shift := attempt - 1; shift >= 0 && shift < 32 {
		if exp := d.cfg.MinBackoff << shift; exp > 0 && exp < b {
			b = exp
		}
	}
	b = b/2 + rand.N(b/2+1)
	if retryAfter > b {
		b = min(retryAfter, d.cfg.MaxBackoff)
	}
	return b
}

// parseRetryAfter reads a Retry-After header in seconds or as an HTTP date.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}
