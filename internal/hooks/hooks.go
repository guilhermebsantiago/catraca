// Package hooks calls the platform's webhooks for the effects of enforced
// rules, such as revoking an API key or suspending an account.
//
// Dispatch writes one delivery per effect to a durable outbox; Run delivers
// them. Each hook takes its own deliveries, at most its Concurrency at a
// time out of Workers shared by every hook, so one slow endpoint never holds
// up another's. Each request is signed in the signature.Header header
// (receivers verify it with signature.Verify), carries an idempotency key
// that is the same on every attempt, and is retried with exponential backoff
// and jitter until it gets a 2xx response, runs out of attempts or outlives
// its hook's MaxAge.
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/signature"
)

// Headers sent with every delivery, next to signature.Header.
const (
	// IdempotencyKeyHeader carries "<decision id>:<effect>". It is the same
	// on every attempt of a delivery: receivers should act on a key once.
	IdempotencyKeyHeader = "Catraca-Idempotency-Key"
	// AttemptHeader carries the attempt number, starting at 1.
	AttemptHeader = "Catraca-Attempt"
)

// Defaults for the zero values of Hook and Config.
const (
	DefaultTimeout     = 10 * time.Second
	DefaultConcurrency = 4
	DefaultMaxAttempts = 15
	DefaultMaxAge      = 24 * time.Hour
	DefaultWorkers     = 16
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
	// PreviousSecrets are secrets being rotated out. Each request carries a
	// v1 signature for Secret and then one for each of them, so a receiver
	// that has not switched to Secret yet still accepts it.
	PreviousSecrets []string
	// Timeout bounds one attempt. Default DefaultTimeout.
	Timeout time.Duration
	// Headers are added to every request, for example an Authorization
	// header. They cannot replace the Catraca-* headers.
	Headers map[string]string
	// Concurrency is how many of the hook's deliveries are attempted at
	// once, at most Config.Workers. Default Config.Concurrency.
	Concurrency int
	// MaxAttempts is how many times a delivery is tried before it is marked
	// dead. Default Config.MaxAttempts.
	MaxAttempts int
	// MaxAge is how long a delivery is tried for, from when it was queued
	// (audit.Delivery.QueuedAt). One not delivered by then is marked dead:
	// an effect that late, such as suspending an account a day after the
	// abuse, may no longer be wanted. Default Config.MaxAge.
	MaxAge time.Duration
}

// Config configures a Dispatcher. Zero values take the defaults.
type Config struct {
	Hooks []Hook
	// Workers is how many deliveries are attempted at once across every
	// hook. Each hook takes at most its own Concurrency of them. Default
	// DefaultWorkers.
	Workers int
	// Concurrency is the Concurrency of hooks that do not set one. Default
	// DefaultConcurrency.
	Concurrency int
	// MaxAttempts is the MaxAttempts of hooks that do not set one. Default
	// DefaultMaxAttempts, which with the default backoff keeps retrying for
	// 45 to 90 minutes.
	MaxAttempts int
	// MaxAge is the MaxAge of hooks that do not set one. Default
	// DefaultMaxAge. Deliveries for an effect no hook carries out are given
	// up at this age: until then another instance, configured with the
	// hook, may still deliver them.
	MaxAge time.Duration
	// MinBackoff is the wait after the first failed attempt; it doubles with
	// each further failure, up to MaxBackoff. Each wait is jittered to
	// between half and all of its value. Defaults 2s and 15m.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// PollInterval is how often Run looks for due deliveries when Dispatch
	// has not woken it. Default 2s.
	PollInterval time.Duration
	// BacklogInterval is how often Run counts the deliveries waiting for
	// each hook (Backlog) and gives up those past their max age. Default
	// 15s.
	BacklogInterval time.Duration
	// EnqueueTimeout bounds an outbox write of Dispatch, including the part
	// that runs on after Dispatch returned. Default 5s.
	EnqueueTimeout time.Duration
	// MaxWrites bounds the outbox writes in flight. While that many are,
	// the outbox is not keeping up, and Dispatch gives up on new effects at
	// once instead of piling up more. Default 1024.
	MaxWrites int
	// Client sends the requests. The default client does not follow
	// redirects: a 3xx response is a failed attempt.
	Client *http.Client
	// Logger receives delivery failures. Default slog.Default().
	Logger *slog.Logger
}

func (c Config) withDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = DefaultWorkers
	}
	if c.Concurrency <= 0 {
		c.Concurrency = min(DefaultConcurrency, c.Workers)
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.MaxAge <= 0 {
		c.MaxAge = DefaultMaxAge
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
	if c.BacklogInterval <= 0 {
		c.BacklogInterval = 15 * time.Second
	}
	if c.EnqueueTimeout <= 0 {
		c.EnqueueTimeout = 5 * time.Second
	}
	if c.MaxWrites <= 0 {
		c.MaxWrites = 1024
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
	// EnqueueErrors are deliveries Dispatch could not write: effects that
	// are lost, each logged.
	EnqueueErrors uint64
	// Deferred deliveries outlasted the wait of their Dispatch (the engine's
	// dispatch budget), so the decision was answered before they were
	// durable. Their write went on, and each is also counted in Enqueued or
	// EnqueueErrors once it ends.
	Deferred uint64
	// Delivered deliveries got a 2xx response.
	Delivered uint64
	// Retried counts failed attempts that will be tried again.
	Retried uint64
	// Dead deliveries were given up.
	Dead uint64
	// Expired deliveries were given up without another attempt because
	// they outlived their hook's max age waiting, or because no hook
	// carries out their effect. They are also counted in Dead.
	Expired uint64
}

// Dispatcher enqueues and delivers effect webhooks. It is safe for
// concurrent use.
type Dispatcher struct {
	outbox audit.Outbox
	cfg    Config
	// hooks are the configured hooks by name, with their defaults applied;
	// names lists them in configuration order.
	hooks map[string]Hook
	names []string
	log   *slog.Logger
	// now is the clock for scheduling and signing; tests replace it.
	now func() time.Time
	// claimTimeout bounds each claim and each refresh of the backlog;
	// tests shorten it.
	claimTimeout time.Duration
	wake         chan struct{}

	// writes holds a token for each outbox write in flight, and writing
	// counts them, so Run can wait for the writes Dispatch left running.
	writes  chan struct{}
	writing sync.WaitGroup
	// overloadLog limits the log of effects lost to a full writes, which
	// counts them meanwhile in overloadLost.
	overloadLog  limiter
	overloadLost atomic.Uint64

	// backlog is what the last refresh found waiting in the outbox.
	backlog atomic.Pointer[[]audit.Backlog]

	enqueued      atomic.Uint64
	enqueueErrors atomic.Uint64
	deferred      atomic.Uint64
	delivered     atomic.Uint64
	retried       atomic.Uint64
	dead          atomic.Uint64
	expired       atomic.Uint64
}

// New returns a Dispatcher that writes to and delivers from outbox, usually
// an *audit.DB. It checks the hooks: each needs a unique name, an http(s)
// URL, a secret, and a concurrency no higher than the workers.
func New(outbox audit.Outbox, cfg Config) (*Dispatcher, error) {
	if outbox == nil {
		return nil, errors.New("hooks: nil outbox")
	}
	cfg = cfg.withDefaults()
	d := &Dispatcher{
		outbox:       outbox,
		cfg:          cfg,
		hooks:        make(map[string]Hook, len(cfg.Hooks)),
		log:          cfg.Logger,
		now:          time.Now,
		claimTimeout: claimTimeout,
		wake:         make(chan struct{}, 1),
		writes:       make(chan struct{}, cfg.MaxWrites),
	}
	for _, h := range cfg.Hooks {
		if err := validateHook(h); err != nil {
			return nil, err
		}
		if _, dup := d.hooks[h.Name]; dup {
			return nil, fmt.Errorf("hooks: hook %q is configured twice", h.Name)
		}
		if h.Timeout == 0 {
			h.Timeout = DefaultTimeout
		}
		if h.Concurrency == 0 {
			h.Concurrency = cfg.Concurrency
		}
		if h.MaxAttempts == 0 {
			h.MaxAttempts = cfg.MaxAttempts
		}
		if h.MaxAge == 0 {
			h.MaxAge = cfg.MaxAge
		}
		if h.Concurrency > cfg.Workers {
			return nil, fmt.Errorf("hooks: hook %q: concurrency %d is more than the %d workers", h.Name, h.Concurrency, cfg.Workers)
		}
		d.hooks[h.Name] = h
		d.names = append(d.names, h.Name)
	}
	return d, nil
}

// secrets returns the secrets requests are signed with: Secret first, then
// the previous ones.
func (h Hook) secrets() []string {
	return append([]string{h.Secret}, h.PreviousSecrets...)
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
	if slices.Contains(h.PreviousSecrets, "") {
		return fmt.Errorf("hooks: hook %q: a previous secret is empty", h.Name)
	}
	if h.Timeout < 0 || h.Concurrency < 0 || h.MaxAttempts < 0 || h.MaxAge < 0 {
		return fmt.Errorf("hooks: hook %q: negative timeout, concurrency, max attempts or max age", h.Name)
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
		Deferred:      d.deferred.Load(),
		Delivered:     d.delivered.Load(),
		Retried:       d.retried.Load(),
		Dead:          d.dead.Load(),
		Expired:       d.expired.Load(),
	}
}

// Dispatch writes a delivery to the outbox for each effect of dec's enforced
// matches that has a hook, then wakes Run. Effects without a hook are
// skipped. Dispatching the same decision again adds nothing.
//
// Dispatch returns once the deliveries are written, so they survive a
// restart, or when ctx is done, whichever comes first. The engine gives it
// its dispatch budget that way, so a slow outbox never holds a decision up
// for long. Canceling ctx never cancels the write: it goes on in the
// background, for at most EnqueueTimeout, because the decision has been made
// and its effects must not be lost. Deliveries whose write fails, or that
// find MaxWrites writes in flight, are lost: they are counted and logged,
// with what to carry out by hand, not returned, because the decision stands
// either way.
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
	select {
	case d.writes <- struct{}{}:
	default:
		d.overloaded(ev, dec, ds)
		return
	}
	written := make(chan struct{})
	d.writing.Go(func() {
		defer func() { <-d.writes }()
		defer close(written)
		d.write(ctx, ev, dec, ds)
	})
	select {
	case <-written:
	case <-ctx.Done():
		d.deferred.Add(uint64(len(ds)))
	}
}

// write writes ds to the outbox, for at most EnqueueTimeout whatever
// happens to ctx.
func (d *Dispatcher) write(ctx context.Context, ev event.Event, dec decision.Decision, ds []audit.Delivery) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.cfg.EnqueueTimeout)
	defer cancel()
	n, err := d.outbox.Enqueue(ctx, ds)
	if err != nil {
		d.enqueueErrors.Add(uint64(len(ds)))
		// The log line is the only trace of these effects, so it names
		// what to carry out by hand.
		d.log.Error("hooks: effects lost: they could not be written to the outbox; carry them out by hand",
			"decision_id", dec.ID, "effects", effectNames(ds), "account_id", ev.AccountID, "api_key_id", ev.APIKeyID, "err", err)
		return
	}
	d.enqueued.Add(uint64(n))
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// overloaded gives up on ds because MaxWrites writes are in flight. Then
// effects may be lost by the hundred each second, so the log is limited to
// a line a second, which counts the effects lost since the last one.
func (d *Dispatcher) overloaded(ev event.Event, dec decision.Decision, ds []audit.Delivery) {
	d.enqueueErrors.Add(uint64(len(ds)))
	d.overloadLost.Add(uint64(len(ds)))
	if !d.overloadLog.allow(time.Now()) {
		return
	}
	d.log.Error("hooks: effects lost: the outbox is not keeping up, with too many writes in flight; carry them out by hand",
		"decision_id", dec.ID, "effects", effectNames(ds), "account_id", ev.AccountID, "api_key_id", ev.APIKeyID,
		"writes_in_flight", d.cfg.MaxWrites, "lost_since_last_line", d.overloadLost.Swap(0))
}

func effectNames(ds []audit.Delivery) []string {
	names := make([]string, len(ds))
	for i, del := range ds {
		names[i] = del.Effect
	}
	return names
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
		if m.Errored {
			continue
		}
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
	// Signed at each attempt, not when queued, so a delivery that waited
	// through a rotation carries the secrets configured now.
	req.Header.Set(signature.Header, signature.SignAll(h.secrets(), d.now(), del.Payload))
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

// limiter lets one log line through per second.
type limiter struct {
	last atomic.Int64
}

func (l *limiter) allow(now time.Time) bool {
	last := l.last.Load()
	if now.UnixNano()-last < int64(time.Second) {
		return false
	}
	return l.last.CompareAndSwap(last, now.UnixNano())
}
