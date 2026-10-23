// Package secretscan implements GitHub's secret scanning partner endpoint.
//
// When GitHub finds one of the platform's API keys in a public repository,
// gist, issue, npm package or Actions log, it posts a signed batch of the
// matches to the partner's endpoint:
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program
//
// The Handler verifies GitHub's ECDSA signature, accepts the batch at once
// and processes it on a bounded pool of workers. For each token it asks a
// Resolver which API key and account the token belongs to, and hands a
// key_leak event for every key it finds to a Decider, where rules such as
// "revoke a leaked key" act. When feedback is enabled, the answer to GitHub
// labels each token a true or false positive.
package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// Decider decides an event. The engine implements it.
type Decider interface {
	Decide(ctx context.Context, ev event.Event) (decision.Decision, error)
}

// Token is one secret GitHub found in public. Its String, GoString and
// LogValue methods leave Raw out, so a token never reaches a log by
// accident.
type Token struct {
	// Raw is the matched secret.
	Raw string
	// SHA256 is the lowercase hex SHA-256 of Raw.
	SHA256 string
	// Type is the secret type name registered with GitHub.
	Type string
	// URL is the public URL where GitHub found the token. It may be empty.
	URL string
	// Source is where GitHub found the token: content, commit, npm,
	// issue_comment, action_logs and so on.
	Source string
}

func (t Token) String() string {
	return fmt.Sprintf("{type:%s source:%s url:%s sha256:%s}", t.Type, t.Source, t.URL, t.SHA256)
}

// GoString keeps %#v from printing Raw.
func (t Token) GoString() string { return "secretscan.Token" + t.String() }

// LogValue keeps slog from logging Raw.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", t.Type),
		slog.String("source", t.Source),
		slog.String("url", t.URL),
	)
}

// Key is the API key a token belongs to.
type Key struct {
	APIKeyID  string
	AccountID string
}

// ErrNotFound is returned by a Resolver when a token is not one of the
// platform's keys. GitHub is told it is a false positive.
var ErrNotFound = errors.New("secretscan: token is not a known key")

// Resolver finds the API key a token belongs to. It returns ErrNotFound when
// there is none; any other error is retried a few times and then logged,
// and the token gets no feedback label.
type Resolver interface {
	Resolve(ctx context.Context, t Token) (Key, error)
}

// Outcome is what the Handler did with a batch or one of its tokens. The
// values are stable and few, so they can label a metric.
type Outcome string

const (
	// OutcomeAccepted means a batch was verified and queued.
	OutcomeAccepted Outcome = "accepted"
	// OutcomeInvalidSignature means a batch was not signed by GitHub.
	OutcomeInvalidSignature Outcome = "invalid_signature"
	// OutcomeKeysUnavailable means GitHub's public keys could not be
	// fetched, so the batch was answered with 503.
	OutcomeKeysUnavailable Outcome = "keys_unavailable"
	// OutcomeMalformed means a verified body was not a batch of matches.
	OutcomeMalformed Outcome = "malformed"
	// OutcomeTooLarge means the body exceeded Config.MaxBodyBytes.
	OutcomeTooLarge Outcome = "too_large"
	// OutcomeOverloaded means the batch did not fit in the queue, or the
	// handler was shutting down, so it was answered with 503.
	OutcomeOverloaded Outcome = "overloaded"
	// OutcomeLeaked means a token resolved to a key and its key_leak event
	// was decided.
	OutcomeLeaked Outcome = "leaked"
	// OutcomeNotFound means a token is not one of the platform's keys.
	OutcomeNotFound Outcome = "not_found"
	// OutcomeResolveFailed means the Resolver kept failing for a token.
	OutcomeResolveFailed Outcome = "resolve_failed"
	// OutcomeDecideFailed means the Decider kept failing for a leaked key.
	OutcomeDecideFailed Outcome = "decide_failed"
)

// Config configures the Handler.
type Config struct {
	// Decider receives a key_leak event for every token that resolves to a
	// key. Required.
	Decider Decider
	// Resolver maps tokens to keys. Required; see NewHTTPResolver.
	Resolver Resolver

	// Feedback makes the answer to GitHub a JSON array that labels each
	// token resolved within FeedbackTimeout as "true_positive" (a key was
	// found) or "false_positive" (ErrNotFound), identified by token_hash.
	// Enable it once GitHub has enabled feedback for your partnership.
	// Without it the batch is acknowledged with 202 before any token is
	// resolved.
	Feedback bool
	// FeedbackTimeout is how long the handler waits for tokens to resolve
	// before answering GitHub in feedback mode. Tokens still pending are
	// left out of the answer and finish in the background. GitHub waits 30
	// seconds for partners that send feedback; the default is 20 seconds.
	FeedbackTimeout time.Duration

	// Workers bounds how many tokens are resolved at once. The default is 8.
	Workers int
	// MaxPending bounds how many accepted tokens may be unfinished at once.
	// A batch that would exceed it is answered with 503 so GitHub retries
	// it later; a batch that arrives when nothing is pending is always
	// accepted, so an oversized batch is never refused forever. The default
	// is 10000.
	MaxPending int
	// ResolveTimeout bounds each Resolve and Decide call. The default is 10
	// seconds.
	ResolveTimeout time.Duration

	// KeysURL is where GitHub's public keys are fetched. The default is
	// DefaultKeysURL; tests point it at a fake.
	KeysURL string
	// GitHubToken, when set, authenticates the keys request. GitHub
	// recommends a token without scopes to avoid unauthenticated rate
	// limits.
	GitHubToken string
	// HTTPClient fetches the keys. The default times out after 10 seconds.
	HTTPClient *http.Client

	// MaxBodyBytes limits the request body. The default is 10 MiB, room
	// for tens of thousands of matches.
	MaxBodyBytes int64
	// Logger receives errors that are not shown to GitHub. Tokens are never
	// logged. The default discards everything.
	Logger *slog.Logger
	// OnOutcome, when set, is called once per batch outcome and once per
	// token processed, for metrics. It must be safe for concurrent use.
	OnOutcome func(Outcome)
}

const (
	defaultFeedbackTimeout = 20 * time.Second
	defaultWorkers         = 8
	defaultMaxPending      = 10000
	defaultResolveTimeout  = 10 * time.Second
	defaultMaxBodyBytes    = 10 << 20
	defaultKeysMaxAge      = time.Hour
	defaultKeysMinRefresh  = time.Minute
	attempts               = 3
)

// Handler is the secret scanning endpoint. Call Shutdown when the server
// stops, so tokens already accepted finish processing.
type Handler struct {
	decider         Decider
	resolver        Resolver
	feedback        bool
	feedbackTimeout time.Duration
	maxPending      int64
	resolveTimeout  time.Duration
	retryBackoff    time.Duration
	maxBody         int64
	log             *slog.Logger
	onOutcome       func(Outcome)
	keys            *keyring
	now             func() time.Time

	sem     chan struct{}
	pending atomic.Int64
	// base outlives requests; Shutdown cancels it to abort work in flight.
	base   context.Context
	cancel context.CancelFunc

	mu       sync.Mutex // guards closing against inflight.Add
	closing  bool
	inflight sync.WaitGroup
}

// New returns a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Decider == nil {
		return nil, errors.New("secretscan: Decider is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("secretscan: Resolver is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	onOutcome := cfg.OnOutcome
	if onOutcome == nil {
		onOutcome = func(Outcome) {}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	keysURL := cfg.KeysURL
	if keysURL == "" {
		keysURL = DefaultKeysURL
	}
	base, cancel := context.WithCancel(context.Background())
	h := &Handler{
		decider:         cfg.Decider,
		resolver:        cfg.Resolver,
		feedback:        cfg.Feedback,
		feedbackTimeout: orDefault(cfg.FeedbackTimeout, defaultFeedbackTimeout),
		maxPending:      int64(orDefault(cfg.MaxPending, defaultMaxPending)),
		resolveTimeout:  orDefault(cfg.ResolveTimeout, defaultResolveTimeout),
		retryBackoff:    500 * time.Millisecond,
		maxBody:         orDefault(cfg.MaxBodyBytes, defaultMaxBodyBytes),
		log:             log,
		onOutcome:       onOutcome,
		now:             time.Now,
		sem:             make(chan struct{}, orDefault(cfg.Workers, defaultWorkers)),
		base:            base,
		cancel:          cancel,
	}
	h.keys = &keyring{
		url:        keysURL,
		token:      cfg.GitHubToken,
		client:     client,
		maxAge:     defaultKeysMaxAge,
		minRefresh: defaultKeysMinRefresh,
		log:        log,
		now:        time.Now,
	}
	return h, nil
}

func orDefault[T int | int64 | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

// alert is one match in GitHub's batch.
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program#create-a-secret-alert-service
type alert struct {
	Token  flexString `json:"token"`
	Type   string     `json:"type"`
	URL    string     `json:"url"`
	Source string     `json:"source"`
}

// flexString accepts a JSON string or number. GitHub documents token as a
// string, but a numeric match would otherwise fail the whole batch.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n)
	return nil
}

// Feedback labels, the only two values GitHub accepts.
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program#provide-feedback-for-false-positives
const (
	labelTruePositive  = "true_positive"
	labelFalsePositive = "false_positive"
)

// feedbackEntry labels one token. Only the hash is sent: GitHub accepts
// either token_raw or token_hash, and the raw token never needs to leave.
type feedbackEntry struct {
	TokenHash string `json:"token_hash"`
	TokenType string `json:"token_type"`
	Label     string `json:"label"`
}

// result is the outcome of one token of a batch, by index.
type result struct {
	i     int
	label string // "" when unknown
}

// ServeHTTP handles one batch from GitHub. It answers 401 for a missing or
// invalid signature, 400 for a body that is not a batch, 413 for a body over
// the limit, 503 when the keys cannot be fetched or the queue is full, and
// otherwise 202 (or 200 with feedback labels).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.onOutcome(OutcomeTooLarge)
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
			return
		}
		h.onOutcome(OutcomeMalformed)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read body"})
		return
	}

	keyID := strings.TrimSpace(r.Header.Get(keyIDHeader))
	sig := strings.TrimSpace(r.Header.Get(signatureHeader))
	if keyID == "" || sig == "" {
		h.onOutcome(OutcomeInvalidSignature)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing signature"})
		return
	}
	if err := h.keys.verify(r.Context(), keyID, sig, body); err != nil {
		if errors.Is(err, errKeysUnavailable) {
			h.onOutcome(OutcomeKeysUnavailable)
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily unavailable"})
			return
		}
		h.onOutcome(OutcomeInvalidSignature)
		h.log.WarnContext(r.Context(), "secretscan: signature rejected", "key_identifier", keyID, "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	var alerts []alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		h.onOutcome(OutcomeMalformed)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body is not a JSON array of matches"})
		return
	}
	tokens := make([]Token, 0, len(alerts))
	for _, a := range alerts {
		if a.Token == "" {
			continue
		}
		sum := sha256.Sum256([]byte(a.Token))
		tokens = append(tokens, Token{
			Raw:    string(a.Token),
			SHA256: hex.EncodeToString(sum[:]),
			Type:   a.Type,
			URL:    a.URL,
			Source: a.Source,
		})
	}

	var results chan result
	if h.feedback {
		// Buffered for every token, so workers never block on a request
		// that has already been answered.
		results = make(chan result, len(tokens))
	}
	if !h.accept(tokens, results) {
		h.onOutcome(OutcomeOverloaded)
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily unavailable"})
		return
	}
	h.onOutcome(OutcomeAccepted)
	h.log.InfoContext(r.Context(), "secretscan: batch accepted", "tokens", len(tokens))

	if !h.feedback {
		writeJSON(w, http.StatusAccepted, []feedbackEntry{})
		return
	}
	writeJSON(w, http.StatusOK, h.collect(r.Context(), tokens, results))
}

// accept queues tokens, or reports false when the handler is shutting down
// or the batch does not fit.
func (h *Handler) accept(tokens []Token, results chan<- result) bool {
	n := int64(len(tokens))
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing {
		return false
	}
	if n == 0 {
		return true
	}
	if cur := h.pending.Load(); cur > 0 && cur+n > h.maxPending {
		return false
	}
	h.pending.Add(n)
	h.inflight.Add(len(tokens))
	go h.feed(tokens, results, h.now())
	return true
}

// feed hands tokens to workers as slots free up.
func (h *Handler) feed(tokens []Token, results chan<- result, received time.Time) {
	for i, t := range tokens {
		select {
		case h.sem <- struct{}{}:
		case <-h.base.Done():
			for range tokens[i:] {
				h.done()
			}
			return
		}
		go func() {
			defer func() {
				<-h.sem
				h.done()
			}()
			h.process(t, received, func(label string) {
				if results != nil {
					results <- result{i: i, label: label}
				}
			})
		}()
	}
}

func (h *Handler) done() {
	h.pending.Add(-1)
	h.inflight.Done()
}

// collect waits for the batch's results until FeedbackTimeout and returns
// the labels known by then, in batch order.
func (h *Handler) collect(ctx context.Context, tokens []Token, results <-chan result) []feedbackEntry {
	labels := make([]string, len(tokens))
	timer := time.NewTimer(h.feedbackTimeout)
	defer timer.Stop()
wait:
	for got := 0; got < len(tokens); got++ {
		select {
		case res := <-results:
			labels[res.i] = res.label
		case <-timer.C:
			break wait
		case <-ctx.Done():
			break wait
		case <-h.base.Done():
			break wait
		}
	}
	entries := make([]feedbackEntry, 0, len(tokens))
	for i, t := range tokens {
		if labels[i] != "" {
			entries = append(entries, feedbackEntry{TokenHash: t.SHA256, TokenType: t.Type, Label: labels[i]})
		}
	}
	return entries
}

// process resolves one token and, when it is a key, decides its key_leak
// event. It reports the feedback label as soon as the token is resolved, or
// "" when it could not be, so a slow decision does not delay the answer to
// GitHub.
func (h *Handler) process(t Token, received time.Time, report func(label string)) {
	var key Key
	err := h.retry(func(ctx context.Context) error {
		var err error
		key, err = h.resolver.Resolve(ctx, t)
		if err == nil && key.APIKeyID == "" {
			return errors.New("resolver returned a key without an id")
		}
		return err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		h.onOutcome(OutcomeNotFound)
		report(labelFalsePositive)
		return
	case err != nil:
		h.onOutcome(OutcomeResolveFailed)
		h.log.Error("secretscan: resolving token", "token", t, "error", err)
		report("")
		return
	}
	// The token is a real key whether or not the decision goes through.
	report(labelTruePositive)

	ev := event.Event{
		Type:       event.KeyLeak,
		Time:       received,
		AccountID:  key.AccountID,
		APIKeyID:   key.APIKeyID,
		Leak:       &event.LeakInfo{Source: leakSource(t.Source), URL: t.URL},
		Attributes: map[string]string{"secret_type": t.Type},
	}
	err = h.retry(func(ctx context.Context) error {
		_, err := h.decider.Decide(ctx, ev)
		return err
	})
	if err != nil {
		h.onOutcome(OutcomeDecideFailed)
		h.log.Error("secretscan: deciding key leak", "api_key_id", key.APIKeyID, "account_id", key.AccountID, "error", err)
	} else {
		h.onOutcome(OutcomeLeaked)
		h.log.Info("secretscan: leaked key reported", "api_key_id", key.APIKeyID, "account_id", key.AccountID, "token", t)
	}
}

func leakSource(githubSource string) string {
	if githubSource == "" {
		return "github"
	}
	return "github:" + githubSource
}

// retry calls f up to three times with backoff, each call bounded by
// ResolveTimeout. ErrNotFound, an event refused as invalid (a key id from
// the resolver with control characters, say) and shutdown end it early.
func (h *Handler) retry(f func(ctx context.Context) error) error {
	var err error
	backoff := h.retryBackoff
	for attempt := range attempts {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
				backoff *= 2
			case <-h.base.Done():
				return err
			}
		}
		ctx, cancel := context.WithTimeout(h.base, h.resolveTimeout)
		err = f(ctx)
		cancel()
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, event.ErrInvalid) || h.base.Err() != nil {
			return err
		}
	}
	return err
}

// Shutdown stops accepting batches and waits for accepted tokens to finish.
// When ctx ends first it aborts the work in flight and returns ctx's error.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closing = true
	h.mu.Unlock()
	finished := make(chan struct{})
	go func() {
		h.inflight.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		h.cancel()
		return nil
	case <-ctx.Done():
		h.cancel()
		return ctx.Err()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
