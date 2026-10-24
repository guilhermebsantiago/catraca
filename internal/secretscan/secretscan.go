// Package secretscan implements GitHub's secret scanning partner endpoint.
//
// When GitHub finds one of the platform's API keys in a public repository,
// gist, issue, npm package or Actions log, it posts a signed batch of the
// matches to the partner's endpoint:
// https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program
//
// The Handler verifies GitHub's ECDSA signature and stores a report for
// each match in a durable queue, the audit database, before it answers, so
// a batch it acknowledged survives a restart and any outage after that;
// when it cannot store the batch it answers 503 and GitHub sends it again.
// Workers process the queue: for each report they ask a Resolver which API
// key and account the token belongs to, and hand a key_leak event for every
// key found to a Decider, where rules such as "revoke a leaked key" act.
// Failures are retried with backoff within bounds on attempts and age, a
// report delivered twice is processed once, and several processes can share
// the queue. When feedback is enabled, the answer to GitHub labels each
// token resolved in time as a true or false positive.
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
	"unicode/utf8"

	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/audit"
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
	// Raw is the matched secret. A Resolver gets it only when
	// Config.RawTokenSecret is set; otherwise it is empty and the token is
	// known by its hash.
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
// there is none; any other error is retried with backoff until the report's
// bounds run out.
type Resolver interface {
	Resolve(ctx context.Context, t Token) (Key, error)
}

// Outcome is what the Handler did with a batch or one of its reports. The
// values are stable and few, so they can label a metric.
type Outcome string

const (
	// OutcomeAccepted means a batch was verified and its reports stored.
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
	// OutcomeUnavailable means the batch's reports could not be stored,
	// for example while the audit database is not open yet, or the handler
	// was shutting down, so the batch was answered with 503 and GitHub
	// sends it again.
	OutcomeUnavailable Outcome = "unavailable"
	// OutcomeDuplicate means a report in an accepted batch was already
	// stored: GitHub delivered it before, and it is not processed again.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeLeaked means a report's token resolved to a key and its
	// key_leak event was decided.
	OutcomeLeaked Outcome = "leaked"
	// OutcomeNotFound means a report's token is not one of the platform's
	// keys.
	OutcomeNotFound Outcome = "not_found"
	// OutcomeRetry means an attempt at a report failed, at the Resolver or
	// the Decider, and the report will be tried again.
	OutcomeRetry Outcome = "retry"
	// OutcomeResolveFailed means a report is dead because its token could
	// not be resolved within its bounds.
	OutcomeResolveFailed Outcome = "resolve_failed"
	// OutcomeDecideFailed means a report is dead because its key_leak event
	// could not be decided within its bounds, or was refused as invalid.
	OutcomeDecideFailed Outcome = "decide_failed"
)

// Config configures the Handler.
type Config struct {
	// Decider receives a key_leak event for every token that resolves to a
	// key. Required.
	Decider Decider
	// Resolver maps tokens to keys. Required; see NewHTTPResolver.
	Resolver Resolver
	// Reports is the durable queue a batch's reports are stored in before
	// it is acknowledged, usually the audit database. Required.
	Reports audit.LeakReports

	// RawTokenSecret, when set, keeps each raw token with its report,
	// encrypted with a key derived from this secret, until the token
	// resolves, and hands it to the Resolver as Token.Raw. Set it only for
	// a Resolver that needs the raw token, such as an HTTPResolver with
	// SendRawToken. Without it only the token's SHA-256 is stored, and
	// Token.Raw is empty.
	RawTokenSecret string
	// RawTokenPreviousSecrets are secrets RawTokenSecret replaced. Raw
	// tokens are sealed with RawTokenSecret only, and opened with whichever
	// of these sealed them, so the reports that wait in the queue while
	// the secret is rotated still resolve. Keep each until no report
	// sealed with it can still be retried: MaxAge after the rotation, and
	// until the dead reports have been requeued or dropped.
	RawTokenPreviousSecrets []string

	// Feedback makes the answer to GitHub a JSON array that labels each
	// token resolved within FeedbackTimeout as "true_positive" (a key was
	// found) or "false_positive" (ErrNotFound), identified by token_hash.
	// Enable it once GitHub has enabled feedback for your partnership.
	// Without it the batch is acknowledged with 202 as soon as it is
	// stored.
	Feedback bool
	// FeedbackTimeout is how long the handler waits for tokens to resolve
	// before answering GitHub in feedback mode. Tokens still pending are
	// left out of the answer and finish in the background. GitHub waits 30
	// seconds for partners that send feedback; the default is 20 seconds.
	FeedbackTimeout time.Duration

	// Workers bounds how many reports are processed at once. The default
	// is 8.
	Workers int
	// ResolveTimeout bounds each Resolve and Decide call. The default is 10
	// seconds.
	ResolveTimeout time.Duration
	// MaxAttempts is how many times a report is tried before it is given
	// up as dead. The default is DefaultMaxAttempts.
	MaxAttempts int
	// MaxAge is how long a report is retried, from when it arrived or was
	// requeued, before it is given up as dead. The default is
	// DefaultMaxAge.
	MaxAge time.Duration
	// MinBackoff is the wait after a report's first failed attempt; it
	// doubles with each further failure, up to MaxBackoff. Each wait is
	// jittered to between half and all of its value. The defaults are 1
	// second and 5 minutes: a leaked key is urgent, so once the resolver is
	// back, waiting reports go through within minutes.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// PollInterval is how often the queue is checked when nothing woke the
	// workers, which picks up reports another process stored and reports
	// requeued by hand. The default is 2 seconds.
	PollInterval time.Duration

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
	// report outcome, for metrics. It must be safe for concurrent use.
	OnOutcome func(Outcome)
	// OnAttempt, when set, is told about every attempt at a report, for
	// metrics. It must be safe for concurrent use and return quickly.
	OnAttempt func(ctx context.Context, a AttemptResult)
	// TracerProvider, when set, traces every attempt at a report: the
	// resolver's request, which carries its W3C traceparent, and the
	// decision. Nil turns tracing off.
	TracerProvider trace.TracerProvider

	// now is the clock, for tests.
	now func() time.Time
	// claimTimeout replaces claimTimeout, for tests.
	claimTimeout time.Duration
}

// Defaults for the bounds on a report. With the default backoff the age
// ends a report first: it is retried for a day.
const (
	DefaultMaxAttempts = 1000
	DefaultMaxAge      = 24 * time.Hour
)

const (
	defaultFeedbackTimeout = 20 * time.Second
	defaultWorkers         = 8
	defaultResolveTimeout  = 10 * time.Second
	defaultMinBackoff      = time.Second
	defaultMaxBackoff      = 5 * time.Minute
	defaultPollInterval    = 2 * time.Second
	defaultMaxBodyBytes    = 10 << 20
	defaultKeysMaxAge      = time.Hour
	defaultKeysMinRefresh  = time.Minute
	// storeTimeout bounds storing a batch's reports, so a slow database
	// turns into a 503 GitHub retries rather than a request that hangs.
	storeTimeout = 10 * time.Second
)

// Handler is the secret scanning endpoint and the workers that process its
// reports. The workers start with New; call Shutdown when the server stops.
type Handler struct {
	decider         Decider
	resolver        Resolver
	reports         audit.LeakReports
	seal            *sealer
	feedback        bool
	feedbackTimeout time.Duration
	workers         int
	resolveTimeout  time.Duration
	maxAttempts     int
	maxAge          time.Duration
	minBackoff      time.Duration
	maxBackoff      time.Duration
	pollInterval    time.Duration
	claimTimeout    time.Duration
	lease           time.Duration
	maxBody         int64
	log             *slog.Logger
	onOutcome       func(Outcome)
	onAttempt       func(context.Context, AttemptResult)
	keys            *keyring
	now             func() time.Time
	// tracer is nil with tracing off.
	tracer trace.Tracer

	labels labelHub
	// wake tells the workers that reports were stored; freed, that a worker
	// is free again.
	wake, freed chan struct{}
	busy        atomic.Int64

	// claiming ends when Shutdown starts: no report is claimed after it.
	// base ends when Shutdown gives up waiting: it aborts the attempts in
	// flight, whose reports come back when their lease ends.
	claiming     context.Context
	stopClaiming context.CancelFunc
	base         context.Context
	cancel       context.CancelFunc
	// stopped is closed when the claim loop has returned; inflight counts
	// the attempts it started.
	stopped  chan struct{}
	inflight sync.WaitGroup

	mu      sync.Mutex // guards closing
	closing bool
}

// New returns a Handler and starts its workers, which resume the reports
// left pending by an earlier run.
func New(cfg Config) (*Handler, error) {
	if cfg.Decider == nil {
		return nil, errors.New("secretscan: Decider is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("secretscan: Resolver is required")
	}
	if cfg.Reports == nil {
		return nil, errors.New("secretscan: Reports is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	onOutcome := cfg.OnOutcome
	if onOutcome == nil {
		onOutcome = func(Outcome) {}
	}
	onAttempt := cfg.OnAttempt
	if onAttempt == nil {
		onAttempt = func(context.Context, AttemptResult) {}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	keysURL := cfg.KeysURL
	if keysURL == "" {
		keysURL = DefaultKeysURL
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	h := &Handler{
		decider:         cfg.Decider,
		resolver:        cfg.Resolver,
		reports:         cfg.Reports,
		feedback:        cfg.Feedback,
		feedbackTimeout: orDefault(cfg.FeedbackTimeout, defaultFeedbackTimeout),
		workers:         orDefault(cfg.Workers, defaultWorkers),
		resolveTimeout:  orDefault(cfg.ResolveTimeout, defaultResolveTimeout),
		maxAttempts:     orDefault(cfg.MaxAttempts, DefaultMaxAttempts),
		maxAge:          orDefault(cfg.MaxAge, DefaultMaxAge),
		minBackoff:      orDefault(cfg.MinBackoff, defaultMinBackoff),
		maxBackoff:      orDefault(cfg.MaxBackoff, defaultMaxBackoff),
		pollInterval:    orDefault(cfg.PollInterval, defaultPollInterval),
		claimTimeout:    orDefault(cfg.claimTimeout, claimTimeout),
		maxBody:         orDefault(cfg.MaxBodyBytes, defaultMaxBodyBytes),
		log:             log,
		onOutcome:       onOutcome,
		onAttempt:       onAttempt,
		now:             now,
		labels:          labelHub{waiting: map[string][]chan labeled{}},
		wake:            make(chan struct{}, 1),
		freed:           make(chan struct{}, 1),
		stopped:         make(chan struct{}),
	}
	h.maxBackoff = max(h.maxBackoff, h.minBackoff)
	if cfg.TracerProvider != nil {
		h.tracer = cfg.TracerProvider.Tracer(tracerName)
	}
	// The lease outlasts the slowest attempt, a Resolve and a Decide at
	// their timeout and the write of the outcome, so a report is not
	// claimed again while its attempt is still running.
	h.lease = 2*h.resolveTimeout + settleTimeout + 30*time.Second
	if cfg.RawTokenSecret != "" {
		var err error
		if h.seal, err = newSealer(cfg.RawTokenSecret, cfg.RawTokenPreviousSecrets...); err != nil {
			return nil, err
		}
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
	h.claiming, h.stopClaiming = context.WithCancel(context.Background())
	h.base, h.cancel = context.WithCancel(context.Background())
	go h.run()
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

// ServeHTTP handles one batch from GitHub. It answers 401 for a missing or
// invalid signature, 400 for a body that is not a batch, 413 for a body over
// the limit, 503 when the keys cannot be fetched or the reports cannot be
// stored, and otherwise 202 (or 200 with feedback labels) once every report
// is stored.
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
			unavailable(w)
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
	tokens, reports := h.newReports(alerts)
	keys := make([]string, len(reports))
	for i, rep := range reports {
		keys[i] = rep.Key
	}

	var results <-chan labeled
	if h.feedback {
		// Waiting starts before the reports are stored, so a label the
		// workers find at once is not missed.
		var stop func()
		results, stop = h.labels.wait(keys)
		defer stop()
	}
	added, err := h.store(r.Context(), reports)
	if err != nil {
		h.onOutcome(OutcomeUnavailable)
		h.log.ErrorContext(r.Context(), "secretscan: storing a batch failed; answering 503 so GitHub sends it again",
			"tokens", len(reports), "error", err)
		unavailable(w)
		return
	}
	h.onOutcome(OutcomeAccepted)
	for range len(reports) - added {
		h.onOutcome(OutcomeDuplicate)
	}
	h.log.InfoContext(r.Context(), "secretscan: batch accepted", "tokens", len(reports), "new", added)

	if !h.feedback {
		writeJSON(w, http.StatusAccepted, []feedbackEntry{})
		return
	}
	writeJSON(w, http.StatusOK, h.collect(r.Context(), tokens, keys, results))
}

// newReports turns a batch's matches into tokens and the reports to store,
// in batch order. Empty tokens are skipped.
func (h *Handler) newReports(alerts []alert) ([]Token, []audit.LeakReport) {
	received := h.now()
	tokens := make([]Token, 0, len(alerts))
	reports := make([]audit.LeakReport, 0, len(alerts))
	for _, a := range alerts {
		if a.Token == "" {
			continue
		}
		sum := sha256.Sum256([]byte(a.Token))
		t := Token{
			Raw:    string(a.Token),
			SHA256: hex.EncodeToString(sum[:]),
			Type:   clean(a.Type, event.MaxIDBytes),
			URL:    clean(a.URL, event.MaxTextBytes),
			Source: clean(a.Source, event.MaxIDBytes),
		}
		rep := audit.LeakReport{
			Key:         reportKey(t),
			TokenSHA256: t.SHA256,
			Type:        t.Type,
			Source:      t.Source,
			URL:         t.URL,
			ReceivedAt:  received,
		}
		if h.seal != nil {
			rep.SealedToken = h.seal.seal(t.Raw, rep.Key)
		}
		tokens = append(tokens, t)
		reports = append(reports, rep)
	}
	return tokens, reports
}

// store stores reports and wakes the workers. It refuses once Shutdown has
// started: the database may be about to close.
func (h *Handler) store(ctx context.Context, reports []audit.LeakReport) (int, error) {
	h.mu.Lock()
	closing := h.closing
	h.mu.Unlock()
	if closing {
		return 0, errors.New("secretscan: shutting down")
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	added, err := h.reports.AddLeakReports(ctx, reports)
	if err != nil {
		return 0, err
	}
	if added > 0 {
		select {
		case h.wake <- struct{}{}:
		default:
		}
	}
	return added, nil
}

// collect returns the labels known for a batch's tokens, in batch order:
// those of reports processed before, for a batch GitHub sends again, and
// those the workers find until FeedbackTimeout. It stops waiting for a
// report that dies, which the workers announce with an empty label.
func (h *Handler) collect(ctx context.Context, tokens []Token, keys []string, results <-chan labeled) []feedbackEntry {
	labels := make(map[string]string, len(keys))
	stored, err := h.reports.LeakReportsByKey(ctx, keys)
	if err != nil {
		h.log.WarnContext(ctx, "secretscan: reading stored reports for feedback", "error", err)
	}
	for _, rep := range stored {
		if l := labelOf(rep); l != "" {
			labels[rep.Key] = l
		}
	}
	missing := map[string]bool{}
	for _, k := range keys {
		if labels[k] == "" {
			missing[k] = true
		}
	}
	timer := time.NewTimer(h.feedbackTimeout)
	defer timer.Stop()
wait:
	for len(missing) > 0 {
		select {
		case res := <-results:
			if missing[res.key] {
				if res.label != "" {
					labels[res.key] = res.label
				}
				delete(missing, res.key)
			}
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
		if l := labels[keys[i]]; l != "" {
			entries = append(entries, feedbackEntry{TokenHash: t.SHA256, TokenType: t.Type, Label: l})
		}
	}
	return entries
}

// labelOf returns the feedback label a stored report has earned, or "".
func labelOf(rep audit.LeakReport) string {
	switch {
	case rep.Outcome == string(OutcomeNotFound):
		return labelFalsePositive
	case rep.APIKeyID != "":
		// The token is a key whether or not its decision went through.
		return labelTruePositive
	}
	return ""
}

// labeled is a feedback label found for a report; "" means none will be.
type labeled struct{ key, label string }

// labelHub hands the labels the workers find to the requests waiting to
// answer GitHub with them. Only requests on this process hear of them: a
// report another process resolves is left out of the answer.
type labelHub struct {
	mu      sync.Mutex
	waiting map[string][]chan labeled
}

// wait registers interest in keys. The channel receives each key's label at
// most once per time it is listed, and is buffered for all of them, so
// publish never blocks; stop unregisters.
func (l *labelHub) wait(keys []string) (results <-chan labeled, stop func()) {
	ch := make(chan labeled, len(keys))
	l.mu.Lock()
	for _, k := range keys {
		l.waiting[k] = append(l.waiting[k], ch)
	}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, k := range keys {
			chans := l.waiting[k][:0]
			for _, c := range l.waiting[k] {
				if c != ch {
					chans = append(chans, c)
				}
			}
			if len(chans) == 0 {
				delete(l.waiting, k)
			} else {
				l.waiting[k] = chans
			}
		}
	}
}

// publish hands key's label to the requests waiting for it.
func (l *labelHub) publish(key, label string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range l.waiting[key] {
		select {
		case ch <- labeled{key, label}:
		default:
		}
	}
	delete(l.waiting, key)
}

// reportKey identifies a report: the same token found by GitHub at the same
// place, with the same type, is the same report delivered again.
func reportKey(t Token) string {
	b, _ := json.Marshal([4]string{t.SHA256, t.Type, t.Source, t.URL})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// eventID is the id of a report's key_leak event. It is the same for every
// attempt, so the engine and the audit log can tell a retried report from a
// new one.
func eventID(reportKey string) string { return "ghss_" + reportKey[:32] }

// clean makes a value from GitHub fit an event and a database column: valid
// UTF-8 without NUL bytes, at most limit bytes. An event that breaks the
// limits would be refused at every attempt.
func clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily unavailable"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
