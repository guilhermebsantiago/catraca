package secretscan

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/monotime"
)

// settleTimeout bounds writing the outcome of an attempt.
const settleTimeout = 10 * time.Second

// claimTimeout bounds a claim of reports. A query on a connection the
// network dropped without a reset waits until TCP gives up on it, a quarter
// of an hour on Linux, and every worker waits for the claim.
const claimTimeout = 10 * time.Second

// run claims due reports while workers are free, until Shutdown. It looks
// again when a batch is stored, when a worker frees up, and every
// PollInterval, which picks up reports stored by another process, requeued
// by hand, or whose lease ran out.
func (h *Handler) run() {
	defer close(h.stopped)
	timer := time.NewTimer(h.pollInterval)
	defer timer.Stop()
	for {
		if free := h.workers - int(h.busy.Load()); free > 0 {
			ctx, cancel := context.WithTimeout(h.claiming, h.claimTimeout)
			reports, err := h.reports.ClaimLeakReports(ctx, h.now(), free, h.lease)
			cancel()
			// Reports claimed just as Shutdown started are still attempted:
			// Shutdown waits for them, and they need not wait out a lease.
			for _, rep := range reports {
				h.busy.Add(1)
				h.inflight.Go(func() {
					defer h.release()
					h.attempt(rep)
				})
			}
			if h.claiming.Err() != nil {
				return
			}
			if err != nil {
				h.log.Error("secretscan: claiming reports", "error", err)
			}
			if err == nil && len(reports) == free {
				continue // every worker got one: more may be due
			}
		}
		timer.Reset(h.pollInterval)
		select {
		case <-h.claiming.Done():
			return
		case <-h.wake:
		case <-h.freed:
		case <-timer.C:
		}
	}
}

func (h *Handler) release() {
	h.busy.Add(-1)
	select {
	case h.freed <- struct{}{}:
	default:
	}
}

// attempt processes one claimed report, measures the attempt and, with
// tracing on, traces it.
func (h *Handler) attempt(rep audit.LeakReport) {
	ctx, span := h.startAttempt(rep)
	start := monotime.Now()
	outcome := h.process(ctx, rep)
	h.attempted(ctx, span, rep, outcome, monotime.Since(start))
}

// process processes one claimed report: it resolves the token, unless an
// earlier attempt already did, and decides the key_leak event of a key. A
// failure is retried with backoff until the report's bounds run out. It
// returns the attempt's outcome, or "" for an attempt that Shutdown
// aborted, which records nothing: its report is claimed again when the
// lease ends, by this process after a restart or by another one. ctx, a
// child of the handler's base context, carries the attempt's span.
func (h *Handler) process(ctx context.Context, rep audit.LeakReport) Outcome {
	key := Key{APIKeyID: rep.APIKeyID, AccountID: rep.AccountID}
	if key.APIKeyID == "" {
		t, err := h.token(rep)
		if err != nil {
			// Retrying cannot bring the raw token back.
			return h.fail(rep, Key{}, OutcomeResolveFailed, err, true)
		}
		err = h.call(ctx, func(ctx context.Context) error {
			ctx, end := h.traceResolve(ctx)
			var err error
			key, err = h.resolver.Resolve(ctx, t)
			if err == nil && key.APIKeyID == "" {
				err = errors.New("secretscan: resolver returned a key without an id")
			}
			end(err)
			return err
		})
		switch {
		case errors.Is(err, ErrNotFound):
			h.publish(rep.Key, labelFalsePositive)
			h.settle(rep, func(ctx context.Context) error {
				return h.reports.FinishLeakReport(ctx, rep.ID, audit.LeakAttempt{
					At: h.now(), Attempt: rep.Attempts, Outcome: string(OutcomeNotFound)})
			})
			h.onOutcome(OutcomeNotFound)
			return OutcomeNotFound
		case err != nil && h.base.Err() != nil:
			return "" // aborted by Shutdown
		case err != nil:
			return h.fail(rep, Key{}, OutcomeResolveFailed, err, false)
		}
	}
	// The token is a real key whether or not the decision goes through.
	h.publish(rep.Key, labelTruePositive)

	var d decision.Decision
	err := h.call(ctx, func(ctx context.Context) error {
		var err error
		d, err = h.decider.Decide(ctx, leakEvent(rep, key))
		return err
	})
	switch {
	case err == nil:
		h.settle(rep, func(ctx context.Context) error {
			return h.reports.FinishLeakReport(ctx, rep.ID, audit.LeakAttempt{
				At: h.now(), Attempt: rep.Attempts, Outcome: string(OutcomeLeaked),
				APIKeyID: key.APIKeyID, AccountID: key.AccountID, DecisionID: d.ID})
		})
		h.onOutcome(OutcomeLeaked)
		h.log.Info("secretscan: leaked key reported", "report_id", rep.ID, "api_key_id", key.APIKeyID,
			"account_id", key.AccountID, "decision_id", d.ID, "type", rep.Type, "source", rep.Source, "url", rep.URL)
		return OutcomeLeaked
	case h.base.Err() != nil:
		return "" // aborted by Shutdown
	default:
		// An event the engine refuses as invalid, say a key id with
		// control characters from the resolver, is refused again.
		return h.fail(rep, key, OutcomeDecideFailed, err, errors.Is(err, event.ErrInvalid))
	}
}

// token returns the token a report is about, with the raw token when the
// Resolver needs it.
func (h *Handler) token(rep audit.LeakReport) (Token, error) {
	t := Token{SHA256: rep.TokenSHA256, Type: rep.Type, URL: rep.URL, Source: rep.Source}
	if h.seal == nil {
		return t, nil
	}
	if rep.SealedToken == "" {
		return t, errors.New("secretscan: the raw token the resolver needs was not stored with this report: it arrived while raw tokens were not kept")
	}
	raw, err := h.seal.open(rep.SealedToken, rep.Key)
	if err != nil {
		return t, err
	}
	t.Raw = raw
	return t, nil
}

// call runs f under ResolveTimeout. ctx is the attempt's, a child of the
// handler's base context, so Shutdown cancels it when it gives up waiting.
func (h *Handler) call(ctx context.Context, f func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, h.resolveTimeout)
	defer cancel()
	return f(ctx)
}

// fail records a failed attempt. The report is retried after a backoff,
// unless it has used up its attempts or its age, or final says retrying
// cannot help; then it is dead, with outcome. key is what is known of the
// token's key, kept so the next attempt does not resolve it again. It
// returns the outcome it recorded: outcome, or OutcomeRetry.
func (h *Handler) fail(rep audit.LeakReport, key Key, outcome Outcome, cause error, final bool) Outcome {
	now := h.now()
	a := audit.LeakAttempt{At: now, Attempt: rep.Attempts, APIKeyID: key.APIKeyID, AccountID: key.AccountID, Error: cause.Error()}
	log := h.log.With("report_id", rep.ID, "attempt", rep.Attempts, "type", rep.Type, "source", rep.Source, "url", rep.URL,
		"api_key_id", key.APIKeyID, "error", cause)
	if final || rep.Attempts >= h.maxAttempts || now.Sub(rep.QueuedAt) >= h.maxAge {
		a.Outcome = string(outcome)
		h.settle(rep, func(ctx context.Context) error { return h.reports.MarkLeakReportDead(ctx, rep.ID, a) })
		// A request waiting to label the token need not wait any longer.
		h.publish(rep.Key, "")
		h.onOutcome(outcome)
		log.Error("secretscan: a leaked-key report is dead and its key may not have been acted on; fix the cause, then requeue it with catraca secretscan retry",
			"outcome", outcome)
		return outcome
	}
	next := now.Add(h.backoff(rep.Attempts))
	h.settle(rep, func(ctx context.Context) error { return h.reports.RetryLeakReport(ctx, rep.ID, a, next) })
	h.onOutcome(OutcomeRetry)
	log.Warn("secretscan: a leaked-key report failed, will retry", "next_attempt", next)
	return OutcomeRetry
}

// settle records an attempt's outcome. It is not canceled by Shutdown: the
// work is done, and recording it saves doing it again. If it fails, the
// report's lease ends and the report is tried again, which the event's
// fixed id makes safe to decide twice, so the error is only logged.
func (h *Handler) settle(rep audit.LeakReport, update func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(h.base), settleTimeout)
	defer cancel()
	if err := update(ctx); err != nil {
		h.log.Error("secretscan: recording a report's outcome failed; it is tried again when its lease ends",
			"report_id", rep.ID, "error", err)
	}
}

// publish hands a label to the requests waiting to answer GitHub with it.
func (h *Handler) publish(key, label string) {
	if h.feedback {
		h.labels.publish(key, label)
	}
}

// backoff returns the wait after attempt number attempt failed: MinBackoff
// doubled per failure up to MaxBackoff, with equal jitter (half fixed, half
// random) so that reports failing together, in an outage of the resolver,
// are not retried together.
func (h *Handler) backoff(attempt int) time.Duration {
	b := h.maxBackoff
	if shift := attempt - 1; shift >= 0 && shift < 32 {
		if exp := h.minBackoff << shift; exp > 0 && exp < b {
			b = exp
		}
	}
	return b/2 + rand.N(b/2+1)
}

// leakEvent is the key_leak event of a report whose token is key. Its time
// is when the report arrived, and its id is fixed per report.
func leakEvent(rep audit.LeakReport, key Key) event.Event {
	return event.Event{
		ID:         eventID(rep.Key),
		Type:       event.KeyLeak,
		Time:       rep.ReceivedAt,
		AccountID:  key.AccountID,
		APIKeyID:   key.APIKeyID,
		Leak:       &event.LeakInfo{Source: leakSource(rep.Source), URL: rep.URL},
		Attributes: map[string]string{"secret_type": rep.Type},
	}
}

func leakSource(githubSource string) string {
	if githubSource == "" {
		return "github"
	}
	return "github:" + githubSource
}

// Shutdown stops accepting batches and claiming reports, and waits for the
// attempts in flight to finish. When ctx ends first it aborts them and
// returns ctx's error; their reports are claimed again when their lease
// ends. Reports still pending stay in the queue for the next start, or for
// another process.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closing = true
	h.mu.Unlock()
	h.stopClaiming()
	finished := make(chan struct{})
	go func() {
		<-h.stopped
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
