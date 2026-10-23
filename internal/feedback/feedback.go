// Package feedback turns delivery feedback from email providers into
// Catraca feedback events: bounces, complaints and deliveries.
//
// Three HTTP handlers are provided:
//
//   - NewSESHandler: Amazon SES notifications delivered through Amazon SNS,
//     with the SNS message signature verified.
//   - NewUseSendHandler: useSend webhooks, with the webhook signature
//     verified.
//   - NewGenericHandler: a feedback event in Catraca's own JSON format,
//     signed with a shared secret.
//
// Every handler builds one event per affected recipient and hands it to a
// Decider. Handlers never put internal errors in a response: callers get a
// status code and a short generic message, and the details go to the
// configured logger.
package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// Decider decides an event. The engine implements it.
type Decider interface {
	Decide(ctx context.Context, ev event.Event) (decision.Decision, error)
}

// Outcome is what a handler did with a request, or with one event of a
// request. The values are stable and few, so they can label a metric.
type Outcome string

const (
	// OutcomeDecided means an event was handed to the Decider.
	OutcomeDecided Outcome = "decided"
	// OutcomeIgnored means the notification is not feedback Catraca uses,
	// such as an open, a click or a provider test message.
	OutcomeIgnored Outcome = "ignored"
	// OutcomeNoAccount means no account id could be derived, so the
	// notification was acknowledged and skipped.
	OutcomeNoAccount Outcome = "no_account"
	// OutcomeInvalidSignature means the request was not signed by the
	// provider or the shared secret, or its timestamp was too old.
	OutcomeInvalidSignature Outcome = "invalid_signature"
	// OutcomeTopicNotAllowed means an SNS message came from a topic that is
	// not in SESConfig.TopicARNs.
	OutcomeTopicNotAllowed Outcome = "topic_not_allowed"
	// OutcomeCertUnavailable means the SNS signing certificate could not be
	// fetched. The request is answered with 503 so SNS retries it.
	OutcomeCertUnavailable Outcome = "cert_unavailable"
	// OutcomeMalformed means the body could not be parsed or failed
	// validation.
	OutcomeMalformed Outcome = "malformed"
	// OutcomeTooLarge means the body exceeded the configured limit.
	OutcomeTooLarge Outcome = "too_large"
	// OutcomeDecideFailed means the Decider returned an error for an event.
	OutcomeDecideFailed Outcome = "decide_failed"
	// OutcomeUncounted means an event was decided, but the store failed, so
	// it may be missing from the counters (decision.Decision.Uncounted).
	// The request is answered 503 so the provider sends it again.
	OutcomeUncounted Outcome = "uncounted"
	// OutcomeSubscriptionConfirmed means an SNS subscription was confirmed.
	OutcomeSubscriptionConfirmed Outcome = "subscription_confirmed"
	// OutcomeSubscriptionFailed means confirming an SNS subscription failed.
	OutcomeSubscriptionFailed Outcome = "subscription_failed"
	// OutcomeUnsubscribed means SNS reported that the endpoint was
	// unsubscribed from a topic.
	OutcomeUnsubscribed Outcome = "unsubscribed"
)

// Bounce types as stored in event.FeedbackInfo.BounceType.
const (
	bouncePermanent = "permanent"
	bounceTransient = "transient"
)

const (
	defaultMaxBodyBytes = 1 << 20
	// decideTimeout bounds the Decide calls of one request. They run
	// detached from the request context so a provider that hangs up halfway
	// does not leave a notification half recorded.
	decideTimeout = 15 * time.Second
	// retryAfter is the Retry-After of a 503 for feedback that could not be
	// counted. SNS and useSend keep their own schedules; a platform posting
	// generic feedback may wait this long before it sends the event again.
	retryAfter = 10 * time.Second
)

// base holds what every handler shares.
type base struct {
	decider   Decider
	maxBody   int64
	log       *slog.Logger
	onOutcome func(Outcome)
}

func newBase(d Decider, maxBody int64, log *slog.Logger, onOutcome func(Outcome)) (base, error) {
	if d == nil {
		return base{}, errors.New("feedback: Decider is required")
	}
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if onOutcome == nil {
		onOutcome = func(Outcome) {}
	}
	return base{decider: d, maxBody: maxBody, log: log, onOutcome: onOutcome}, nil
}

// readBody reads the request body up to the configured limit. It answers
// 405 itself for anything but POST and returns ok=false in that case.
func (b base) readBody(w http.ResponseWriter, r *http.Request) (body []byte, ok bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, b.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			b.onOutcome(OutcomeTooLarge)
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return nil, false
		}
		b.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "could not read body")
		return nil, false
	}
	return body, true
}

// decideResult is what decideAll did with the events of a request.
type decideResult struct {
	// decided counts events that were decided and counted.
	decided int
	// failed counts events that may not have counted, in a way a retry may
	// fix: the Decider failed on them, or decided them while the store
	// failed (decision.Decision.Uncounted).
	failed int
	// invalid is the error of the first event the Decider refused as
	// invalid (event.ErrInvalid), such as one older than the engine
	// accepts. A retry would be refused the same way.
	invalid error
	last    decision.Decision
}

// decideAll hands each event to the Decider. It keeps going after an error
// so one bad event does not drop the others.
func (b base) decideAll(r *http.Request, provider string, evs []event.Event) decideResult {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), decideTimeout)
	defer cancel()
	var res decideResult
	for _, ev := range evs {
		d, err := b.decider.Decide(ctx, ev)
		switch {
		case errors.Is(err, event.ErrInvalid):
			b.onOutcome(OutcomeMalformed)
			b.log.WarnContext(ctx, "feedback: event refused",
				"provider", provider, "kind", ev.Feedback.Kind, "error", err)
			if res.invalid == nil {
				res.invalid = err
			}
		case err != nil:
			b.onOutcome(OutcomeDecideFailed)
			b.log.ErrorContext(ctx, "feedback: decide failed",
				"provider", provider, "kind", ev.Feedback.Kind, "error", err)
			res.failed++
		case d.Uncounted:
			// A decision degraded by a store that merely answered late is
			// not here: its writes still apply.
			b.onOutcome(OutcomeUncounted)
			b.log.WarnContext(ctx, "feedback: the store failed; asking the provider to send the event again",
				"provider", provider, "kind", ev.Feedback.Kind, "event_id", d.EventID, "decision_id", d.ID)
			res.failed++
		default:
			b.onOutcome(OutcomeDecided)
			res.decided++
			res.last = d
		}
	}
	return res
}

// answerDecided writes the response for a notification whose events were
// handed to the Decider. When an event may not have counted, the provider
// gets a 503 and sends the notification again: its events carry the same
// ids each time, so those that counted do not count twice. Otherwise it
// gets a 200, events refused as invalid included, since they would only be
// refused again.
func answerDecided(w http.ResponseWriter, res decideResult) {
	if res.failed > 0 {
		writeUnavailable(w)
		return
	}
	writeOK(w)
}

// eventIDs gives each event of a notification an id made of base, the
// provider's id for the notification, which it keeps when it sends the
// notification again, and the event's position in it. The engine counts an
// event once per id, so a notification sent again after a 503 counts each
// of its events once. Without a base the events keep no id, and each
// delivery counts.
func eventIDs(evs []event.Event, base string) {
	if base == "" {
		return
	}
	for i := range evs {
		evs[i].ID = base + ":" + strconv.Itoa(i)
	}
}

// writeUnavailable asks the provider to send the request again later.
func writeUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
}

// invalidMessage returns what an event.ErrInvalid error says is wrong, for
// the caller: "to has 2000 addresses; ...".
func invalidMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), event.ErrInvalid.Error()+": ")
	return strings.TrimPrefix(msg, "event: ")
}

func writeOK(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// parseTime parses the timestamps providers send. SES uses RFC 3339 in
// event publishing but documents "2018-10-08T14:05:45 +0000" in classic
// notifications. An unparseable time yields the zero time, which the engine
// replaces with the time it receives the event.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05 -0700", "2006-01-02T15:04:05.000-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// feedbackEvent copies template with info for one recipient. Each event gets
// its own Feedback and Attributes, so the Decider may keep or change them.
func feedbackEvent(template event.Event, info event.FeedbackInfo, recipient string) event.Event {
	ev := template
	info.Recipient = recipient
	ev.Feedback = &info
	ev.Attributes = maps.Clone(template.Attributes)
	return ev
}

// feedbackEvents builds one event per recipient. A notification that names
// no recipient still yields one event, so the account's counters see it.
func feedbackEvents(template event.Event, info event.FeedbackInfo, recipients []string) []event.Event {
	if len(recipients) == 0 {
		return []event.Event{feedbackEvent(template, info, "")}
	}
	evs := make([]event.Event, 0, len(recipients))
	for _, rcpt := range recipients {
		evs = append(evs, feedbackEvent(template, info, rcpt))
	}
	return evs
}
