package feedback

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/signature"
)

// GenericConfig configures the generic feedback handler.
type GenericConfig struct {
	// Decider receives the feedback event. Required.
	Decider Decider
	// Secret is the shared secret requests are signed with. Required.
	Secret string
	// Tolerance is how far the signed timestamp may be from now. The
	// default is signature.DefaultTolerance.
	Tolerance time.Duration
	// MaxBodyBytes limits the request body. The default is 1 MiB.
	MaxBodyBytes int64
	// Logger receives errors that are not shown to the caller. The default
	// discards them.
	Logger *slog.Logger
	// OnOutcome, when set, is called once per request outcome and once per
	// event decided, for metrics.
	OnOutcome func(Outcome)
}

type genericHandler struct {
	base
	secret    string
	tolerance time.Duration
}

// NewGenericHandler returns a handler for feedback events in Catraca's own
// format, for providers Catraca has no adapter for. The body is an
// event.Event with type "feedback" (the type may be omitted):
//
//	{
//	  "account_id": "acct_123",
//	  "time": "2026-10-15T12:00:00Z",
//	  "from": "news@example.com",
//	  "feedback": {"kind": "bounce", "bounce_type": "permanent",
//	               "recipient": "someone@example.org", "message_id": "msg_1"},
//	  "attributes": {"provider": "postmark"}
//	}
//
// Requests must carry a valid signature.Header, the scheme Catraca signs its
// own webhooks with, so a platform needs one implementation for both
// directions; a platform in Go signs with signature.Sign. The answer is 202
// with the decision, like POST /v1/events.
func NewGenericHandler(cfg GenericConfig) (http.Handler, error) {
	b, err := newBase(cfg.Decider, cfg.MaxBodyBytes, cfg.Logger, cfg.OnOutcome)
	if err != nil {
		return nil, err
	}
	if cfg.Secret == "" {
		return nil, errors.New("feedback: the generic handler needs a secret")
	}
	return &genericHandler{base: b, secret: cfg.Secret, tolerance: cfg.Tolerance}, nil
}

func (h *genericHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	if err := signature.Verify(h.secret, r.Header.Get(signature.Header), body, h.tolerance); err != nil {
		h.onOutcome(OutcomeInvalidSignature)
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	var in event.Event
	if err := json.Unmarshal(body, &in); err != nil {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "body is not a JSON event")
		return
	}
	ev, err := genericEvent(in)
	if err != nil {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	decided, d := h.decideAll(r, "generic", []event.Event{ev})
	if decided == 0 {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusAccepted, struct {
		Decision decision.Decision `json:"decision"`
	}{d})
}

// genericEvent validates a generic feedback event and keeps only the fields
// a feedback event uses. Its error messages are written for the caller.
func genericEvent(in event.Event) (event.Event, error) {
	if in.Type != "" && in.Type != event.Feedback {
		return event.Event{}, errors.New(`type must be "feedback"`)
	}
	if strings.TrimSpace(in.AccountID) == "" {
		return event.Event{}, errors.New("account_id is required")
	}
	if in.Feedback == nil {
		return event.Event{}, errors.New("feedback is required")
	}
	info := *in.Feedback
	switch info.Kind {
	case event.Bounce:
		switch strings.ToLower(info.BounceType) {
		case bouncePermanent, bounceTransient:
			info.BounceType = strings.ToLower(info.BounceType)
		default:
			return event.Event{}, errors.New(`feedback.bounce_type must be "permanent" or "transient"`)
		}
	case event.Complaint, event.Delivery:
		info.BounceType = ""
	default:
		return event.Event{}, errors.New(`feedback.kind must be "bounce", "complaint" or "delivery"`)
	}
	return event.Event{
		Type:       event.Feedback,
		Time:       in.Time,
		AccountID:  strings.TrimSpace(in.AccountID),
		From:       in.From,
		Feedback:   &info,
		Attributes: in.Attributes,
	}, nil
}
