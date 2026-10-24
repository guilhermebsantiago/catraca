package feedback

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
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
	// PreviousSecrets are secrets being rotated out: a request signed with
	// any of them, or with Secret, is accepted, so the platform can switch
	// to Secret whenever it is ready.
	PreviousSecrets []string
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
	secrets   []string
	tolerance time.Duration
}

// NewGenericHandler returns a handler for feedback events in Catraca's own
// format, for providers Catraca has no adapter for. The body is an
// event.Event with type "feedback" (the type may be omitted):
//
//	{
//	  "id": "fb_123",
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
// with the decision, like POST /v1/events, or 503 with Retry-After when the
// event could not be counted: sent again with the same id, it counts once.
func NewGenericHandler(cfg GenericConfig) (http.Handler, error) {
	b, err := newBase(cfg.Decider, cfg.MaxBodyBytes, cfg.Logger, cfg.OnOutcome)
	if err != nil {
		return nil, err
	}
	if cfg.Secret == "" {
		return nil, errors.New("feedback: the generic handler needs a secret")
	}
	if slices.Contains(cfg.PreviousSecrets, "") {
		return nil, errors.New("feedback: a previous secret of the generic handler is empty")
	}
	secrets := append([]string{cfg.Secret}, cfg.PreviousSecrets...)
	return &genericHandler{base: b, secrets: secrets, tolerance: cfg.Tolerance}, nil
}

func (h *genericHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	if err := signature.VerifyAny(h.secrets, r.Header.Get(signature.Header), body, h.tolerance); err != nil {
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
	res := h.decideAll(r, "generic", []event.Event{ev})
	switch {
	case res.invalid != nil:
		// The platform sent the event, so it can fix it: say what is wrong.
		writeError(w, http.StatusBadRequest, invalidMessage(res.invalid))
		return
	case res.failed > 0:
		// Sent again with the same id, it counts once.
		writeUnavailable(w)
		return
	}
	writeJSON(w, http.StatusAccepted, struct {
		Decision decision.Decision `json:"decision"`
	}{res.last})
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
		ID:         in.ID,
		Type:       event.Feedback,
		Time:       in.Time,
		AccountID:  strings.TrimSpace(in.AccountID),
		From:       in.From,
		Feedback:   &info,
		Attributes: in.Attributes,
	}, nil
}
