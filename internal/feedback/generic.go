package feedback

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// SignatureHeader carries the signature of a generic feedback request:
// "t=<unix seconds>,v1=<hex HMAC-SHA256 of t + "." + body>". It is the same
// scheme Catraca uses to sign its outgoing webhooks, so a platform needs one
// implementation for both directions. Several v1 values may be sent while a
// secret is rotated.
const SignatureHeader = "Catraca-Signature"

// GenericConfig configures the generic feedback handler.
type GenericConfig struct {
	// Decider receives the feedback event. Required.
	Decider Decider
	// Secret is the shared secret requests are signed with. Required.
	Secret string
	// Tolerance is how far the signed timestamp may be from now. The
	// default is 5 minutes.
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
	secret    []byte
	tolerance time.Duration
	now       func() time.Time
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
// Requests must carry a valid SignatureHeader. The answer is 202 with the
// decision, like POST /v1/events.
func NewGenericHandler(cfg GenericConfig) (http.Handler, error) {
	b, err := newBase(cfg.Decider, cfg.MaxBodyBytes, cfg.Logger, cfg.OnOutcome)
	if err != nil {
		return nil, err
	}
	if cfg.Secret == "" {
		return nil, errors.New("feedback: the generic handler needs a secret")
	}
	tol := cfg.Tolerance
	if tol <= 0 {
		tol = 5 * time.Minute
	}
	return &genericHandler{base: b, secret: []byte(cfg.Secret), tolerance: tol, now: time.Now}, nil
}

func (h *genericHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	if !verifySignature(r.Header.Get(SignatureHeader), body, h.secret, h.now(), h.tolerance) {
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

// verifySignature checks a SignatureHeader value against body.
func verifySignature(header string, body, secret []byte, now time.Time, tolerance time.Duration) bool {
	var ts string
	var sigs [][]byte
	for part := range strings.SplitSeq(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			if sig, err := hex.DecodeString(v); err == nil {
				sigs = append(sigs, sig)
			}
		}
	}
	if ts == "" || len(sigs) == 0 {
		return false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if age := now.Sub(time.Unix(sec, 0)); age > tolerance || age < -tolerance {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	want := mac.Sum(nil)
	for _, sig := range sigs {
		if hmac.Equal(sig, want) {
			return true
		}
	}
	return false
}
