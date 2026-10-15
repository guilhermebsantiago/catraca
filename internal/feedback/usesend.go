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

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// UseSendConfig configures the useSend webhook handler.
//
// By default the account id is the useSend team id (the payload's teamId),
// which fits a self-hosted useSend whose teams are the platform's accounts.
// Set AccountMetadataKey to read it from the email's metadata instead.
type UseSendConfig struct {
	// Decider receives one feedback event per recipient. Required.
	Decider Decider
	// Secret is the webhook's signing secret, shown when the webhook is
	// created in useSend. Required.
	Secret string
	// Tolerance is how far the signed timestamp may be from now. The
	// default, 5 minutes, matches useSend's SDK.
	Tolerance time.Duration
	// AccountMetadataKey, when set, reads the account id from
	// data.metadata[AccountMetadataKey] instead of teamId. useSend documents
	// metadata as the custom metadata attached to the email, but as of
	// webhook version 2026-01-18 its code fills metadata with event details
	// (apps/web/src/server/service/ses-hook-parser.ts), so check your
	// version before relying on it.
	AccountMetadataKey string
	// MaxBodyBytes limits the request body. The default is 1 MiB.
	MaxBodyBytes int64
	// Logger receives errors that are not shown to the caller. The default
	// discards them.
	Logger *slog.Logger
	// OnOutcome, when set, is called once per request outcome and once per
	// event decided, for metrics.
	OnOutcome func(Outcome)
}

type useSendHandler struct {
	base
	secret      []byte
	tolerance   time.Duration
	metadataKey string
	now         func() time.Time
}

// NewUseSendHandler returns a handler for useSend webhooks
// (https://github.com/usesend/useSend). It verifies the X-UseSend-Signature
// header and maps email.bounced, email.complained and email.delivered to
// feedback events, one per address in the email's to list. Other event
// types are acknowledged and ignored.
//
// useSend retries any non-2xx answer up to six times, so only a failure to
// decide is answered with a 5xx.
func NewUseSendHandler(cfg UseSendConfig) (http.Handler, error) {
	b, err := newBase(cfg.Decider, cfg.MaxBodyBytes, cfg.Logger, cfg.OnOutcome)
	if err != nil {
		return nil, err
	}
	if cfg.Secret == "" {
		return nil, errors.New("feedback: useSend needs the webhook signing secret")
	}
	tol := cfg.Tolerance
	if tol <= 0 {
		tol = 5 * time.Minute
	}
	return &useSendHandler{
		base:        b,
		secret:      []byte(cfg.Secret),
		tolerance:   tol,
		metadataKey: cfg.AccountMetadataKey,
		now:         time.Now,
	}, nil
}

// useSend webhook headers and signature scheme: X-UseSend-Signature is
// "v1=" + hex(HMAC-SHA256(secret, timestamp + "." + rawBody)) and
// X-UseSend-Timestamp is Unix milliseconds.
// https://github.com/usesend/useSend/blob/main/apps/docs/guides/webhooks.mdx
// https://github.com/usesend/useSend/blob/main/packages/sdk/src/webhooks.ts
const (
	useSendSignatureHeader = "X-UseSend-Signature"
	useSendTimestampHeader = "X-UseSend-Timestamp"
)

func (h *useSendHandler) verify(r *http.Request, body []byte) bool {
	sig := r.Header.Get(useSendSignatureHeader)
	ts := r.Header.Get(useSendTimestampHeader)
	hexSig, ok := strings.CutPrefix(sig, "v1=")
	if !ok || ts == "" {
		return false
	}
	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if age := h.now().Sub(time.UnixMilli(ms)); age > h.tolerance || age < -h.tolerance {
		return false
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// useSendWebhook is the webhook envelope.
// https://github.com/usesend/useSend/blob/main/apps/web/src/server/service/webhook-service.ts
type useSendWebhook struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt string          `json:"createdAt"`
	TeamID    json.Number     `json:"teamId"`
	Data      json.RawMessage `json:"data"`
}

// useSendEmail is the data of email events.
// https://github.com/usesend/useSend/blob/main/packages/lib/src/webhook/webhook-events.ts
type useSendEmail struct {
	ID         string         `json:"id"`
	From       string         `json:"from"`
	To         []string       `json:"to"`
	OccurredAt string         `json:"occurredAt"`
	Metadata   map[string]any `json:"metadata"`
	Bounce     *struct {
		Type    string `json:"type"`
		SubType string `json:"subType"`
	} `json:"bounce"`
}

func (h *useSendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	if !h.verify(r, body) {
		h.onOutcome(OutcomeInvalidSignature)
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	var hook useSendWebhook
	if err := json.Unmarshal(body, &hook); err != nil || hook.Type == "" {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "not a useSend webhook")
		return
	}
	var kind event.FeedbackKind
	switch hook.Type {
	case "email.bounced":
		kind = event.Bounce
	case "email.complained":
		kind = event.Complaint
	case "email.delivered":
		kind = event.Delivery
	default:
		h.onOutcome(OutcomeIgnored)
		writeOK(w)
		return
	}
	var email useSendEmail
	if err := json.Unmarshal(hook.Data, &email); err != nil {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "invalid event data")
		return
	}
	evs, outcome := h.events(&hook, &email, kind)
	if outcome != "" {
		h.onOutcome(outcome)
		writeOK(w)
		return
	}
	decided, _ := h.decideAll(r, "usesend", evs)
	answerDecided(w, decided, len(evs))
}

func (h *useSendHandler) events(hook *useSendWebhook, email *useSendEmail, kind event.FeedbackKind) ([]event.Event, Outcome) {
	// useSend copies SES's complaint feedback type into metadata; a
	// "not-spam" report retracts a complaint.
	if kind == event.Complaint {
		if ft, _ := email.Metadata["feedbackType"].(string); strings.EqualFold(ft, "not-spam") {
			return nil, OutcomeIgnored
		}
	}
	account := h.accountID(hook, email)
	if account == "" {
		return nil, OutcomeNoAccount
	}
	// createdAt is when useSend processed the feedback; occurredAt is when
	// the original email was sent (SES mail.timestamp).
	t := parseTime(hook.CreatedAt)
	if t.IsZero() {
		t = parseTime(email.OccurredAt)
	}
	template := event.Event{
		Type:       event.Feedback,
		Time:       t,
		AccountID:  account,
		From:       bareAddress(email.From),
		Attributes: map[string]string{"provider": "usesend"},
	}
	info := event.FeedbackInfo{Kind: kind, MessageID: email.ID}
	if kind == event.Bounce {
		info.BounceType = bounceTransient
		if email.Bounce != nil {
			if email.Bounce.Type == "Permanent" {
				info.BounceType = bouncePermanent
			}
			template.Attributes["bounce_subtype"] = email.Bounce.SubType
		}
	}
	// useSend reports the email's whole to list, not only the recipients
	// the bounce or complaint was about.
	return feedbackEvents(template, info, email.To), ""
}

func (h *useSendHandler) accountID(hook *useSendWebhook, email *useSendEmail) string {
	if h.metadataKey != "" {
		switch v := email.Metadata[h.metadataKey].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	if id := hook.TeamID.String(); id != "" && id != "0" {
		return id
	}
	return ""
}
