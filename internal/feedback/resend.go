package feedback

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// DefaultResendAccountTag is the Resend tag that holds the account id when
// ResendConfig.AccountTag is empty.
const DefaultResendAccountTag = "catraca-account"

// ResendConfig configures the Resend webhook handler.
type ResendConfig struct {
	// Decider receives the feedback events: one per complaint, and one per
	// recipient of a bounce or delivery. Required.
	Decider Decider
	// Secret is the webhook's signing secret, shown on the webhook's page
	// in Resend: whsec_ followed by base64. The prefix may be left out.
	// Required.
	Secret string
	// PreviousSecrets are secrets being rotated out: a webhook signed with
	// any of them, or with Secret, is accepted.
	PreviousSecrets []string
	// AccountTag is the name of the tag, among those the email was sent
	// with, whose value is the account id. Default DefaultResendAccountTag.
	AccountTag string
	// Tolerance is how far the signed timestamp may be from now. The
	// default, 5 minutes, matches Svix's libraries.
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

type resendHandler struct {
	base
	keys       [][]byte
	tolerance  time.Duration
	accountTag string
	now        func() time.Time
}

// NewResendHandler returns a handler for Resend webhooks
// (https://resend.com/docs/webhooks/introduction). It verifies the Svix
// signature Resend sends them with, and maps email.bounced,
// email.complained and email.delivered to feedback events: a complaint
// counts once, and a bounce or delivery once per address in the email's to
// list. Other event types are acknowledged and ignored. The account id is
// the value of the email's AccountTag tag.
//
// Resend retries a webhook that gets any answer but a 2xx, so only feedback
// that could not be counted is answered with a 5xx: a 503, after which
// Resend sends it again with the same svix-id, and the events that did
// count do not count twice.
func NewResendHandler(cfg ResendConfig) (http.Handler, error) {
	b, err := newBase(cfg.Decider, cfg.MaxBodyBytes, cfg.Logger, cfg.OnOutcome)
	if err != nil {
		return nil, err
	}
	if cfg.Secret == "" {
		return nil, errors.New("feedback: Resend needs the webhook signing secret")
	}
	key, err := DecodeResendSecret(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("feedback: the Resend secret is %w", err)
	}
	keys := [][]byte{key}
	for i, s := range cfg.PreviousSecrets {
		key, err := DecodeResendSecret(s)
		if err != nil {
			return nil, fmt.Errorf("feedback: previous Resend secret %d is %w", i, err)
		}
		keys = append(keys, key)
	}
	tol := cfg.Tolerance
	if tol <= 0 {
		tol = 5 * time.Minute
	}
	tag := cfg.AccountTag
	if tag == "" {
		tag = DefaultResendAccountTag
	}
	return &resendHandler{base: b, keys: keys, tolerance: tol, accountTag: tag, now: time.Now}, nil
}

// Resend signs its webhooks with Svix
// (https://docs.svix.com/receiving/verifying-payloads/how-manual):
//   - svix-id is the message id, the same on every retry of it;
//   - svix-timestamp is the attempt's time in Unix seconds;
//   - svix-signature is a space-separated list of "v1,<base64>" entries,
//     each the HMAC-SHA256 of "<svix-id>.<svix-timestamp>.<raw body>" keyed
//     with the base64-decoded part of the whsec_ secret. Any entry may
//     match: while a secret is rotated, Resend signs with both.
const (
	svixIDHeader        = "svix-id"
	svixTimestampHeader = "svix-timestamp"
	svixSignatureHeader = "svix-signature"
	svixSecretPrefix    = "whsec_"
)

// DecodeResendSecret returns the HMAC key of a Resend webhook signing
// secret: whsec_ followed by base64, the prefix optional, as Svix's
// libraries accept it.
func DecodeResendSecret(secret string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, svixSecretPrefix))
	if err != nil || len(key) == 0 {
		return nil, errors.New("not whsec_ followed by base64")
	}
	return key, nil
}

// svixSignatures returns the decoded signatures of a svix-signature header:
// its v1 entries, separated by spaces. Entries of other versions, and
// entries that do not decode or are empty, are skipped, so that one of them
// does not hide a valid one.
func svixSignatures(header string) [][]byte {
	var sigs [][]byte
	for entry := range strings.SplitSeq(header, " ") {
		version, sig, ok := strings.Cut(entry, ",")
		if !ok || version != "v1" {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(sig); err == nil && len(b) > 0 {
			sigs = append(sigs, b)
		}
	}
	return sigs
}

// verify checks the Svix signature of a webhook and returns its svix-id.
func (h *resendHandler) verify(header http.Header, body []byte) (id string, ok bool) {
	id = header.Get(svixIDHeader)
	ts := header.Get(svixTimestampHeader)
	sigs := svixSignatures(header.Get(svixSignatureHeader))
	if id == "" || ts == "" || len(sigs) == 0 {
		return "", false
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", false
	}
	// Each attempt is signed anew, so a stale timestamp is a recorded
	// request posted again, not a slow retry.
	if age := h.now().Sub(time.Unix(unix, 0)); age > h.tolerance || age < -h.tolerance {
		return "", false
	}
	// Every key is tried against every signature, without stopping at the
	// first match, so the time taken does not tell which one signed it.
	for _, key := range h.keys {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id))
		mac.Write([]byte{'.'})
		mac.Write([]byte(ts))
		mac.Write([]byte{'.'})
		mac.Write(body)
		want := mac.Sum(nil)
		for _, sig := range sigs {
			if hmac.Equal(sig, want) {
				ok = true
			}
		}
	}
	return id, ok
}

// resendWebhook is the webhook payload.
// https://resend.com/docs/webhooks/event-types
type resendWebhook struct {
	Type      string          `json:"type"`
	CreatedAt string          `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// resendEmail is the data of email events.
// https://resend.com/docs/webhooks/emails/bounced
type resendEmail struct {
	EmailID   string   `json:"email_id"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	CreatedAt string   `json:"created_at"`
	// Tags is an object of tag names to values. It is decoded on its own,
	// so a tags field of another shape costs the account id, not the
	// event.
	Tags   json.RawMessage `json:"tags"`
	Bounce *struct {
		Type    string `json:"type"`
		SubType string `json:"subType"`
	} `json:"bounce"`
}

func (h *resendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	id, ok := h.verify(r.Header, body)
	if !ok {
		h.onOutcome(OutcomeInvalidSignature)
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	var hook resendWebhook
	if err := json.Unmarshal(body, &hook); err != nil || hook.Type == "" {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "not a Resend webhook")
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
	var email resendEmail
	if err := json.Unmarshal(hook.Data, &email); err != nil {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "invalid event data")
		return
	}
	evs := h.events(&hook, &email, kind)
	if evs == nil {
		h.onOutcome(OutcomeNoAccount)
		writeOK(w)
		return
	}
	// svix-id names the message, and Resend keeps it on every retry.
	eventIDs(evs, "resend:"+id)
	answerDecided(w, h.decideAll(r, "resend", evs))
}

// events builds the feedback events of an email event, or none when it has
// no account id.
func (h *resendHandler) events(hook *resendWebhook, email *resendEmail, kind event.FeedbackKind) []event.Event {
	account := h.accountID(email.Tags)
	if account == "" {
		return nil
	}
	// The payload's created_at is when the event happened; data.created_at
	// is when the email was sent.
	t := parseTime(hook.CreatedAt)
	if t.IsZero() {
		t = parseTime(email.CreatedAt)
	}
	template := event.Event{
		Type:       event.Feedback,
		Time:       t,
		AccountID:  account,
		From:       bareAddress(email.From),
		Attributes: map[string]string{"provider": "resend"},
	}
	info := event.FeedbackInfo{Kind: kind, MessageID: email.EmailID}
	if kind == event.Bounce {
		// Only a Permanent bounce is hard; Transient and Undetermined
		// count as soft, so the hard bounce rate grows only on evidence.
		info.BounceType = bounceTransient
		if email.Bounce != nil {
			if email.Bounce.Type == "Permanent" {
				info.BounceType = bouncePermanent
			}
			template.Attributes["bounce_subtype"] = email.Bounce.SubType
		}
	}
	// A complaint comes from one person marking the email as spam, so it
	// counts once, whatever the length of the to list, and names its
	// recipient only when the email had one.
	if kind == event.Complaint {
		var rcpt string
		if len(email.To) == 1 {
			rcpt = email.To[0]
		}
		return []event.Event{feedbackEvent(template, info, rcpt)}
	}
	return feedbackEvents(template, info, email.To)
}

// accountID returns the value of the account tag, or "" when the email was
// sent without it.
func (h *resendHandler) accountID(raw json.RawMessage) string {
	var tags map[string]any
	if json.Unmarshal(raw, &tags) != nil {
		return ""
	}
	v, _ := tags[h.accountTag].(string)
	return strings.TrimSpace(v)
}
