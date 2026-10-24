// Package event defines what a sending platform reports to Catraca: a send it
// is about to make, delivery feedback, account activity and leaked keys.
package event

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Type is the kind of event.
type Type string

const (
	// Send is an email the platform is about to send. It is decided
	// synchronously, inside the platform's request.
	Send Type = "send"
	// Feedback is a delivery outcome: a bounce, a complaint or a delivery.
	Feedback Type = "feedback"
	// Account is account activity: signup, login, a new API key or domain.
	Account Type = "account"
	// KeyLeak is an API key found in public, for example by GitHub secret
	// scanning.
	KeyLeak Type = "key_leak"
)

// FeedbackKind is the outcome carried by a Feedback event.
type FeedbackKind string

const (
	Bounce    FeedbackKind = "bounce"
	Complaint FeedbackKind = "complaint"
	Delivery  FeedbackKind = "delivery"
)

// Event is one thing that happened on the platform. Only Type, AccountID and
// Time are required; the rest depends on the type.
type Event struct {
	ID        string    `json:"id,omitempty"`
	Type      Type      `json:"type"`
	Time      time.Time `json:"time"`
	AccountID string    `json:"account_id"`
	APIKeyID  string    `json:"api_key_id,omitempty"`
	IP        string    `json:"ip,omitempty"`

	// Send fields.
	From    string   `json:"from,omitempty"`
	To      []string `json:"to,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Links   []string `json:"links,omitempty"`

	Feedback *FeedbackInfo `json:"feedback,omitempty"`
	Account  *AccountInfo  `json:"account,omitempty"`
	Leak     *LeakInfo     `json:"leak,omitempty"`

	// Attributes carries platform-specific values, exposed to rules as
	// event.attributes.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// FeedbackInfo describes a delivery outcome.
type FeedbackInfo struct {
	Kind FeedbackKind `json:"kind"`
	// BounceType is "permanent" or "transient" for bounces.
	BounceType string `json:"bounce_type,omitempty"`
	Recipient  string `json:"recipient,omitempty"`
	// MessageID is the platform's id for the email the feedback is about.
	MessageID string `json:"message_id,omitempty"`
}

// AccountInfo describes account activity and what the platform knows about
// the account.
type AccountInfo struct {
	// Action is what happened, for example "signup", "login",
	// "api_key_created" or "domain_added".
	Action string `json:"action,omitempty"`
	// CreatedAt is when the account was created. When it is unknown, Catraca
	// uses the first time it saw the account.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	Plan      string     `json:"plan,omitempty"`
}

// LeakInfo describes where a leaked key was found.
type LeakInfo struct {
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
}

// Limits on one event. A real email stays far below each of them. They keep
// one event from taking over what every decision shares: the counter store,
// whose work for a send grows with its distinct recipient domains, and the
// audit log.
const (
	// MaxIDBytes bounds id, account_id, api_key_id, ip and the names of
	// attributes. An email address, which some platforms use as the account
	// id, is at most 254 bytes.
	MaxIDBytes = 256
	// MaxRecipients bounds to. Providers take 50 recipients per message (SES,
	// Postmark, Resend) up to 1,000 (Mailgun and SendGrid batches), and
	// 1,000 is also Postfix's default smtpd_recipient_limit.
	MaxRecipients = 1000
	// MaxLinks bounds links.
	MaxLinks = 1000
	// MaxAttributes bounds the number of attributes.
	MaxAttributes = 64
	// MaxTextBytes bounds every other string: an address, the subject, a
	// link, an attribute value. Long tracking links fit with room to spare.
	MaxTextBytes = 8 << 10
)

// ErrInvalid is wrapped by the errors of Validate, and by the engine's for an
// event it refuses, so a caller that only sees a Decider's error can tell an
// event that will never be accepted from a failure worth retrying.
var ErrInvalid = errors.New("invalid event")

// invalid is an error of Validate. Its message names the problem for the
// platform; it wraps ErrInvalid.
type invalid string

func (e invalid) Error() string { return "event: " + string(e) }
func (invalid) Unwrap() error   { return ErrInvalid }

func invalidf(format string, args ...any) error { return invalid(fmt.Sprintf(format, args...)) }

// Validate reports whether the event has what its type needs and stays within
// the limits above. Identifiers (id, account_id, api_key_id, ip and attribute
// names) must be valid UTF-8 without control characters: they become store
// keys and audit columns, and show up in terminals. No string may contain
// NUL, which no email field can carry and Postgres cannot store.
func (e Event) Validate() error {
	switch e.Type {
	case Send, Feedback, Account, KeyLeak:
	case "":
		return invalid("type is required")
	default:
		return invalid("unknown type " + string(e.Type))
	}
	if e.AccountID == "" && e.Type != KeyLeak {
		return invalid("account_id is required")
	}
	if e.Type == Feedback && e.Feedback == nil {
		return invalid("feedback events need a feedback object")
	}
	if e.Type == KeyLeak && e.APIKeyID == "" {
		return invalid("key_leak events need api_key_id")
	}
	return e.checkLimits()
}

// checkLimits runs on every decision, so it formats a field's name only once
// the field is found wrong.
func (e Event) checkLimits() error {
	for _, f := range [...]field{{"id", e.ID}, {"account_id", e.AccountID}, {"api_key_id", e.APIKeyID}, {"ip", e.IP}} {
		if p := idProblem(f.v); p != "" {
			return invalid(f.name + " " + p)
		}
	}
	if err := checkList("to", e.To, MaxRecipients, "addresses"); err != nil {
		return err
	}
	if err := checkList("links", e.Links, MaxLinks, "links"); err != nil {
		return err
	}
	if n := len(e.Attributes); n > MaxAttributes {
		return invalidf("attributes has %d entries; at most %d are accepted", n, MaxAttributes)
	}
	for k, v := range e.Attributes {
		if p := idProblem(k); p != "" {
			return invalidf("attribute name %s %s", quote(k), p)
		}
		if p := textProblem(v); p != "" {
			return invalidf("attributes[%s] %s", quote(k), p)
		}
	}
	// An absent object checks as empty strings, which pass.
	var (
		fb   FeedbackInfo
		acct AccountInfo
		leak LeakInfo
	)
	if e.Feedback != nil {
		fb = *e.Feedback
	}
	if e.Account != nil {
		acct = *e.Account
	}
	if e.Leak != nil {
		leak = *e.Leak
	}
	for _, f := range [...]field{
		{"from", e.From}, {"subject", e.Subject},
		{"feedback.kind", string(fb.Kind)}, {"feedback.bounce_type", fb.BounceType},
		{"feedback.recipient", fb.Recipient}, {"feedback.message_id", fb.MessageID},
		{"account.action", acct.Action}, {"account.plan", acct.Plan},
		{"leak.source", leak.Source}, {"leak.url", leak.URL},
	} {
		if p := textProblem(f.v); p != "" {
			return invalid(f.name + " " + p)
		}
	}
	return nil
}

type field struct{ name, v string }

// idProblem says what is wrong with an identifier, or returns "": it must be
// at most MaxIDBytes of valid UTF-8 without control characters.
func idProblem(v string) string {
	if len(v) > MaxIDBytes {
		return fmt.Sprintf("is %d bytes; at most %d are accepted", len(v), MaxIDBytes)
	}
	for i := 0; i < len(v); {
		c := v[i]
		if c < utf8.RuneSelf {
			if c < 0x20 || c == 0x7f {
				return fmt.Sprintf("contains the control character %U", rune(c))
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(v[i:])
		if r == utf8.RuneError && size == 1 {
			return "is not valid UTF-8"
		}
		if unicode.IsControl(r) {
			return fmt.Sprintf("contains the control character %U", r)
		}
		i += size
	}
	return ""
}

// textProblem says what is wrong with any other string, or returns "": it
// must be at most MaxTextBytes, without NUL.
func textProblem(v string) string {
	if len(v) > MaxTextBytes {
		return fmt.Sprintf("is %d bytes; at most %d are accepted", len(v), MaxTextBytes)
	}
	if strings.IndexByte(v, 0) >= 0 {
		return "contains NUL (U+0000)"
	}
	return ""
}

// checkList checks the length of a list and each of its strings.
func checkList(name string, vs []string, limit int, what string) error {
	if len(vs) > limit {
		return invalidf("%s has %d %s; at most %d are accepted", name, len(vs), what, limit)
	}
	for i, v := range vs {
		if p := textProblem(v); p != "" {
			return invalidf("%s[%d] %s", name, i, p)
		}
	}
	return nil
}

// quote quotes s for an error message, escaping control characters, and
// shortens it so a huge name does not make a huge message.
func quote(s string) string {
	const limit = 64
	if len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "") + "..."
	}
	return fmt.Sprintf("%q", s)
}

// Normalize fills Time when it is zero and lowercases addresses, so counters
// key on the same value however the platform spelled it. A valid event stays
// valid once normalized.
func (e *Event) Normalize(now time.Time) {
	if e.Time.IsZero() {
		e.Time = now
	}
	e.Time = e.Time.UTC()
	e.From = lowerAddress(e.From)
	for i, to := range e.To {
		e.To[i] = lowerAddress(to)
	}
	if e.Feedback != nil {
		e.Feedback.Recipient = lowerAddress(e.Feedback.Recipient)
	}
}

// lowerAddress trims and lowercases an address. The lowercase of U+023A and
// U+023E takes a byte more than they do, and invalid UTF-8 turns into U+FFFD,
// three bytes for each bad one, so an address whose lowercase would outgrow
// MaxTextBytes is only trimmed: lowercased, it would take the event past the
// limit Validate checked, and the work and storage it bounds with it.
func lowerAddress(s string) string {
	s = strings.TrimSpace(s)
	if l := strings.ToLower(s); len(l) <= MaxTextBytes || len(l) <= len(s) {
		return l
	}
	return s
}

// DomainOf returns the domain of an email address, or "" when it has none.
// It accepts both "user@example.com" and "Name <user@example.com>".
func DomainOf(address string) string {
	if a, err := mail.ParseAddress(address); err == nil {
		address = a.Address
	}
	at := strings.LastIndexByte(address, '@')
	if at < 0 || at == len(address)-1 {
		return ""
	}
	return strings.ToLower(address[at+1:])
}
