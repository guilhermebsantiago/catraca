// Package event defines what a sending platform reports to Catraca: a send it
// is about to make, delivery feedback, account activity and leaked keys.
package event

import (
	"errors"
	"net/mail"
	"strings"
	"time"
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

// Validate reports whether the event has what its type needs.
func (e Event) Validate() error {
	switch e.Type {
	case Send, Feedback, Account, KeyLeak:
	case "":
		return errors.New("event: type is required")
	default:
		return errors.New("event: unknown type " + string(e.Type))
	}
	if e.AccountID == "" && e.Type != KeyLeak {
		return errors.New("event: account_id is required")
	}
	if e.Type == Feedback && e.Feedback == nil {
		return errors.New("event: feedback events need a feedback object")
	}
	if e.Type == KeyLeak && e.APIKeyID == "" {
		return errors.New("event: key_leak events need api_key_id")
	}
	return nil
}

// Normalize fills Time when it is zero and lowercases addresses, so counters
// key on the same value however the platform spelled it.
func (e *Event) Normalize(now time.Time) {
	if e.Time.IsZero() {
		e.Time = now
	}
	e.Time = e.Time.UTC()
	e.From = strings.ToLower(strings.TrimSpace(e.From))
	for i, to := range e.To {
		e.To[i] = strings.ToLower(strings.TrimSpace(to))
	}
	if e.Feedback != nil {
		e.Feedback.Recipient = strings.ToLower(strings.TrimSpace(e.Feedback.Recipient))
	}
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
