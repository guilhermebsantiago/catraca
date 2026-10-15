package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// maxRecipientDomains bounds the domains kept for one event, so a send to
// thousands of recipients does not make a huge row.
const maxRecipientDomains = 100

// StoredEvent is what the log keeps of an event: enough to review a decision,
// and no message content. Addresses are reduced to their domains and the
// subject to a hash prefix.
type StoredEvent struct {
	ID         string     `json:"id,omitempty"`
	Type       event.Type `json:"type"`
	Time       time.Time  `json:"time"`
	AccountID  string     `json:"account_id"`
	APIKeyID   string     `json:"api_key_id,omitempty"`
	IP         string     `json:"ip,omitempty"`
	FromDomain string     `json:"from_domain,omitempty"`
	// Recipients is the number of recipients.
	Recipients int `json:"recipients,omitempty"`
	// RecipientDomains are the distinct recipient domains, in the order they
	// first appear, at most 100.
	RecipientDomains []string `json:"recipient_domains,omitempty"`
	// SubjectSHA256 is the first 16 hex digits of the SHA-256 of the
	// subject: equal subjects can be grouped without keeping the text.
	SubjectSHA256 string `json:"subject_sha256,omitempty"`
	// FeedbackKind, BounceType and AccountAction say what a feedback or
	// account event was about.
	FeedbackKind  event.FeedbackKind `json:"feedback_kind,omitempty"`
	BounceType    string             `json:"bounce_type,omitempty"`
	AccountAction string             `json:"account_action,omitempty"`
	// Full is the whole event, set only in EventFull mode.
	Full *event.Event `json:"full,omitempty"`
}

// NewStoredEvent returns what the log keeps of ev in the given mode. In
// EventFull mode, Full shares ev's slices and maps.
func NewStoredEvent(ev event.Event, mode EventMode) StoredEvent {
	s := StoredEvent{
		ID:         ev.ID,
		Type:       ev.Type,
		Time:       ev.Time,
		AccountID:  ev.AccountID,
		APIKeyID:   ev.APIKeyID,
		IP:         ev.IP,
		FromDomain: event.DomainOf(ev.From),
		Recipients: len(ev.To),
	}
	if len(ev.To) > 0 {
		seen := make(map[string]bool, len(ev.To))
		for _, to := range ev.To {
			d := event.DomainOf(to)
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			s.RecipientDomains = append(s.RecipientDomains, d)
			if len(s.RecipientDomains) == maxRecipientDomains {
				break
			}
		}
	}
	if ev.Subject != "" {
		sum := sha256.Sum256([]byte(ev.Subject))
		s.SubjectSHA256 = hex.EncodeToString(sum[:8])
	}
	if ev.Feedback != nil {
		s.FeedbackKind = ev.Feedback.Kind
		s.BounceType = ev.Feedback.BounceType
	}
	if ev.Account != nil {
		s.AccountAction = ev.Account.Action
	}
	if mode == EventFull {
		full := ev
		s.Full = &full
	}
	return s
}
