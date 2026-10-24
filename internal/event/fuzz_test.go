package event

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// FuzzEvent decodes a body as POST /v1/decide does, strictly, and checks
// what the engine relies on: Validate and Normalize never panic, Validate
// accepts exactly the events within the limits, Normalize is idempotent, and
// a valid event stays valid, within the limits, once normalized.
func FuzzEvent(f *testing.F) {
	for _, seed := range []string{
		// The examples of docs/api.md.
		`{"type": "send", "account_id": "acct_42", "api_key_id": "key_7d3e", "ip": "203.0.113.7",
		  "from": "hello@shop.example", "to": ["ana@mail.example"], "subject": "Your receipt",
		  "links": ["https://shop.example/r/1"]}`,
		`{"type": "account", "account_id": "acct_new", "ip": "198.51.100.4",
		  "account": {"action": "signup", "created_at": "2026-10-15T12:00:00Z"}}`,
		`{"type": "key_leak", "account_id": "acct_42", "api_key_id": "key_7d3e", "leak": {"source": "support-ticket"}}`,
		`{"id": "fb_123", "type": "feedback", "account_id": "acct_123", "time": "2026-10-15T12:00:00Z",
		  "from": "News <News@Example.com>", "attributes": {"provider": "postmark"},
		  "feedback": {"kind": "bounce", "bounce_type": "permanent", "recipient": " Someone@Example.ORG ", "message_id": "msg_1"}}`,
		`{"type": "send", "account_id": "conta-ação-日本", "api_key_id": "chave_🔑", "ip": "fe80::1%eth0",
		  "from": "\tNews <news@shop.example>\n", "subject": "Line one\r\n\tline two", "time": "2026-10-15T09:00:00-03:00"}`,
		`{"type": "send", "account_id": "acct\u0085", "to": ["a\u0000@b.example"]}`,
		`{"type": "teleport", "account_id": "a"}`,
		`{"type": "feedback", "account_id": "a"}`,
		`{"type": "send", "account_id": "a", "time": "0001-01-01T00:00:00Z"}`,
		`{"type": "send", "account_id": "a", "time": "9999-12-31T23:59:59.999999999-23:59"}`,
	} {
		f.Add([]byte(seed))
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, body []byte) {
		ev, ok := decodeStrict(body)
		if !ok {
			return
		}
		err := ev.Validate()
		if problem := limitsProblem(ev); (err == nil) != (problem == "") {
			t.Fatalf("Validate = %v, but the reference check finds %q", err, problem)
		}

		ev.Normalize(now)
		if ev.Time.IsZero() || ev.Time.Location() != time.UTC {
			t.Errorf("normalized time %v is zero or not UTC", ev.Time)
		}
		if err == nil {
			if err := ev.Validate(); err != nil {
				t.Errorf("a valid event is invalid once normalized: %v", err)
			}
		}
		again, _ := decodeStrict(body)
		again.Normalize(now)
		again.Normalize(now.Add(time.Hour))
		if !reflect.DeepEqual(again, ev) {
			t.Errorf("Normalize is not idempotent:\nonce  %+v\ntwice %+v", ev, again)
		}
	})
}

// decodeStrict decodes body as the API does: unknown fields and trailing
// data are errors.
func decodeStrict(body []byte) (Event, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var ev Event
	if dec.Decode(&ev) != nil {
		return Event{}, false
	}
	if _, err := dec.Token(); err == nil {
		return Event{}, false
	}
	return ev, true
}

// limitsProblem is a reference for Validate written from its documentation:
// it names a problem, or returns "" for an event Validate must accept.
func limitsProblem(e Event) string {
	switch {
	case e.Type != Send && e.Type != Feedback && e.Type != Account && e.Type != KeyLeak:
		return "type"
	case e.AccountID == "" && e.Type != KeyLeak:
		return "account_id required"
	case e.Type == Feedback && e.Feedback == nil:
		return "feedback required"
	case e.Type == KeyLeak && e.APIKeyID == "":
		return "api_key_id required"
	case len(e.To) > MaxRecipients, len(e.Links) > MaxLinks, len(e.Attributes) > MaxAttributes:
		return "list too long"
	}
	ids := []string{e.ID, e.AccountID, e.APIKeyID, e.IP}
	texts := []string{e.From, e.Subject}
	texts = append(texts, e.To...)
	texts = append(texts, e.Links...)
	for k, v := range e.Attributes {
		ids = append(ids, k)
		texts = append(texts, v)
	}
	if fb := e.Feedback; fb != nil {
		texts = append(texts, string(fb.Kind), fb.BounceType, fb.Recipient, fb.MessageID)
	}
	if a := e.Account; a != nil {
		texts = append(texts, a.Action, a.Plan)
	}
	if l := e.Leak; l != nil {
		texts = append(texts, l.Source, l.URL)
	}
	for _, id := range ids {
		if len(id) > MaxIDBytes || !utf8.ValidString(id) || strings.ContainsFunc(id, unicode.IsControl) {
			return "identifier " + id
		}
	}
	for _, s := range texts {
		if len(s) > MaxTextBytes || strings.ContainsRune(s, 0) {
			return "text " + s
		}
	}
	return ""
}
