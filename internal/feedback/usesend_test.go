package feedback

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

const useSendSecret = "whsec_test"

// useSendHeaders signs body the way useSend's webhook service does:
// https://github.com/usesend/useSend/blob/main/apps/web/src/server/service/webhook-service.ts
func useSendHeaders(secret string, at time.Time, body []byte) http.Header {
	ts := strconv.FormatInt(at.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	return http.Header{
		"X-Usesend-Signature": {"v1=" + hex.EncodeToString(mac.Sum(nil))},
		"X-Usesend-Timestamp": {ts},
		"X-Usesend-Event":     {"email.bounced"},
		"Content-Type":        {"application/json"},
	}
}

func newTestUseSend(t *testing.T, cfg UseSendConfig) http.Handler {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = useSendSecret
	}
	h, err := NewUseSendHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The payload follows the documented example and webhook-events.ts.
const useSendBounce = `{
  "id": "call_abc123",
  "type": "email.bounced",
  "version": "2026-01-18",
  "createdAt": "2026-10-15T10:30:05.000Z",
  "teamId": 123,
  "data": {
    "id": "email_123",
    "status": "BOUNCED",
    "from": "Acme <sender@example.com>",
    "to": ["a@example.org", "b@example.org"],
    "subject": "Welcome!",
    "occurredAt": "2026-10-15T10:30:00Z",
    "domainId": 7,
    "metadata": {"bounceType": "Permanent", "bounceSubType": "General"},
    "bounce": {"type": "Permanent", "subType": "General", "message": "smtp; 550 5.1.1 user unknown"}
  },
  "attempt": 1
}`

func TestUseSendBounce(t *testing.T) {
	dec := &recorder{}
	h := newTestUseSend(t, UseSendConfig{Decider: dec})
	body := []byte(useSendBounce)
	rec := post(t, h, body, useSendHeaders(useSendSecret, time.Now(), body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	evs := dec.got()
	if len(evs) != 2 {
		t.Fatalf("got %d events, want one per recipient", len(evs))
	}
	for i, rcpt := range []string{"a@example.org", "b@example.org"} {
		ev := evs[i]
		if err := ev.Validate(); err != nil {
			t.Fatal(err)
		}
		if ev.AccountID != "123" || ev.From != "sender@example.com" {
			t.Errorf("event %d: account %q from %q", i, ev.AccountID, ev.From)
		}
		if !ev.Time.Equal(time.Date(2026, 10, 15, 10, 30, 5, 0, time.UTC)) {
			t.Errorf("event %d: time %v, want createdAt", i, ev.Time)
		}
		want := event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent", Recipient: rcpt, MessageID: "email_123"}
		if *ev.Feedback != want {
			t.Errorf("event %d: feedback %+v, want %+v", i, *ev.Feedback, want)
		}
		if ev.Attributes["provider"] != "usesend" || ev.Attributes["bounce_subtype"] != "General" {
			t.Errorf("event %d: attributes %v", i, ev.Attributes)
		}
	}
}

func TestUseSendKinds(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		kind       event.FeedbackKind
		bounceType string
	}{
		{"transient bounce", `{"type":"email.bounced","teamId":5,"data":{"id":"e","to":["a@example.org"],"bounce":{"type":"Transient","subType":"MailboxFull"}}}`, event.Bounce, "transient"},
		{"undetermined bounce", `{"type":"email.bounced","teamId":5,"data":{"id":"e","to":["a@example.org"],"bounce":{"type":"Undetermined","subType":"General"}}}`, event.Bounce, "transient"},
		{"complaint", `{"type":"email.complained","teamId":5,"data":{"id":"e","to":["a@example.org"],"metadata":{"feedbackType":"abuse"}}}`, event.Complaint, ""},
		{"delivery", `{"type":"email.delivered","teamId":5,"data":{"id":"e","to":["a@example.org"]}}`, event.Delivery, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			h := newTestUseSend(t, UseSendConfig{Decider: dec})
			body := []byte(tt.body)
			if rec := post(t, h, body, useSendHeaders(useSendSecret, time.Now(), body)); rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			evs := dec.got()
			if len(evs) != 1 || evs[0].Feedback.Kind != tt.kind || evs[0].Feedback.BounceType != tt.bounceType || evs[0].AccountID != "5" {
				t.Fatalf("events %+v", evs)
			}
		})
	}
}

func TestUseSendIgnoresOtherEvents(t *testing.T) {
	for _, body := range []string{
		`{"type":"email.opened","teamId":5,"data":{"id":"e","to":["a@example.org"]}}`,
		`{"type":"email.suppressed","teamId":5,"data":{"id":"e","to":["a@example.org"]}}`,
		`{"type":"contact.created","teamId":5,"data":{"id":"c"}}`,
		`{"type":"webhook.test","teamId":5,"data":{"test":true,"webhookId":"wh_abc123"}}`,
		`{"type":"email.complained","teamId":5,"data":{"id":"e","to":["a@example.org"],"metadata":{"feedbackType":"not-spam"}}}`,
	} {
		dec := &recorder{}
		var out outcomes
		h := newTestUseSend(t, UseSendConfig{Decider: dec, OnOutcome: out.add})
		b := []byte(body)
		if rec := post(t, h, b, useSendHeaders(useSendSecret, time.Now(), b)); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", body, rec.Code)
		}
		if len(dec.got()) != 0 || !out.has(OutcomeIgnored) {
			t.Errorf("%s: decided %d events", body, len(dec.got()))
		}
	}
}

func TestUseSendSignature(t *testing.T) {
	body := []byte(useSendBounce)
	now := time.Now()
	tests := []struct {
		name   string
		header http.Header
	}{
		{"no headers", http.Header{}},
		{"wrong secret", useSendHeaders("other", now, body)},
		{"stale timestamp", useSendHeaders(useSendSecret, now.Add(-6*time.Minute), body)},
		{"future timestamp", useSendHeaders(useSendSecret, now.Add(6*time.Minute), body)},
		{"no v1 prefix", func() http.Header {
			h := useSendHeaders(useSendSecret, now, body)
			h.Set("X-UseSend-Signature", h.Get("X-UseSend-Signature")[3:])
			return h
		}()},
		{"timestamp not signed", func() http.Header {
			h := useSendHeaders(useSendSecret, now, body)
			h.Set("X-UseSend-Timestamp", strconv.FormatInt(now.UnixMilli()+1, 10))
			return h
		}()},
		{"seconds instead of milliseconds", func() http.Header {
			h := useSendHeaders(useSendSecret, now, body)
			h.Set("X-UseSend-Timestamp", strconv.FormatInt(now.Unix(), 10))
			return h
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			var out outcomes
			h := newTestUseSend(t, UseSendConfig{Decider: dec, OnOutcome: out.add})
			rec := post(t, h, body, tt.header)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
			if len(dec.got()) != 0 || !out.has(OutcomeInvalidSignature) {
				t.Error("unsigned webhook was decided")
			}
		})
	}

	t.Run("tampered body", func(t *testing.T) {
		dec := &recorder{}
		h := newTestUseSend(t, UseSendConfig{Decider: dec})
		header := useSendHeaders(useSendSecret, now, body)
		tampered := []byte(useSendBounce[:len(useSendBounce)-1] + " }")
		if rec := post(t, h, tampered, header); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", rec.Code)
		}
	})
}

func TestUseSendAccount(t *testing.T) {
	tests := []struct {
		name string
		key  string
		body string
		want string
	}{
		{"team id", "", `{"type":"email.delivered","teamId":42,"data":{"id":"e","to":["a@example.org"]}}`, "42"},
		{"no team id", "", `{"type":"email.delivered","data":{"id":"e","to":["a@example.org"]}}`, ""},
		{"metadata key", "account", `{"type":"email.delivered","teamId":42,"data":{"id":"e","to":["a@example.org"],"metadata":{"account":"acct_9"}}}`, "acct_9"},
		{"numeric metadata", "account", `{"type":"email.delivered","teamId":42,"data":{"id":"e","to":["a@example.org"],"metadata":{"account":1001}}}`, "1001"},
		{"metadata key missing", "account", `{"type":"email.delivered","teamId":42,"data":{"id":"e","to":["a@example.org"]}}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			var out outcomes
			h := newTestUseSend(t, UseSendConfig{Decider: dec, AccountMetadataKey: tt.key, OnOutcome: out.add})
			b := []byte(tt.body)
			if rec := post(t, h, b, useSendHeaders(useSendSecret, time.Now(), b)); rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			evs := dec.got()
			if tt.want == "" {
				if len(evs) != 0 || !out.has(OutcomeNoAccount) {
					t.Errorf("events %+v", evs)
				}
				return
			}
			if len(evs) != 1 || evs[0].AccountID != tt.want {
				t.Errorf("events %+v, want account %q", evs, tt.want)
			}
		})
	}
}

func TestUseSendErrors(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		h := newTestUseSend(t, UseSendConfig{Decider: &recorder{}})
		for _, body := range []string{`not json`, `{"type":"email.bounced","teamId":1,"data":"x"}`, `{}`} {
			b := []byte(body)
			if rec := post(t, h, b, useSendHeaders(useSendSecret, time.Now(), b)); rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status %d, want 400", body, rec.Code)
			}
		}
	})
	t.Run("decide fails: useSend retries", func(t *testing.T) {
		h := newTestUseSend(t, UseSendConfig{Decider: &recorder{fail: func(event.Event) bool { return true }}})
		b := []byte(useSendBounce)
		if rec := post(t, h, b, useSendHeaders(useSendSecret, time.Now(), b)); rec.Code != http.StatusInternalServerError {
			t.Errorf("status %d, want 500", rec.Code)
		}
	})
	t.Run("event refused: no retry that would be refused again", func(t *testing.T) {
		var out outcomes
		h := newTestUseSend(t, UseSendConfig{Decider: &recorder{refuse: func(event.Event) bool { return true }}, OnOutcome: out.add})
		b := []byte(useSendBounce)
		if rec := post(t, h, b, useSendHeaders(useSendSecret, time.Now(), b)); rec.Code != http.StatusOK {
			t.Errorf("status %d, want 200", rec.Code)
		}
		if !out.has(OutcomeMalformed) || out.has(OutcomeDecideFailed) {
			t.Errorf("outcomes %v, want malformed and no decide_failed", out.list)
		}
	})
	t.Run("config", func(t *testing.T) {
		if _, err := NewUseSendHandler(UseSendConfig{Decider: &recorder{}}); err == nil {
			t.Error("no secret: want an error")
		}
		if _, err := NewUseSendHandler(UseSendConfig{Secret: "s"}); err == nil {
			t.Error("no decider: want an error")
		}
	})
}
