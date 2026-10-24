package feedback

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/signature"
)

const genericSecret = "s3cret"

func newTestGeneric(t *testing.T, dec Decider, out *outcomes) http.Handler {
	t.Helper()
	cfg := GenericConfig{Decider: dec, Secret: genericSecret}
	if out != nil {
		cfg.OnOutcome = out.add
	}
	h, err := NewGenericHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func postSigned(t *testing.T, h http.Handler, body string) (int, string) {
	t.Helper()
	b := []byte(body)
	rec := post(t, h, b, http.Header{signature.Header: {signature.Sign(genericSecret, time.Now(), b)}})
	return rec.Code, rec.Body.String()
}

func TestGenericFeedback(t *testing.T) {
	dec := &recorder{}
	h := newTestGeneric(t, dec, nil)
	code, body := postSigned(t, h, `{
		"id": "fb_1",
		"account_id": "acct_123",
		"time": "2026-10-15T12:00:00Z",
		"from": "news@example.com",
		"to": ["dropped@example.org"],
		"subject": "dropped",
		"feedback": {"kind": "bounce", "bounce_type": "Permanent", "recipient": "someone@example.org", "message_id": "msg_1"},
		"attributes": {"provider": "postmark"}
	}`)
	if code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", code, body)
	}
	var resp struct {
		Decision struct {
			ID     string `json:"id"`
			Action string `json:"action"`
		} `json:"decision"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil || resp.Decision.ID != "dec_1" || resp.Decision.Action != "allow" {
		t.Errorf("response %s (%v)", body, err)
	}
	evs := dec.got()
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	ev := evs[0]
	if ev.ID != "fb_1" || ev.Type != event.Feedback || ev.AccountID != "acct_123" || ev.From != "news@example.com" || ev.Attributes["provider"] != "postmark" {
		t.Errorf("event %+v", ev)
	}
	if ev.To != nil || ev.Subject != "" {
		t.Errorf("send fields were kept: to %v subject %q", ev.To, ev.Subject)
	}
	want := event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent", Recipient: "someone@example.org", MessageID: "msg_1"}
	if *ev.Feedback != want {
		t.Errorf("feedback %+v, want %+v", *ev.Feedback, want)
	}
	if !ev.Time.Equal(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("time %v", ev.Time)
	}
}

func TestGenericValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
		msg  string
	}{
		{"not json", `{`, "JSON"},
		{"wrong type", `{"type":"send","account_id":"a","feedback":{"kind":"delivery"}}`, "type"},
		{"no account", `{"feedback":{"kind":"delivery"}}`, "account_id"},
		{"no feedback", `{"account_id":"a"}`, "feedback is required"},
		{"bad kind", `{"account_id":"a","feedback":{"kind":"open"}}`, "kind"},
		{"bounce without type", `{"account_id":"a","feedback":{"kind":"bounce"}}`, "bounce_type"},
		{"bad bounce type", `{"account_id":"a","feedback":{"kind":"bounce","bounce_type":"soft"}}`, "bounce_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			var out outcomes
			h := newTestGeneric(t, dec, &out)
			code, body := postSigned(t, h, tt.body)
			if code != http.StatusBadRequest || !strings.Contains(body, tt.msg) {
				t.Errorf("status %d body %s, want 400 mentioning %q", code, body, tt.msg)
			}
			if len(dec.got()) != 0 || !out.has(OutcomeMalformed) {
				t.Error("invalid event was decided")
			}
		})
	}
}

func TestGenericComplaintDropsBounceType(t *testing.T) {
	dec := &recorder{}
	h := newTestGeneric(t, dec, nil)
	if code, body := postSigned(t, h, `{"account_id":"a","feedback":{"kind":"complaint","bounce_type":"permanent"}}`); code != http.StatusAccepted {
		t.Fatalf("status %d body %s", code, body)
	}
	if evs := dec.got(); len(evs) != 1 || evs[0].Feedback.BounceType != "" {
		t.Errorf("events %+v", evs)
	}
}

func TestGenericSignature(t *testing.T) {
	body := []byte(`{"account_id":"a","feedback":{"kind":"delivery"}}`)
	now := time.Now()
	good := signature.Sign(genericSecret, now, body)
	tests := []struct {
		name   string
		header string
		ok     bool
	}{
		{"valid", good, true},
		{"rotation: second v1 matches", strings.Replace(signature.Sign("old", now, body), ",v1=", ",v1=00,v1=", 1) + "," + good[strings.Index(good, "v1="):], true},
		{"spaces", strings.ReplaceAll(good, ",", ", "), true},
		{"missing", "", false},
		{"wrong secret", signature.Sign("other", now, body), false},
		{"stale", signature.Sign(genericSecret, now.Add(-10*time.Minute), body), false},
		{"no timestamp", good[strings.Index(good, "v1="):], false},
		{"no signature", good[:strings.Index(good, ",")], false},
		{"bad hex", good[:strings.Index(good, "v1=")] + "v1=zz", false},
		{"bad timestamp", "t=soon," + good[strings.Index(good, "v1="):], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			h := newTestGeneric(t, dec, nil)
			rec := post(t, h, body, http.Header{signature.Header: {tt.header}})
			if tt.ok != (rec.Code == http.StatusAccepted) {
				t.Fatalf("status %d, want accepted = %v", rec.Code, tt.ok)
			}
			if !tt.ok && rec.Code != http.StatusUnauthorized {
				t.Errorf("status %d, want 401", rec.Code)
			}
		})
	}
}

func TestGenericDecideFails(t *testing.T) {
	for name, dec := range map[string]*recorder{
		"decide fails": {fail: func(event.Event) bool { return true }},
		"store failed": {uncounted: func(event.Event) bool { return true }},
	} {
		h := newTestGeneric(t, dec, nil)
		b := []byte(`{"id":"fb_1","account_id":"a","feedback":{"kind":"delivery"}}`)
		rec := post(t, h, b, http.Header{signature.Header: {signature.Sign(genericSecret, time.Now(), b)}})
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "10" || strings.Contains(rec.Body.String(), "exploded") {
			t.Errorf("%s: status %d, Retry-After %q, body %s; want 503 and 10", name, rec.Code, rec.Header().Get("Retry-After"), rec.Body)
		}
	}
	// A store that answered late still counts the event.
	code, body := postSigned(t, newTestGeneric(t, &recorder{late: func(event.Event) bool { return true }}, nil),
		`{"account_id":"a","feedback":{"kind":"delivery"}}`)
	if code != http.StatusAccepted || !strings.Contains(body, `"degraded":true`) {
		t.Errorf("late store: status %d body %s, want 202 with the degraded decision", code, body)
	}
}

// The platform signs the generic event itself, so when the engine refuses it
// the platform is told why, and that a retry would not help.
func TestGenericEventRefused(t *testing.T) {
	var out outcomes
	h := newTestGeneric(t, &recorder{refuse: func(event.Event) bool { return true }}, &out)
	code, body := postSigned(t, h, `{"account_id":"a","time":"1970-01-01T00:00:00Z","feedback":{"kind":"delivery"}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, `"time 1970-01-01T00:00:00Z is more than 168h0m0s in the past"`) {
		t.Errorf("status %d body %s, want 400 with the reason", code, body)
	}
	if !out.has(OutcomeMalformed) {
		t.Errorf("outcomes %v, want malformed", out.list)
	}
}

// TestGenericSecretRotation checks that with previous secrets, a request
// signed with any configured secret is accepted, whichever the platform
// signs with while it switches, and one signed with another is not.
func TestGenericSecretRotation(t *testing.T) {
	const old, older = "old-feedback-secret", "older-feedback-secret"
	h, err := NewGenericHandler(GenericConfig{Decider: &recorder{}, Secret: genericSecret, PreviousSecrets: []string{old, older}})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"account_id":"a","feedback":{"kind":"delivery"}}`)
	now := time.Now()
	for name, tt := range map[string]struct {
		header string
		want   int
	}{
		"new secret":            {signature.Sign(genericSecret, now, body), http.StatusAccepted},
		"previous secret":       {signature.Sign(old, now, body), http.StatusAccepted},
		"second previous":       {signature.Sign(older, now, body), http.StatusAccepted},
		"new and old together":  {signature.SignAll([]string{genericSecret, old}, now, body), http.StatusAccepted},
		"a secret never set":    {signature.Sign("other", now, body), http.StatusUnauthorized},
		"a previous one, stale": {signature.Sign(old, now.Add(-10*time.Minute), body), http.StatusUnauthorized},
	} {
		if rec := post(t, h, body, http.Header{signature.Header: {tt.header}}); rec.Code != tt.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tt.want)
		}
	}
}

func TestNewGenericHandlerValidatesConfig(t *testing.T) {
	if _, err := NewGenericHandler(GenericConfig{Decider: &recorder{}}); err == nil {
		t.Error("no secret: want an error")
	}
	if _, err := NewGenericHandler(GenericConfig{Decider: &recorder{}, Secret: "s", PreviousSecrets: []string{""}}); err == nil {
		t.Error("an empty previous secret: want an error")
	}
	if _, err := NewGenericHandler(GenericConfig{Secret: "s"}); err == nil {
		t.Error("no decider: want an error")
	}
}
