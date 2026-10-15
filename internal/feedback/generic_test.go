package feedback

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

const genericSecret = "s3cret"

func catracaSignature(secret string, at time.Time, body []byte) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

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
	rec := post(t, h, b, http.Header{SignatureHeader: {catracaSignature(genericSecret, time.Now(), b)}})
	return rec.Code, rec.Body.String()
}

func TestGenericFeedback(t *testing.T) {
	dec := &recorder{}
	h := newTestGeneric(t, dec, nil)
	code, body := postSigned(t, h, `{
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
	if ev.Type != event.Feedback || ev.AccountID != "acct_123" || ev.From != "news@example.com" || ev.Attributes["provider"] != "postmark" {
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
	good := catracaSignature(genericSecret, now, body)
	tests := []struct {
		name   string
		header string
		ok     bool
	}{
		{"valid", good, true},
		{"rotation: second v1 matches", strings.Replace(catracaSignature("old", now, body), ",v1=", ",v1=00,v1=", 1) + "," + good[strings.Index(good, "v1="):], true},
		{"spaces", strings.ReplaceAll(good, ",", ", "), true},
		{"missing", "", false},
		{"wrong secret", catracaSignature("other", now, body), false},
		{"stale", catracaSignature(genericSecret, now.Add(-10*time.Minute), body), false},
		{"no timestamp", good[strings.Index(good, "v1="):], false},
		{"no signature", good[:strings.Index(good, ",")], false},
		{"bad hex", good[:strings.Index(good, "v1=")] + "v1=zz", false},
		{"bad timestamp", "t=soon," + good[strings.Index(good, "v1="):], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			h := newTestGeneric(t, dec, nil)
			rec := post(t, h, body, http.Header{SignatureHeader: {tt.header}})
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
	h := newTestGeneric(t, &recorder{fail: func(event.Event) bool { return true }}, nil)
	code, body := postSigned(t, h, `{"account_id":"a","feedback":{"kind":"delivery"}}`)
	if code != http.StatusInternalServerError || strings.Contains(body, "exploded") {
		t.Errorf("status %d body %s", code, body)
	}
}

func TestNewGenericHandlerValidatesConfig(t *testing.T) {
	if _, err := NewGenericHandler(GenericConfig{Decider: &recorder{}}); err == nil {
		t.Error("no secret: want an error")
	}
	if _, err := NewGenericHandler(GenericConfig{Secret: "s"}); err == nil {
		t.Error("no decider: want an error")
	}
}
