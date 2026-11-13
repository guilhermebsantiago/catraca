package feedback

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// The secret, message and signature of the example in Svix's guide to
// verifying webhooks by hand:
// https://docs.svix.com/receiving/verifying-payloads/how-manual
const (
	svixDocSecret    = "whsec_plJ3nmyCDGBKInavdOK15jsl"
	svixDocID        = "msg_loFOjxBNrRLzqYUf"
	svixDocTimestamp = "1731705121"
	svixDocBody      = `{"event_type":"ping","data":{"success":true}}`
	svixDocSignature = "v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0="
)

const (
	resendSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	resendID     = "msg_2Jm8PZbYcSu2Ihm9CUNZBVBKVGx"
)

// svixSign returns the svix-signature entry of body: what Resend sends for
// one secret.
func svixSign(t testing.TB, secret, id string, at time.Time, body []byte) string {
	t.Helper()
	key, err := DecodeResendSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + strconv.FormatInt(at.Unix(), 10) + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// resendHeaders signs body as Resend does, with id as svix-id.
func resendHeaders(t testing.TB, secret, id string, at time.Time, body []byte) http.Header {
	t.Helper()
	return http.Header{
		"Svix-Id":        {id},
		"Svix-Timestamp": {strconv.FormatInt(at.Unix(), 10)},
		"Svix-Signature": {svixSign(t, secret, id, at, body)},
		"Content-Type":   {"application/json"},
	}
}

func newTestResend(t testing.TB, cfg ResendConfig) *resendHandler {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = resendSecret
	}
	h, err := NewResendHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h.(*resendHandler)
}

// postResend signs body with resendSecret and resendID, as of now, and
// posts it.
func postResend(t *testing.T, h http.Handler, body string) int {
	t.Helper()
	b := []byte(body)
	return post(t, h, b, resendHeaders(t, resendSecret, resendID, time.Now(), b)).Code
}

// The payload is the documented example of email.bounced, with a second
// recipient and the account tag.
// https://resend.com/docs/webhooks/emails/bounced
const resendBounce = `{
  "type": "email.bounced",
  "created_at": "2026-11-12T23:41:12.126Z",
  "data": {
    "broadcast_id": "8b146471-e88e-4322-86af-016cd36fd216",
    "created_at": "2026-11-12T23:41:11.894Z",
    "email_id": "56761188-7520-42d8-8898-ff6fc54ce618",
    "message_id": "<111-222-333@email.example.com>",
    "from": "Acme <onboarding@example.com>",
    "to": ["a@example.org", "b@example.org"],
    "subject": "Sending this example",
    "template_id": "43f68331-0622-4e15-8202-246a0388854b",
    "bounce": {
      "message": "The recipient's email address is on the suppression list because it has a recent history of producing hard bounces.",
      "subType": "Suppressed",
      "type": "Permanent"
    },
    "tags": {"category": "confirm_email", "catraca-account": "acct_123"}
  }
}`

// TestResendSvixExample checks the verification against the example in
// Svix's guide, at the example's time.
func TestResendSvixExample(t *testing.T) {
	for _, secret := range []string{svixDocSecret, strings.TrimPrefix(svixDocSecret, "whsec_")} {
		h := newTestResend(t, ResendConfig{Decider: &recorder{}, Secret: secret})
		unix, _ := strconv.ParseInt(svixDocTimestamp, 10, 64)
		h.now = func() time.Time { return time.Unix(unix, 0).Add(time.Minute) }
		header := http.Header{"Svix-Id": {svixDocID}, "Svix-Timestamp": {svixDocTimestamp}, "Svix-Signature": {svixDocSignature}}
		if id, ok := h.verify(header, []byte(svixDocBody)); !ok || id != svixDocID {
			t.Errorf("secret %q: verify = %q, %v; want the example to verify", secret, id, ok)
		}
		if _, ok := h.verify(header, []byte(svixDocBody+" ")); ok {
			t.Errorf("secret %q: the example with a space added verifies", secret)
		}
		// The example is two years old by now.
		h.now = time.Now
		if _, ok := h.verify(header, []byte(svixDocBody)); ok {
			t.Errorf("secret %q: the example verifies today", secret)
		}
	}
}

func TestResendSignature(t *testing.T) {
	body := []byte(resendBounce)
	now := time.Now()
	good := svixSign(t, resendSecret, resendID, now, body)
	headers := func(edit func(http.Header)) http.Header {
		h := resendHeaders(t, resendSecret, resendID, now, body)
		edit(h)
		return h
	}
	tests := []struct {
		name   string
		header http.Header
		want   int
	}{
		{"valid", headers(func(http.Header) {}), http.StatusOK},
		{"valid among several", headers(func(h http.Header) {
			h.Set("Svix-Signature", svixSign(t, "whsec_b3RoZXI=", resendID, now, body)+" v1,AAAA "+good+" v2,"+good[3:])
		}), http.StatusOK},
		{"valid after unknown versions", headers(func(h http.Header) { h.Set("Svix-Signature", "v1a,xyz v2,"+good[3:]+" "+good) }), http.StatusOK},
		{"valid after one that does not decode", headers(func(h http.Header) { h.Set("Svix-Signature", "v1,!!! "+good) }), http.StatusOK},
		{"four minutes old", resendHeaders(t, resendSecret, resendID, now.Add(-4*time.Minute), body), http.StatusOK},
		{"four minutes ahead", resendHeaders(t, resendSecret, resendID, now.Add(4*time.Minute), body), http.StatusOK},
		{"wrong secret", resendHeaders(t, "whsec_b3RoZXI=", resendID, now, body), http.StatusUnauthorized},
		{"no headers", http.Header{}, http.StatusUnauthorized},
		{"no svix-id", headers(func(h http.Header) { h.Del("Svix-Id") }), http.StatusUnauthorized},
		{"no svix-timestamp", headers(func(h http.Header) { h.Del("Svix-Timestamp") }), http.StatusUnauthorized},
		{"no svix-signature", headers(func(h http.Header) { h.Del("Svix-Signature") }), http.StatusUnauthorized},
		{"empty svix-signature", headers(func(h http.Header) { h.Set("Svix-Signature", "") }), http.StatusUnauthorized},
		{"no version", headers(func(h http.Header) { h.Set("Svix-Signature", good[3:]) }), http.StatusUnauthorized},
		{"another version", headers(func(h http.Header) { h.Set("Svix-Signature", "v2,"+good[3:]) }), http.StatusUnauthorized},
		{"v1= instead of v1,", headers(func(h http.Header) { h.Set("Svix-Signature", "v1="+good[3:]) }), http.StatusUnauthorized},
		{"hex instead of base64", headers(func(h http.Header) {
			sig, _ := base64.StdEncoding.DecodeString(good[3:])
			h.Set("Svix-Signature", "v1,"+hex.EncodeToString(sig))
		}), http.StatusUnauthorized},
		{"comma-separated list", headers(func(h http.Header) { h.Set("Svix-Signature", "v1,AAAA,"+good) }), http.StatusUnauthorized},
		{"timestamp in milliseconds", headers(func(h http.Header) { h.Set("Svix-Timestamp", strconv.FormatInt(now.UnixMilli(), 10)) }), http.StatusUnauthorized},
		{"timestamp not a number", headers(func(h http.Header) { h.Set("Svix-Timestamp", "soon") }), http.StatusUnauthorized},
		{"stale timestamp", resendHeaders(t, resendSecret, resendID, now.Add(-6*time.Minute), body), http.StatusUnauthorized},
		{"future timestamp", resendHeaders(t, resendSecret, resendID, now.Add(6*time.Minute), body), http.StatusUnauthorized},
		{"timestamp not signed", headers(func(h http.Header) { h.Set("Svix-Timestamp", strconv.FormatInt(now.Unix()+1, 10)) }), http.StatusUnauthorized},
		// The id is signed, so a recorded webhook cannot be posted again
		// under another id to count again.
		{"svix-id not signed", headers(func(h http.Header) { h.Set("Svix-Id", resendID+"x") }), http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			var out outcomes
			h := newTestResend(t, ResendConfig{Decider: dec, OnOutcome: out.add})
			rec := post(t, h, body, tt.header)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			if tt.want == http.StatusUnauthorized && (len(dec.got()) != 0 || !out.has(OutcomeInvalidSignature)) {
				t.Errorf("decided %d events, outcomes %v; want none and invalid_signature", len(dec.got()), out.list)
			}
			if tt.want == http.StatusOK && len(dec.got()) != 2 {
				t.Errorf("decided %d events, want 2", len(dec.got()))
			}
		})
	}

	t.Run("tampered body", func(t *testing.T) {
		dec := &recorder{}
		h := newTestResend(t, ResendConfig{Decider: dec})
		tampered := []byte(strings.Replace(resendBounce, "acct_123", "acct_124", 1))
		if rec := post(t, h, tampered, resendHeaders(t, resendSecret, resendID, now, body)); rec.Code != http.StatusUnauthorized || len(dec.got()) != 0 {
			t.Fatalf("status %d, decided %d; want 401 and none", rec.Code, len(dec.got()))
		}
	})
}

// TestResendSecretRotation checks that a webhook signed with the new or a
// previous secret is accepted, with or without the whsec_ prefix, as is one
// signed with both, as Resend signs for a day after a rotation.
func TestResendSecretRotation(t *testing.T) {
	const newSecret, older = "whsec_bmV3LXNlY3JldC0wMTIzNDU2Nzg5", "whsec_b2xkZXItc2VjcmV0LTAxMjM0NTY3"
	body := []byte(resendBounce)
	now := time.Now()
	for name, tt := range map[string]struct {
		secrets []string
		want    int
	}{
		"new secret":         {[]string{newSecret}, http.StatusOK},
		"previous secret":    {[]string{resendSecret}, http.StatusOK},
		"second previous":    {[]string{older}, http.StatusOK},
		"both":               {[]string{resendSecret, newSecret}, http.StatusOK},
		"a secret never set": {[]string{"whsec_b3RoZXI="}, http.StatusUnauthorized},
	} {
		var sigs []string
		for _, s := range tt.secrets {
			sigs = append(sigs, svixSign(t, s, resendID, now, body))
		}
		header := resendHeaders(t, newSecret, resendID, now, body)
		header.Set("Svix-Signature", strings.Join(sigs, " "))
		for _, previous := range [][]string{{resendSecret, older}, {strings.TrimPrefix(resendSecret, "whsec_"), strings.TrimPrefix(older, "whsec_")}} {
			h := newTestResend(t, ResendConfig{Decider: &recorder{}, Secret: strings.TrimPrefix(newSecret, "whsec_"), PreviousSecrets: previous})
			if rec := post(t, h, body, header); rec.Code != tt.want {
				t.Errorf("%s, previous %q: status %d, want %d", name, previous, rec.Code, tt.want)
			}
		}
	}
}

func TestResendBounce(t *testing.T) {
	dec := &recorder{}
	h := newTestResend(t, ResendConfig{Decider: dec})
	if code := postResend(t, h, resendBounce); code != http.StatusOK {
		t.Fatalf("status %d", code)
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
		if ev.AccountID != "acct_123" || ev.From != "onboarding@example.com" || ev.ID != "resend:"+resendID+":"+strconv.Itoa(i) {
			t.Errorf("event %d: account %q from %q id %q", i, ev.AccountID, ev.From, ev.ID)
		}
		if !ev.Time.Equal(time.Date(2026, 11, 12, 23, 41, 12, 126e6, time.UTC)) {
			t.Errorf("event %d: time %v, want the event's created_at", i, ev.Time)
		}
		want := event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent", Recipient: rcpt, MessageID: "56761188-7520-42d8-8898-ff6fc54ce618"}
		if *ev.Feedback != want {
			t.Errorf("event %d: feedback %+v, want %+v", i, *ev.Feedback, want)
		}
		if ev.Attributes["provider"] != "resend" || ev.Attributes["bounce_subtype"] != "Suppressed" || len(ev.Attributes) != 2 {
			t.Errorf("event %d: attributes %v", i, ev.Attributes)
		}
	}
}

func TestResendKinds(t *testing.T) {
	const tags = `"tags":{"catraca-account":"acct_5"}`
	tests := []struct {
		name       string
		body       string
		kind       event.FeedbackKind
		bounceType string
		subtype    string
	}{
		{"transient bounce", `{"type":"email.bounced","data":{"email_id":"e","to":["a@example.org"],"bounce":{"type":"Transient","subType":"MailboxFull"},` + tags + `}}`, event.Bounce, "transient", "MailboxFull"},
		{"undetermined bounce", `{"type":"email.bounced","data":{"email_id":"e","to":["a@example.org"],"bounce":{"type":"Undetermined","subType":"Undetermined"},` + tags + `}}`, event.Bounce, "transient", "Undetermined"},
		{"temporary bounce", `{"type":"email.bounced","data":{"email_id":"e","to":["a@example.org"],"bounce":{"type":"Temporary","subType":"General"},` + tags + `}}`, event.Bounce, "transient", "General"},
		{"bounce of unknown type", `{"type":"email.bounced","data":{"email_id":"e","to":["a@example.org"],"bounce":{"type":"permanent"},` + tags + `}}`, event.Bounce, "transient", ""},
		{"bounce without details", `{"type":"email.bounced","data":{"email_id":"e","to":["a@example.org"],` + tags + `}}`, event.Bounce, "transient", ""},
		{"complaint", `{"type":"email.complained","data":{"email_id":"e","to":["a@example.org"],` + tags + `}}`, event.Complaint, "", ""},
		{"delivery", `{"type":"email.delivered","data":{"email_id":"e","to":["a@example.org"],` + tags + `}}`, event.Delivery, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			h := newTestResend(t, ResendConfig{Decider: dec})
			if code := postResend(t, h, tt.body); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			evs := dec.got()
			if len(evs) != 1 || evs[0].Feedback.Kind != tt.kind || evs[0].Feedback.BounceType != tt.bounceType ||
				evs[0].AccountID != "acct_5" || evs[0].Feedback.Recipient != "a@example.org" || evs[0].Attributes["bounce_subtype"] != tt.subtype {
				t.Fatalf("events %+v", evs)
			}
			if err := evs[0].Validate(); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestResendComplaintCountsOnce checks that a complaint about an email to
// many addresses is one event, naming the recipient only when there was
// one, and that the same webhook sent again has the same event id.
func TestResendComplaintCountsOnce(t *testing.T) {
	tests := []struct {
		name string
		to   string
		rcpt string
	}{
		{"three recipients", `["a@example.org","b@example.org","c@example.org"]`, ""},
		{"one recipient", `["a@example.org"]`, "a@example.org"},
		{"no recipients", `[]`, ""},
		{"no to", `null`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			h := newTestResend(t, ResendConfig{Decider: dec})
			body := `{"type":"email.complained","created_at":"2026-11-12T10:00:00Z","data":{"email_id":"email_9","to":` + tt.to + `,"tags":{"catraca-account":"acct_1"}}}`
			for range 2 {
				if code := postResend(t, h, body); code != http.StatusOK {
					t.Fatalf("status %d", code)
				}
			}
			evs := dec.got()
			if len(evs) != 2 {
				t.Fatalf("got %d events, want one per webhook", len(evs))
			}
			for _, ev := range evs {
				want := event.FeedbackInfo{Kind: event.Complaint, Recipient: tt.rcpt, MessageID: "email_9"}
				if *ev.Feedback != want || ev.ID != "resend:"+resendID+":0" {
					t.Errorf("event %s: feedback %+v, want %+v", ev.ID, *ev.Feedback, want)
				}
			}
		})
	}
}

func TestResendIgnoresOtherEvents(t *testing.T) {
	for _, typ := range []string{
		"email.sent", "email.scheduled", "email.delivery_delayed", "email.opened", "email.clicked",
		"email.failed", "email.suppressed", "email.received", "contact.created", "domain.updated",
		"suppression.added", "topic.deleted", "inbox.thread.created",
	} {
		dec := &recorder{}
		var out outcomes
		h := newTestResend(t, ResendConfig{Decider: dec, OnOutcome: out.add})
		body := `{"type":"` + typ + `","created_at":"2026-11-12T10:00:00Z","data":{"email_id":"e","to":["a@example.org"],"tags":{"catraca-account":"acct_1"}}}`
		if code := postResend(t, h, body); code != http.StatusOK {
			t.Errorf("%s: status %d", typ, code)
		}
		if len(dec.got()) != 0 || !out.has(OutcomeIgnored) {
			t.Errorf("%s: decided %d events, outcomes %v", typ, len(dec.got()), out.list)
		}
	}
}

func TestResendAccount(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		tags string
		want string
	}{
		{"default tag", "", `{"catraca-account":"acct_9"}`, "acct_9"},
		{"spaces around", "", `{"catraca-account":"  acct_9 "}`, "acct_9"},
		{"tag of the config", "workspace_id", `{"catraca-account":"acct_9","workspace_id":"ws_42"}`, "ws_42"},
		{"no tags", "", ``, ""},
		{"null tags", "", `null`, ""},
		{"other tags only", "", `{"category":"welcome"}`, ""},
		{"empty value", "", `{"catraca-account":""}`, ""},
		{"blank value", "", `{"catraca-account":"   "}`, ""},
		{"number value", "", `{"catraca-account":42}`, ""},
		{"tag of the config missing", "workspace_id", `{"catraca-account":"acct_9"}`, ""},
		{"tags as a list", "", `[{"name":"catraca-account","value":"acct_9"}]`, ""},
		{"tags as a string", "", `"catraca-account=acct_9"`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			var out outcomes
			h := newTestResend(t, ResendConfig{Decider: dec, AccountTag: tt.tag, OnOutcome: out.add})
			tags := ""
			if tt.tags != "" {
				tags = `,"tags":` + tt.tags
			}
			body := `{"type":"email.delivered","data":{"email_id":"e","to":["a@example.org"]` + tags + `}}`
			if code := postResend(t, h, body); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			evs := dec.got()
			if tt.want == "" {
				if len(evs) != 0 || !out.has(OutcomeNoAccount) {
					t.Errorf("events %+v, outcomes %v; want none and no_account", evs, out.list)
				}
				return
			}
			if len(evs) != 1 || evs[0].AccountID != tt.want {
				t.Errorf("events %+v, want account %q", evs, tt.want)
			}
		})
	}
}

// TestResendTime checks the event time: the payload's created_at, when the
// event happened, else the email's, else none, for the engine to stamp.
func TestResendTime(t *testing.T) {
	for _, tt := range []struct {
		name, event, email string
		want               time.Time
	}{
		{"event time", `"created_at":"2026-11-12T10:00:05Z",`, `"created_at":"2026-11-12T10:00:00Z",`, time.Date(2026, 11, 12, 10, 0, 5, 0, time.UTC)},
		{"email time", ``, `"created_at":"2026-11-12T10:00:00Z",`, time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)},
		{"unparseable", `"created_at":"yesterday",`, ``, time.Time{}},
	} {
		dec := &recorder{}
		h := newTestResend(t, ResendConfig{Decider: dec})
		body := `{"type":"email.delivered",` + tt.event + `"data":{` + tt.email + `"to":["a@example.org"],"tags":{"catraca-account":"a"}}}`
		if code := postResend(t, h, body); code != http.StatusOK {
			t.Fatalf("%s: status %d", tt.name, code)
		}
		if evs := dec.got(); len(evs) != 1 || !evs[0].Time.Equal(tt.want) {
			t.Errorf("%s: events %+v, want time %v", tt.name, evs, tt.want)
		}
	}
}

func TestResendErrors(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		var out outcomes
		dec := &recorder{}
		h := newTestResend(t, ResendConfig{Decider: dec, OnOutcome: out.add})
		for _, body := range []string{`not json`, `{}`, `{"type":""}`, `[]`, `{"type":"email.bounced","data":"x"}`, `{"type":"email.bounced"}`, `{"type":"email.bounced","data":{"to":"a@example.org"}}`} {
			if code := postResend(t, h, body); code != http.StatusBadRequest {
				t.Errorf("%s: status %d, want 400", body, code)
			}
		}
		if len(dec.got()) != 0 || !out.has(OutcomeMalformed) {
			t.Errorf("decided %d events, outcomes %v", len(dec.got()), out.list)
		}
	})
	t.Run("not POST", func(t *testing.T) {
		h := newTestResend(t, ResendConfig{Decider: &recorder{}})
		rec := post(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Method = http.MethodGet
			h.ServeHTTP(w, r)
		}), []byte(resendBounce), nil)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("status %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
		}
	})
	t.Run("too large", func(t *testing.T) {
		var out outcomes
		h := newTestResend(t, ResendConfig{Decider: &recorder{}, MaxBodyBytes: 64, OnOutcome: out.add})
		if code := postResend(t, h, resendBounce); code != http.StatusRequestEntityTooLarge || !out.has(OutcomeTooLarge) {
			t.Errorf("status %d, outcomes %v", code, out.list)
		}
	})
	t.Run("decide fails: Resend retries", func(t *testing.T) {
		h := newTestResend(t, ResendConfig{Decider: &recorder{fail: func(event.Event) bool { return true }}})
		b := []byte(resendBounce)
		wantRetry(t, post(t, h, b, resendHeaders(t, resendSecret, resendID, time.Now(), b)))
	})
	t.Run("store failed for one recipient: Resend retries, with the same event ids", func(t *testing.T) {
		failing := true
		dec := &recorder{uncounted: func(ev event.Event) bool { return failing && ev.Feedback.Recipient == "b@example.org" }}
		var out outcomes
		h := newTestResend(t, ResendConfig{Decider: dec, OnOutcome: out.add})
		b := []byte(resendBounce)
		wantRetry(t, post(t, h, b, resendHeaders(t, resendSecret, resendID, time.Now(), b)))
		if !out.has(OutcomeUncounted) || !out.has(OutcomeDecided) {
			t.Errorf("outcomes %v, want decided and uncounted", out.list)
		}
		// The retry is signed anew, at a later time, with the same svix-id.
		failing = false
		if rec := post(t, h, b, resendHeaders(t, resendSecret, resendID, time.Now().Add(5*time.Second), b)); rec.Code != http.StatusOK {
			t.Fatalf("retry: status %d, want 200", rec.Code)
		}
		var ids []string
		for _, ev := range dec.got() {
			ids = append(ids, ev.ID)
		}
		// The engine counts each id once, so a's second event does not
		// count again.
		want := []string{"resend:" + resendID + ":0", "resend:" + resendID + ":0", "resend:" + resendID + ":1"}
		if !slices.Equal(ids, want) {
			t.Errorf("event ids = %q, want %q", ids, want)
		}
	})
	t.Run("event refused: no retry that would be refused again", func(t *testing.T) {
		var out outcomes
		h := newTestResend(t, ResendConfig{Decider: &recorder{refuse: func(event.Event) bool { return true }}, OnOutcome: out.add})
		if code := postResend(t, h, resendBounce); code != http.StatusOK {
			t.Errorf("status %d, want 200", code)
		}
		if !out.has(OutcomeMalformed) || out.has(OutcomeDecideFailed) {
			t.Errorf("outcomes %v, want malformed and no decide_failed", out.list)
		}
	})
	t.Run("config", func(t *testing.T) {
		for name, cfg := range map[string]ResendConfig{
			"no decider":                {Secret: resendSecret},
			"no secret":                 {Decider: &recorder{}},
			"secret not base64":         {Decider: &recorder{}, Secret: "whsec_garbled!secret"},
			"secret only the prefix":    {Decider: &recorder{}, Secret: "whsec_"},
			"an empty previous secret":  {Decider: &recorder{}, Secret: resendSecret, PreviousSecrets: []string{""}},
			"a previous secret garbled": {Decider: &recorder{}, Secret: resendSecret, PreviousSecrets: []string{"whsec_garbled!secret"}},
		} {
			_, err := NewResendHandler(cfg)
			if err == nil {
				t.Errorf("%s: want an error", name)
			} else if strings.Contains(err.Error(), "garbled") || strings.Contains(err.Error(), resendSecret[6:]) {
				t.Errorf("%s: the error shows the secret: %v", name, err)
			}
		}
	})
}

func TestSvixSignatures(t *testing.T) {
	for _, tt := range []struct {
		header string
		want   []string
	}{
		{"", nil},
		{"v1,AAAA", []string{"AAAA"}},
		{"v1,AAAA v1,AQID", []string{"AAAA", "AQID"}},
		{"v1,AAAA  v1,AQID ", []string{"AAAA", "AQID"}},
		{"v1a,AAAA v2,AAAA v1,AQID", []string{"AQID"}},
		{"v1,A v1,!!!! v1,", nil},
		{"v1=AAAA AAAA ,AAAA", nil},
	} {
		var got []string
		for _, sig := range svixSignatures(tt.header) {
			got = append(got, base64.StdEncoding.EncodeToString(sig))
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("svixSignatures(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}
