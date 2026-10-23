package feedback

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// classicBounce is an identity notification shaped like the examples in
// https://docs.aws.amazon.com/ses/latest/dg/notification-contents.html,
// with original headers included and the account in X-Catraca-Account.
const classicBounce = `{
  "notificationType": "Bounce",
  "bounce": {
    "bounceType": "Permanent",
    "bounceSubType": "General",
    "bouncedRecipients": [
      {"status": "5.0.0", "action": "failed", "diagnosticCode": "smtp; 550 user unknown", "emailAddress": "Recipient1@Example.com"},
      {"status": "5.1.1", "action": "failed", "emailAddress": "recipient2@example.com"}
    ],
    "reportingMTA": "example.com",
    "timestamp": "2012-05-25T14:59:38.605Z",
    "feedbackId": "000001378603176d-5a4b5ad9-6f30-4198-a8c3-b1eb0c270a1d-000000"
  },
  "mail": {
    "timestamp": "2018-10-08T14:05:45 +0000",
    "messageId": "000001378603177f-7a5433e7-8edb-42ae-af10-f0181f34d6ee-000000",
    "source": "bounces@mail.example.com",
    "sendingAccountId": "123456789012",
    "destination": ["recipient1@example.com", "recipient2@example.com"],
    "headersTruncated": false,
    "headers": [
      {"name": "From", "value": "\"Sender Name\" <sender@example.com>"},
      {"name": "X-Catraca-Account", "value": " acct_classic "}
    ],
    "commonHeaders": {"from": ["Sender Name <Sender@Example.com>"], "subject": "Hello"}
  }
}`

// publishedBounce is an event publishing record shaped like
// https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-examples.html
const publishedBounce = `{
  "eventType": "Bounce",
  "bounce": {
    "bounceType": "Transient",
    "bounceSubType": "MailboxFull",
    "bouncedRecipients": [{"emailAddress": "recipient@example.com", "status": "4.2.2"}],
    "timestamp": "2017-08-05T00:41:02.669Z",
    "feedbackId": "01000157c44f053b-61b59c11-9236-11e6-8f96-7be8aexample-000000"
  },
  "mail": {
    "timestamp": "2017-08-05T00:40:02.012Z",
    "source": "Sender Name <sender@example.com>",
    "messageId": "EXAMPLE7c191be45-e9aedb9a-02f9-4d12-a87d-dd0099a07f8a-000000",
    "destination": ["recipient@example.com"],
    "tags": {
      "ses:configuration-set": ["ConfigSet"],
      "catraca-account": ["acct_tagged"]
    }
  }
}`

func TestSESClassicBounce(t *testing.T) {
	dec := &recorder{}
	h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "x-catraca-account"})
	rec := postJSON(t, h, notification(t, classicBounce))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	evs := dec.got()
	if len(evs) != 2 {
		t.Fatalf("got %d events, want one per bounced recipient", len(evs))
	}
	wantTime := time.Date(2012, 5, 25, 14, 59, 38, 605e6, time.UTC)
	for i, wantRcpt := range []string{"Recipient1@Example.com", "recipient2@example.com"} {
		ev := evs[i]
		if err := ev.Validate(); err != nil {
			t.Fatalf("event %d invalid: %v", i, err)
		}
		if ev.Type != event.Feedback || ev.AccountID != "acct_classic" {
			t.Errorf("event %d: type %q account %q", i, ev.Type, ev.AccountID)
		}
		if ev.From != "Sender@Example.com" {
			t.Errorf("event %d: from %q, want the From header address", i, ev.From)
		}
		if !ev.Time.Equal(wantTime) {
			t.Errorf("event %d: time %v, want the bounce time %v", i, ev.Time, wantTime)
		}
		fb := ev.Feedback
		if fb.Kind != event.Bounce || fb.BounceType != "permanent" || fb.Recipient != wantRcpt {
			t.Errorf("event %d: feedback %+v", i, *fb)
		}
		if fb.MessageID != "000001378603177f-7a5433e7-8edb-42ae-af10-f0181f34d6ee-000000" {
			t.Errorf("event %d: message id %q", i, fb.MessageID)
		}
		if ev.Attributes["provider"] != "ses" || ev.Attributes["bounce_subtype"] != "General" {
			t.Errorf("event %d: attributes %v", i, ev.Attributes)
		}
	}
	if evs[0].Attributes["bounce_status"] != "5.0.0" || evs[1].Attributes["bounce_status"] != "5.1.1" {
		t.Errorf("bounce statuses %q %q", evs[0].Attributes["bounce_status"], evs[1].Attributes["bounce_status"])
	}
}

func TestSESEventPublishingBounce(t *testing.T) {
	dec := &recorder{}
	h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountTag: "catraca-account"})
	if rec := postJSON(t, h, notification(t, publishedBounce)); rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	evs := dec.got()
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.AccountID != "acct_tagged" || ev.Feedback.BounceType != "transient" || ev.Feedback.Recipient != "recipient@example.com" {
		t.Errorf("event %+v feedback %+v", ev, *ev.Feedback)
	}
	if ev.From != "sender@example.com" {
		t.Errorf("from %q, want the address of mail.source", ev.From)
	}
	if ev.Attributes["bounce_status"] != "4.2.2" || ev.Attributes["ses_bounce_type"] != "Transient" {
		t.Errorf("attributes %v", ev.Attributes)
	}
}

func TestSESUndeterminedBounceIsTransient(t *testing.T) {
	dec := &recorder{}
	h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch})
	msg := `{"eventType":"Bounce","bounce":{"bounceType":"Undetermined","bounceSubType":"Undetermined",
		"bouncedRecipients":[{"emailAddress":"a@example.org"}],"timestamp":"2026-10-15T12:00:00Z"},
		"mail":{"messageId":"m","source":"s@example.com","tags":{"catraca-account":["acct_1"]}}}`
	if rec := postJSON(t, h, notification(t, msg)); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	evs := dec.got()
	if len(evs) != 1 || evs[0].Feedback.BounceType != "transient" || evs[0].Attributes["ses_bounce_type"] != "Undetermined" {
		t.Fatalf("events %+v", evs)
	}
}

func TestSESComplaint(t *testing.T) {
	complaint := func(feedbackType string) string {
		return `{"notificationType":"Complaint","complaint":{"userAgent":"ExampleCorp Feedback Loop (V0.01)",
		"complainedRecipients":[{"emailAddress":"recipient1@example.com"},{"emailAddress":"recipient2@example.com"}],
		"complaintFeedbackType":"` + feedbackType + `","arrivalDate":"2009-12-03T04:24:21.000-05:00",
		"timestamp":"2012-05-25T14:59:38.623Z","feedbackId":"f"},
		"mail":{"timestamp":"2012-05-25T14:58:38.623Z","messageId":"m","source":"sender@example.com",
		"headers":[{"name":"X-Catraca-Account","value":"acct_1"}]}}`
	}

	dec := &recorder{}
	var out outcomes
	h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account", OnOutcome: out.add})
	if rec := postJSON(t, h, notification(t, complaint("abuse"))); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	evs := dec.got()
	if len(evs) != 2 {
		t.Fatalf("got %d events, want one per complained recipient", len(evs))
	}
	for _, ev := range evs {
		if ev.Feedback.Kind != event.Complaint || ev.Feedback.BounceType != "" || ev.Attributes["complaint_type"] != "abuse" {
			t.Errorf("event %+v feedback %+v", ev, *ev.Feedback)
		}
	}

	// A not-spam report retracts a complaint and must not count as one.
	if rec := postJSON(t, h, notification(t, complaint("not-spam"))); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if len(dec.got()) != 2 || !out.has(OutcomeIgnored) {
		t.Error("not-spam report was decided")
	}
}

func TestSESDelivery(t *testing.T) {
	dec := &recorder{}
	h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch})
	msg := `{"eventType":"Delivery","mail":{"timestamp":"2016-10-19T23:20:52.240Z","source":"sender@example.com",
	"messageId":"m","tags":{"catraca-account":["acct_1"]}},"delivery":{"timestamp":"2016-10-19T23:21:04.133Z",
	"processingTimeMillis":11893,"recipients":["a@example.com","b@example.com","c@example.com"],"smtpResponse":"250 2.6.0"}}`
	if rec := postJSON(t, h, notification(t, msg)); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	evs := dec.got()
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3", len(evs))
	}
	if evs[2].Feedback.Kind != event.Delivery || evs[2].Feedback.Recipient != "c@example.com" {
		t.Errorf("feedback %+v", *evs[2].Feedback)
	}
}

func TestSESAccountSources(t *testing.T) {
	msg := func(mail string) string {
		return `{"eventType":"Delivery","mail":` + mail + `,"delivery":{"recipients":["a@example.com"]}}`
	}
	tests := []struct {
		name   string
		tag    string
		header string
		mail   string
		want   string
	}{
		{"tag", "acct", "", `{"tags":{"acct":["t1"]}}`, "t1"},
		{"tag wins over header", "acct", "X-Acct", `{"tags":{"acct":["t1"]},"headers":[{"name":"X-Acct","value":"h1"}]}`, "t1"},
		{"header fallback", "acct", "X-Acct", `{"headers":[{"name":"x-acct","value":"h1"}]}`, "h1"},
		{"blank tag falls back", "acct", "X-Acct", `{"tags":{"acct":[" "]},"headers":[{"name":"X-Acct","value":"h1"}]}`, "h1"},
		{"missing", "acct", "X-Acct", `{"tags":{"other":["x"]}}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			var out outcomes
			h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountTag: tt.tag, AccountHeader: tt.header, OnOutcome: out.add})
			rec := postJSON(t, h, notification(t, msg(tt.mail)))
			// Even without an account the answer is 200: a retry would not
			// find one either.
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			evs := dec.got()
			if tt.want == "" {
				if len(evs) != 0 || !out.has(OutcomeNoAccount) {
					t.Errorf("events %v, outcomes %v", evs, out.list)
				}
				return
			}
			if len(evs) != 1 || evs[0].AccountID != tt.want {
				t.Fatalf("events %+v, want account %q", evs, tt.want)
			}
		})
	}
}

func TestSESIgnoresOtherNotifications(t *testing.T) {
	for _, msg := range []string{
		`{"eventType":"Open","mail":{"tags":{"catraca-account":["acct_1"]}},"open":{"ipAddress":"192.0.2.1"}}`,
		`{"eventType":"Send","mail":{"tags":{"catraca-account":["acct_1"]}},"send":{}}`,
		`{"eventType":"DeliveryDelay","mail":{"tags":{"catraca-account":["acct_1"]}},"deliveryDelay":{}}`,
		`{"notificationType":"AmazonSnsSubscriptionSucceeded","message":"You have successfully subscribed"}`,
		`{"eventType":"Bounce","mail":{"tags":{"catraca-account":["acct_1"]}}}`,
		"Successfully validated SNS topic for Amazon SES event publishing.",
	} {
		dec := &recorder{}
		var out outcomes
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, OnOutcome: out.add})
		if rec := postJSON(t, h, notification(t, msg)); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", msg, rec.Code)
		}
		if len(dec.got()) != 0 || !out.has(OutcomeIgnored) {
			t.Errorf("%s: decided %d events, outcomes %v", msg, len(dec.got()), out.list)
		}
	}
}

// wantRetry checks that rec asks the provider to send the request again.
func wantRetry(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("status %d, Retry-After %q; want 503 and 10", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestSESDecideFailures(t *testing.T) {
	t.Run("all fail: SNS retries", func(t *testing.T) {
		dec := &recorder{fail: func(event.Event) bool { return true }}
		var out outcomes
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account", OnOutcome: out.add})
		wantRetry(t, postJSON(t, h, notification(t, classicBounce)))
		if !out.has(OutcomeDecideFailed) {
			t.Error("decide_failed not reported")
		}
	})
	t.Run("some fail: SNS retries, with the same event ids", func(t *testing.T) {
		failing := true
		dec := &recorder{fail: func(ev event.Event) bool { return failing && ev.Feedback.Recipient == "recipient2@example.com" }}
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account"})
		msg := notification(t, classicBounce)
		wantRetry(t, postJSON(t, h, msg))
		failing = false
		if rec := postJSON(t, h, msg); rec.Code != http.StatusOK {
			t.Fatalf("retry: status %d, want 200", rec.Code)
		}
		// The engine counts each id once, so recipient1's second event
		// does not count again.
		var ids []string
		for _, ev := range dec.got() {
			ids = append(ids, strings.ToLower(ev.Feedback.Recipient)+" "+ev.ID)
		}
		want := []string{
			"recipient1@example.com ses:22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324:0",
			"recipient1@example.com ses:22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324:0",
			"recipient2@example.com ses:22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324:1",
		}
		if !slices.Equal(ids, want) {
			t.Errorf("events decided = %q, want %q", ids, want)
		}
	})
	t.Run("store failed: SNS retries", func(t *testing.T) {
		dec := &recorder{uncounted: func(ev event.Event) bool { return ev.Feedback.Recipient == "recipient2@example.com" }}
		var out outcomes
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account", OnOutcome: out.add})
		wantRetry(t, postJSON(t, h, notification(t, classicBounce)))
		if !out.has(OutcomeUncounted) || !out.has(OutcomeDecided) {
			t.Errorf("outcomes %v, want uncounted and decided", out.list)
		}
	})
	t.Run("store late: no retry, its writes still apply", func(t *testing.T) {
		dec := &recorder{late: func(event.Event) bool { return true }}
		var out outcomes
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account", OnOutcome: out.add})
		if rec := postJSON(t, h, notification(t, classicBounce)); rec.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", rec.Code)
		}
		if out.has(OutcomeUncounted) {
			t.Errorf("outcomes %v: a late store is not a failed one", out.list)
		}
	})
	t.Run("all refused: no retry that would be refused again", func(t *testing.T) {
		dec := &recorder{refuse: func(event.Event) bool { return true }}
		var out outcomes
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account", OnOutcome: out.add})
		rec := postJSON(t, h, notification(t, classicBounce))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", rec.Code)
		}
		if !out.has(OutcomeMalformed) || out.has(OutcomeDecideFailed) {
			t.Errorf("outcomes %v, want malformed and no decide_failed", out.list)
		}
	})
	t.Run("one refused, one failed: SNS retries", func(t *testing.T) {
		dec := &recorder{
			refuse: func(ev event.Event) bool { return strings.EqualFold(ev.Feedback.Recipient, "recipient1@example.com") },
			fail:   func(ev event.Event) bool { return ev.Feedback.Recipient == "recipient2@example.com" },
		}
		h := newTestSES(t, SESConfig{Decider: dec, FetchCert: (&fetcher{}).fetch, AccountHeader: "X-Catraca-Account"})
		wantRetry(t, postJSON(t, h, notification(t, classicBounce)))
	})
}

func TestParseTime(t *testing.T) {
	tests := map[string]time.Time{
		"2017-08-05T00:41:02.669Z":      time.Date(2017, 8, 5, 0, 41, 2, 669e6, time.UTC),
		"2018-10-08T14:05:45 +0000":     time.Date(2018, 10, 8, 14, 5, 45, 0, time.UTC),
		"2009-12-03T04:24:21.000-05:00": time.Date(2009, 12, 3, 9, 24, 21, 0, time.UTC),
		"":                              {},
		"yesterday":                     {},
	}
	for in, want := range tests {
		if got := parseTime(in); !got.Equal(want) {
			t.Errorf("parseTime(%q) = %v, want %v", in, got, want)
		}
	}
}
