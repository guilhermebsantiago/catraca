package feedback

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/signature"
)

// The feedback fuzz targets decide with a recorder that refuses what the
// engine would refuse, so the refused path runs too, and check the events
// handed to it: one shape for every provider, an id per event when the
// provider names the notification, and nothing decided for a request whose
// signature does not hold.

// validating is a Decider that refuses invalid events, as the engine does.
func validating() *recorder {
	return &recorder{refuse: func(ev event.Event) bool { return ev.Validate() != nil }}
}

// checkEvents checks the events a handler decided for one notification:
// feedback events with their own Feedback and Attributes, the provider in
// the attributes, and the ids id gives by position.
func checkEvents(t *testing.T, evs []event.Event, provider string, id func(i int) string) {
	t.Helper()
	feedbacks := map[*event.FeedbackInfo]bool{}
	attributes := map[uintptr]bool{}
	for i, ev := range evs {
		fb := ev.Feedback
		if ev.Type != event.Feedback || fb == nil {
			t.Fatalf("event %d is not feedback: %+v", i, ev)
		}
		switch {
		case fb.Kind == event.Bounce && (fb.BounceType == bouncePermanent || fb.BounceType == bounceTransient):
		case (fb.Kind == event.Complaint || fb.Kind == event.Delivery) && fb.BounceType == "":
		default:
			t.Errorf("event %d has kind %q and bounce type %q", i, fb.Kind, fb.BounceType)
		}
		if ev.AccountID == "" || ev.AccountID != strings.TrimSpace(ev.AccountID) {
			t.Errorf("event %d has account %q", i, ev.AccountID)
		}
		if ev.Attributes["provider"] != provider {
			t.Errorf("event %d has attributes %v, want provider %s", i, ev.Attributes, provider)
		}
		if want := id(i); ev.ID != want {
			t.Errorf("event %d has id %q, want %q", i, ev.ID, want)
		}
		if feedbacks[fb] {
			t.Errorf("event %d shares its Feedback with another event", i)
		}
		feedbacks[fb] = true
		if p := reflect.ValueOf(ev.Attributes).Pointer(); p != 0 {
			if attributes[p] {
				t.Errorf("event %d shares its Attributes with another event", i)
			}
			attributes[p] = true
		}
	}
}

// fuzzSNS is what the SES fuzz targets share: a handler that fetches the
// test certificate and confirms subscriptions without a network, and the
// canonical strings of every message signed so far, so a target can tell
// an authentic message from one whose signature should have failed.
type fuzzSNS struct {
	h       *sesHandler
	dec     *recorder
	fetched func() int32
	mu      sync.Mutex
	signed  map[string]bool
	visited []string
}

func newFuzzSNS(tb testing.TB) *fuzzSNS {
	tb.Helper()
	s := &fuzzSNS{dec: validating(), signed: map[string]bool{}}
	f := &fetcher{}
	s.fetched = f.calls.Load
	confirm := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		s.mu.Lock()
		s.visited = append(s.visited, r.URL.String())
		s.mu.Unlock()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	h, err := NewSESHandler(SESConfig{
		Decider: s.dec, TopicARNs: []string{testTopic}, AccountTag: "catraca-account",
		AccountHeader: "X-Catraca-Account", FetchCert: f.fetch, HTTPClient: confirm,
	})
	if err != nil {
		tb.Fatal(err)
	}
	s.h = h.(*sesHandler)
	return s
}

// sign signs m and remembers what it signed.
func (s *fuzzSNS) sign(tb testing.TB, m *snsMessage, version string) {
	testSigner().sign(tb, m, version)
	canonical, err := m.stringToSign()
	if err != nil {
		tb.Fatal(err)
	}
	s.mu.Lock()
	s.signed[canonical] = true
	s.mu.Unlock()
}

// authentic reports whether body decodes to a message that was signed here.
func (s *fuzzSNS) authentic(body []byte) bool {
	var m snsMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	canonical, err := m.stringToSign()
	s.mu.Lock()
	defer s.mu.Unlock()
	return err == nil && s.signed[canonical]
}

// positional returns the ids eventIDs gives the events of a notification
// whose provider id is base: none without one.
func positional(base string) func(i int) string {
	return func(i int) string {
		if base == "" {
			return ""
		}
		return fmt.Sprintf("%s:%d", base, i)
	}
}

// FuzzSESNotification signs an SNS notification around any message, posts
// it, and posts it again with one field changed. The authentic one is
// answered and its events have the shape of feedback; one changed in what
// is signed is refused, and decides nothing.
func FuzzSESNotification(f *testing.F) {
	for _, msg := range []string{
		classicBounce, publishedBounce, deliveryJSON,
		`{"eventType":"Bounce","bounce":{"bounceType":"Undetermined","bounceSubType":"Undetermined",
		"bouncedRecipients":[{"emailAddress":"a@example.org"}],"timestamp":"2026-10-15T12:00:00Z"},
		"mail":{"messageId":"m","source":"s@example.com","tags":{"catraca-account":["acct_1"]}}}`,
		`{"notificationType":"Complaint","complaint":{"complainedRecipients":[{"emailAddress":"r1@example.com"},{"emailAddress":"r2@example.com"}],
		"complaintFeedbackType":"abuse","timestamp":"2012-05-25T14:59:38.623Z"},
		"mail":{"messageId":"m","source":"sender@example.com","headers":[{"name":"X-Catraca-Account","value":"acct_1"}]}}`,
		`{"notificationType":"Complaint","complaint":{"complaintFeedbackType":"not-spam"},"mail":{"tags":{"catraca-account":["a"]}}}`,
		`{"eventType":"Open","mail":{"tags":{"catraca-account":["a"]}}}`,
		`{"eventType":"Bounce","bounce":{},"mail":{"tags":{"catraca-account":["  ", "\u0000"]}}}`,
		"Successfully validated SNS topic for Amazon SES event publishing.",
	} {
		f.Add(msg, "22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324", "", byte(0), "")
		f.Add(msg, "", "Amazon SES Email Event Notification", byte(1|1<<2), `{"eventType":"Delivery"}`)
	}
	f.Add(deliveryJSON, "id", "s", byte(2|6<<2), "c2ln")
	f.Add(deliveryJSON, "id", "", byte(7<<2), "1")
	s := newFuzzSNS(f)
	f.Fuzz(func(t *testing.T, message, messageID, subject string, flags byte, change string) {
		// JSON carries only valid UTF-8: anything else would reach the
		// handler changed, and fail its signature.
		message, messageID = strings.ToValidUTF8(message, "�"), strings.ToValidUTF8(messageID, "�")
		subject, change = strings.ToValidUTF8(subject, "�"), strings.ToValidUTF8(change, "�")
		m := &snsMessage{Type: snsNotification, MessageID: messageID, TopicArn: testTopic, Message: message, Timestamp: "2026-10-15T12:00:00.000Z"}
		if flags&1 != 0 {
			m.Subject = &subject
		}
		version := "2"
		if flags&2 != 0 {
			version = "1"
		}
		s.sign(t, m, version)
		before := len(s.dec.got())
		rec := postJSON(t, s.h, m)
		evs := s.dec.got()[before:]
		if rec.Code != http.StatusOK {
			t.Fatalf("an authentic notification got %d: %s", rec.Code, rec.Body)
		}
		base := ""
		if messageID != "" {
			base = "ses:" + messageID
		}
		checkEvents(t, evs, "ses", positional(base))

		signed, _ := m.stringToSign()
		sig := m.Signature
		switch flags >> 2 % 8 {
		case 0:
			return
		case 1:
			m.Message = change
		case 2:
			m.MessageID = change
		case 3:
			m.Subject = &change
		case 4:
			m.Timestamp = change
		case 5:
			m.TopicArn = change
		case 6:
			m.Signature = change
		case 7:
			m.SignatureVersion = change
		}
		canonical, err := m.stringToSign()
		decoded, _ := base64.StdEncoding.DecodeString(m.Signature)
		original, _ := base64.StdEncoding.DecodeString(sig)
		if err == nil && canonical == signed && bytes.Equal(decoded, original) && m.SignatureVersion == version {
			return // the change left what is signed as it was
		}
		before = len(s.dec.got())
		rec = postJSON(t, s.h, m)
		if rec.Code == http.StatusOK || len(s.dec.got()) != before {
			t.Fatalf("a changed notification got %d and decided %d events", rec.Code, len(s.dec.got())-before)
		}
	})
}

// FuzzSESEnvelope posts any body to the SES handler. Nothing is fetched for
// a topic that is not allowed, and nothing is decided, and no subscription
// confirmed, unless the body is a message signed by the test certificate.
func FuzzSESEnvelope(f *testing.F) {
	s := newFuzzSNS(f)
	confirmation := &snsMessage{
		Type: snsSubscriptionConfirmation, MessageID: "165545c9-2a5c-472c-8df2-7ff2be2b3b1b", TopicArn: testTopic,
		Message:      "You have chosen to subscribe to the topic.",
		SubscribeURL: "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=" + testTopic + "&Token=2336412f37",
		Token:        "2336412f37", Timestamp: "2026-10-15T12:00:00.000Z",
	}
	unsubscribe := *confirmation
	unsubscribe.Type = snsUnsubscribeConfirmation
	messages := []*snsMessage{confirmation, &unsubscribe}
	for _, msg := range []string{classicBounce, publishedBounce, deliveryJSON} {
		messages = append(messages, notification(f, msg))
	}
	for i, m := range messages {
		s.sign(f, m, []string{"1", "2"}[i%2])
		body, err := json.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(body)
	}
	f.Add([]byte(`{"Type":"Notification","TopicArn":"arn:aws:sns:us-east-1:123456789012:other","SigningCertURL":"https://example.com/x.pem"}`))
	f.Add([]byte(`{"Type":"Notification","type":"SubscriptionConfirmation","TopicArn":"` + testTopic + `","SigningCertURL":"https://sns.us-east-1.amazonaws.com.evil.example/x.pem"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var m snsMessage
		decodes := json.Unmarshal(body, &m) == nil
		fetchedBefore, decidedBefore := s.fetched(), len(s.dec.got())
		s.mu.Lock()
		visitedBefore := len(s.visited)
		s.mu.Unlock()

		rec := post(t, s.h, body, nil)

		authentic := s.authentic(body)
		if !authentic && (rec.Code < 400 || rec.Code >= 500) {
			t.Errorf("a body not signed here got %d: %s", rec.Code, rec.Body)
		}
		if (!decodes || m.TopicArn != testTopic) && s.fetched() != fetchedBefore {
			t.Errorf("a certificate was fetched for topic %q", m.TopicArn)
		}
		if decided := len(s.dec.got()) - decidedBefore; decided > 0 && !authentic {
			t.Errorf("%d events decided from a body not signed here", decided)
		}
		s.mu.Lock()
		visited := slices.Clone(s.visited[visitedBefore:])
		s.mu.Unlock()
		for _, u := range visited {
			if !authentic || !validSNSURL(u, false) {
				t.Errorf("visited %s for a body that is authentic: %v", u, authentic)
			}
		}
	})
}

// FuzzUseSend signs any body as useSend does and posts it, then posts
// another body with the same signature. The signed body is never refused
// for its signature and its events have the shape of feedback; the other
// is refused and decides nothing.
func FuzzUseSend(f *testing.F) {
	for _, seed := range []string{
		useSendBounce,
		`{"id":"call_2","type":"email.complained","createdAt":"2026-10-15T10:30:05Z","teamId":"7",
		  "data":{"id":"e","from":"a@b.example","to":["x@y.example"],"metadata":{"feedbackType":"abuse","account":"acct_9"}}}`,
		`{"id":"call_3","type":"email.complained","teamId":7,"data":{"to":["x@y.example"],"metadata":{"feedbackType":"Not-Spam"}}}`,
		`{"id":"call_4","type":"email.delivered","teamId":1.5e3,"data":{"to":[],"occurredAt":"2026-10-15T10:30:00Z"}}`,
		`{"type":"email.bounced","teamId":0,"data":{"to":["a@b"]}}`,
		`{"type":"email.opened","teamId":1,"data":null}`,
		`{"type":"email.bounced","teamId":"abc","data":{}}`,
		`{"type":"email.bounced","teamId":1,"data":{"to":["a@b"],"metadata":{"account":1e300}}}`,
	} {
		f.Add([]byte(seed), []byte(seed+" "))
	}
	dec := validating()
	h, err := NewUseSendHandler(UseSendConfig{Decider: dec, Secret: useSendSecret})
	if err != nil {
		f.Fatal(err)
	}
	byMetadata, err := NewUseSendHandler(UseSendConfig{Decider: dec, Secret: useSendSecret, AccountMetadataKey: "account"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body, other []byte) {
		header := useSendHeaders(useSendSecret, time.Now(), body)
		for _, h := range []http.Handler{h, byMetadata} {
			before := len(dec.got())
			rec := post(t, h, body, header)
			switch rec.Code {
			case http.StatusOK, http.StatusBadRequest:
			default:
				t.Fatalf("a signed body got %d: %s", rec.Code, rec.Body)
			}
			var hook struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(body, &hook)
			base := ""
			if hook.ID != "" {
				base = "usesend:" + hook.ID
			}
			checkEvents(t, dec.got()[before:], "usesend", positional(base))
		}
		if !bytes.Equal(other, body) {
			before := len(dec.got())
			if rec := post(t, h, other, header); rec.Code != http.StatusUnauthorized || len(dec.got()) != before {
				t.Fatalf("a body with another's signature got %d", rec.Code)
			}
		}
	})
}

// FuzzGeneric signs any body with signature.Sign and posts it to the
// generic handler, then posts another body with the same signature. A
// signed body is decided once or refused with 400; the other is refused
// with 401.
func FuzzGeneric(f *testing.F) {
	for _, seed := range []string{
		`{"id":"fb_1","account_id":"acct_123","time":"2026-10-15T12:00:00Z","from":"news@example.com",
		  "feedback":{"kind":"bounce","bounce_type":"Permanent","recipient":"someone@example.org","message_id":"msg_1"},
		  "attributes":{"provider":"postmark"}}`,
		`{"type":"feedback","account_id":" acct ","feedback":{"kind":"complaint","bounce_type":"permanent"}}`,
		`{"account_id":"a","feedback":{"kind":"delivery"},"to":["dropped@example.org"],"subject":"dropped"}`,
		`{"type":"send","account_id":"a","feedback":{"kind":"bounce","bounce_type":"transient"}}`,
		`{"account_id":"a","feedback":{"kind":"bounce","bounce_type":"soft"}}`,
		`{"account_id":"a\u0000","feedback":{"kind":"bounce","bounce_type":"TRANSIENT"}}`,
		`{"account_id":"  ","feedback":{"kind":"delivery"}}`,
		`{"account_id":"a"}`,
		`{"account_id":"a","time":"1999-01-01T00:00:00Z","feedback":{"kind":"delivery"}}`,
		`not json`,
	} {
		f.Add([]byte(seed), []byte(strings.Replace(seed, "a", "b", 1)))
	}
	dec := validating()
	h, err := NewGenericHandler(GenericConfig{Decider: dec, Secret: genericSecret})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body, other []byte) {
		header := http.Header{signature.Header: {signature.Sign(genericSecret, time.Now(), body)}}
		before := len(dec.got())
		rec := post(t, h, body, header)
		evs := dec.got()[before:]
		switch rec.Code {
		case http.StatusAccepted:
			if len(evs) != 1 {
				t.Fatalf("202 with %d events decided", len(evs))
			}
			var in event.Event
			if err := json.Unmarshal(body, &in); err != nil {
				t.Fatalf("202 for a body that does not decode: %v", err)
			}
			// The platform's own id, which its retries keep.
			checkEvents(t, evs, in.Attributes["provider"], func(int) string { return in.ID })
		case http.StatusBadRequest:
			if len(evs) != 0 {
				t.Fatalf("400 with %d events decided", len(evs))
			}
		default:
			t.Fatalf("a signed body got %d: %s", rec.Code, rec.Body)
		}
		if !bytes.Equal(other, body) {
			before := len(dec.got())
			if rec := post(t, h, other, header); rec.Code != http.StatusUnauthorized || len(dec.got()) != before {
				t.Fatalf("a body with another's signature got %d", rec.Code)
			}
		}
	})
}
