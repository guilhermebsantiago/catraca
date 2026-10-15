package feedback

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

// The expected strings are the examples in
// https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message-verify-message-signature.html
// with the trailing newline the page says to append.
func TestStringToSign(t *testing.T) {
	tests := []struct {
		name string
		msg  snsMessage
		want string
	}{
		{
			name: "notification with subject",
			msg: snsMessage{
				Type:      snsNotification,
				Message:   "My Test Message",
				MessageID: "4d4dc071-ddbf-465d-bba8-08f81c89da64",
				Subject:   ptr("My subject"),
				Timestamp: "2019-01-31T04:37:04.321Z",
				TopicArn:  "arn:aws:sns:us-east-2:123456789012:s4-MySNSTopic-1G1WEFCOXTC0P",
				// Not signed for notifications.
				Token:        "ignored",
				SubscribeURL: "https://ignored",
			},
			want: "Message\nMy Test Message\nMessageId\n4d4dc071-ddbf-465d-bba8-08f81c89da64\n" +
				"Subject\nMy subject\nTimestamp\n2019-01-31T04:37:04.321Z\n" +
				"TopicArn\narn:aws:sns:us-east-2:123456789012:s4-MySNSTopic-1G1WEFCOXTC0P\nType\nNotification\n",
		},
		{
			name: "notification without subject",
			msg: snsMessage{
				Type:      snsNotification,
				Message:   "line one\nline two",
				MessageID: "m1",
				Timestamp: "2019-01-31T04:37:04.321Z",
				TopicArn:  "arn:aws:sns:us-east-2:123456789012:t",
			},
			want: "Message\nline one\nline two\nMessageId\nm1\nTimestamp\n2019-01-31T04:37:04.321Z\n" +
				"TopicArn\narn:aws:sns:us-east-2:123456789012:t\nType\nNotification\n",
		},
		{
			name: "subscription confirmation",
			msg: snsMessage{
				Type:         snsSubscriptionConfirmation,
				Message:      "Please confirm your subscription",
				MessageID:    "3d891288-136d-417f-bc05-901c108273ee",
				SubscribeURL: "https://sns.us-east-2.amazonaws.com/...",
				Timestamp:    "2024-01-01T00:00:00.000Z",
				Token:        "abc123...",
				TopicArn:     "arn:aws:sns:us-east-2:123456789012:MyTopic",
			},
			want: "Message\nPlease confirm your subscription\nMessageId\n3d891288-136d-417f-bc05-901c108273ee\n" +
				"SubscribeURL\nhttps://sns.us-east-2.amazonaws.com/...\nTimestamp\n2024-01-01T00:00:00.000Z\n" +
				"Token\nabc123...\nTopicArn\narn:aws:sns:us-east-2:123456789012:MyTopic\nType\nSubscriptionConfirmation\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.msg.stringToSign()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
	if _, err := (&snsMessage{Type: "Bogus"}).stringToSign(); err == nil {
		t.Error("unknown type: want an error")
	}
}

func TestValidSNSURL(t *testing.T) {
	tests := []struct {
		url  string
		pem  bool
		want bool
	}{
		{"https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem", true, true},
		{"https://sns.cn-north-1.amazonaws.com.cn/SimpleNotificationService-abc.pem", true, true},
		{"https://sns.us-gov-west-1.amazonaws.com/SimpleNotificationService-abc.pem", true, true},
		{"https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=x", false, true},
		{"http://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem", true, false},
		{"https://sns.us-east-1.amazonaws.com.evil.com/cert.pem", true, false},
		{"https://evil.com/sns.us-east-1.amazonaws.com/cert.pem", true, false},
		{"https://sns.amazonaws.com/cert.pem", true, false},
		{"https://s3.us-east-1.amazonaws.com/cert.pem", true, false},
		{"https://sns.us-east-1.amazonaws.com/cert.txt", true, false},
		{"https://user@sns.us-east-1.amazonaws.com/cert.pem", true, false},
		{"https://sns.us-east-1.amazonaws.com:8443/cert.pem", true, false},
		{"", true, false},
		{"::not a url", true, false},
	}
	for _, tt := range tests {
		if got := validSNSURL(tt.url, tt.pem); got != tt.want {
			t.Errorf("validSNSURL(%q, %v) = %v, want %v", tt.url, tt.pem, got, tt.want)
		}
	}
}

func newTestSES(t *testing.T, cfg SESConfig) http.Handler {
	t.Helper()
	if cfg.TopicARNs == nil {
		cfg.TopicARNs = []string{testTopic}
	}
	if cfg.AccountTag == "" && cfg.AccountHeader == "" {
		cfg.AccountTag = "catraca-account"
	}
	h, err := NewSESHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const deliveryJSON = `{"eventType":"Delivery","mail":{"timestamp":"2026-10-15T11:59:00.000Z",
"source":"news@example.com","messageId":"msg-1","tags":{"catraca-account":["acct_1"]}},
"delivery":{"timestamp":"2026-10-15T12:00:00.000Z","recipients":["a@example.org"]}}`

func TestSESSignatureVersions(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			dec := &recorder{}
			f := &fetcher{}
			h := newTestSES(t, SESConfig{Decider: dec, FetchCert: f.fetch})
			m := notification(t, deliveryJSON)
			testSigner().sign(t, m, version)
			rec := postJSON(t, h, m)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body)
			}
			if n := len(dec.got()); n != 1 {
				t.Fatalf("decided %d events, want 1", n)
			}
		})
	}
}

func TestSESRejectsForgeries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(m *snsMessage)
		status int
		fetch  bool
	}{
		{"tampered message", func(m *snsMessage) { m.Message = strings.Replace(m.Message, "acct_1", "acct_2", 1) }, http.StatusForbidden, true},
		{"tampered subject", func(m *snsMessage) { m.Subject = ptr("added") }, http.StatusForbidden, true},
		{"bad base64", func(m *snsMessage) { m.Signature = "%%%" }, http.StatusForbidden, true},
		{"unknown version", func(m *snsMessage) { m.SignatureVersion = "3" }, http.StatusForbidden, true},
		{"http cert URL", func(m *snsMessage) {
			m.SigningCertURL = strings.Replace(testCertURL, "https", "http", 1)
		}, http.StatusForbidden, false},
		{"foreign cert host", func(m *snsMessage) { m.SigningCertURL = "https://evil.example.com/cert.pem" }, http.StatusForbidden, false},
		{"topic not allowed", func(m *snsMessage) { m.TopicArn = "arn:aws:sns:us-east-1:999999999999:other" }, http.StatusForbidden, false},
		{"unknown type", func(m *snsMessage) { m.Type = "Bogus" }, http.StatusForbidden, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &recorder{}
			f := &fetcher{}
			var out outcomes
			h := newTestSES(t, SESConfig{Decider: dec, FetchCert: f.fetch, OnOutcome: out.add})
			m := notification(t, deliveryJSON)
			tt.mutate(m)
			rec := postJSON(t, h, m)
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d", rec.Code, tt.status)
			}
			if len(dec.got()) != 0 {
				t.Error("a forged message was decided")
			}
			if fetched := f.calls.Load() > 0; fetched != tt.fetch {
				t.Errorf("certificate fetched = %v, want %v", fetched, tt.fetch)
			}
			if strings.Contains(rec.Body.String(), "rsa") || strings.Contains(rec.Body.String(), "sns:") {
				t.Errorf("response leaks internals: %s", rec.Body)
			}
		})
	}
}

func TestSESCachesCertificates(t *testing.T) {
	f := &fetcher{}
	h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: f.fetch})
	for range 3 {
		if rec := postJSON(t, h, notification(t, deliveryJSON)); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("fetched the certificate %d times, want 1", n)
	}
}

func TestSESCertificateUnavailable(t *testing.T) {
	f := &fetcher{err: errors.New("connection reset")}
	var out outcomes
	h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: f.fetch, OnOutcome: out.add})
	rec := postJSON(t, h, notification(t, deliveryJSON))
	// 5xx, so SNS retries the message.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("response leaks the error: %s", rec.Body)
	}
	if !out.has(OutcomeCertUnavailable) {
		t.Error("cert_unavailable not reported")
	}
}

func subscription(t *testing.T, typ, subscribeURL string) *snsMessage {
	t.Helper()
	m := &snsMessage{
		Type:         typ,
		MessageID:    "165545c9-2a5c-472c-8df2-7ff2be2b3b1b",
		Token:        "2336412f37",
		TopicArn:     testTopic,
		Message:      "You have chosen to subscribe to the topic " + testTopic,
		SubscribeURL: subscribeURL,
		Timestamp:    "2026-10-15T12:00:00.000Z",
	}
	testSigner().sign(t, m, "1")
	return m
}

func TestSESConfirmsSubscription(t *testing.T) {
	const subscribeURL = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=" + testTopic + "&Token=2336412f37"
	var visited []string
	client := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		visited = append(visited, r.Method+" "+r.URL.String())
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("<ConfirmSubscriptionResponse/>"))}, nil
	})}
	var out outcomes
	h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: (&fetcher{}).fetch, HTTPClient: client, OnOutcome: out.add})

	rec := postJSON(t, h, subscription(t, snsSubscriptionConfirmation, subscribeURL))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if len(visited) != 1 || visited[0] != "GET "+subscribeURL {
		t.Fatalf("visited %v, want one GET of SubscribeURL", visited)
	}
	if !out.has(OutcomeSubscriptionConfirmed) {
		t.Error("subscription_confirmed not reported")
	}
}

func TestSESSubscriptionFailures(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		answer int
		status int
	}{
		{"subscribe URL on a foreign host", "https://evil.example.com/?Action=ConfirmSubscription", http.StatusOK, http.StatusForbidden},
		{"subscribe URL over http", "http://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription", http.StatusOK, http.StatusForbidden},
		{"SNS refuses", "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription", http.StatusForbidden, http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: tt.answer, Status: http.StatusText(tt.answer), Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			var out outcomes
			h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: (&fetcher{}).fetch, HTTPClient: client, OnOutcome: out.add})
			rec := postJSON(t, h, subscription(t, snsSubscriptionConfirmation, tt.url))
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d", rec.Code, tt.status)
			}
			if tt.status == http.StatusForbidden && calls != 0 {
				t.Error("visited an invalid SubscribeURL")
			}
			if !out.has(OutcomeSubscriptionFailed) {
				t.Error("subscription_failed not reported")
			}
		})
	}
}

func TestSESDoesNotFollowRedirects(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		h := http.Header{"Location": []string{"https://evil.example.com/"}}
		return &http.Response{StatusCode: http.StatusFound, Status: "302 Found", Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: (&fetcher{}).fetch, HTTPClient: client})
	rec := postJSON(t, h, subscription(t, snsSubscriptionConfirmation, "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"))
	if rec.Code != http.StatusBadGateway || calls != 1 {
		t.Fatalf("status %d after %d requests, want 502 after 1", rec.Code, calls)
	}
}

func TestSESUnsubscribeConfirmation(t *testing.T) {
	var out outcomes
	h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: (&fetcher{}).fetch, OnOutcome: out.add})
	rec := postJSON(t, h, subscription(t, snsUnsubscribeConfirmation, "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !out.has(OutcomeUnsubscribed) {
		t.Error("unsubscribed not reported")
	}
}

func TestSESRequestErrors(t *testing.T) {
	h := newTestSES(t, SESConfig{Decider: &recorder{}, FetchCert: (&fetcher{}).fetch, MaxBodyBytes: 512})

	if rec := post(t, h, []byte("not json"), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body: status %d, want 400", rec.Code)
	}
	if rec := post(t, h, []byte(`{"Type":"Notification"}`), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no topic: status %d, want 400", rec.Code)
	}
	big, _ := json.Marshal(map[string]string{"Type": "Notification", "Message": strings.Repeat("x", 1024)})
	if rec := post(t, h, big, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: status %d, want 413", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET: status %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestNewSESHandlerValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  SESConfig
	}{
		{"no decider", SESConfig{TopicARNs: []string{testTopic}, AccountTag: "a"}},
		{"no topics", SESConfig{Decider: &recorder{}, AccountTag: "a"}},
		{"bad topic", SESConfig{Decider: &recorder{}, TopicARNs: []string{"topic"}, AccountTag: "a"}},
		{"no account source", SESConfig{Decider: &recorder{}, TopicARNs: []string{testTopic}}},
	}
	for _, tt := range tests {
		if _, err := NewSESHandler(tt.cfg); err == nil {
			t.Errorf("%s: want an error", tt.name)
		}
	}
}
