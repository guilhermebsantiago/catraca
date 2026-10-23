package feedback

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// recorder is a Decider that records the events it counts.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
	// fail, when set, decides whether Decide fails, as when no ruleset is
	// loaded.
	fail func(event.Event) bool
	// refuse, when set, decides whether Decide refuses the event as the
	// engine refuses one it does not accept, with errRefused.
	refuse func(event.Event) bool
	// uncounted, when set, decides whether the event is decided as with a
	// store that failed: degraded and uncounted, and not recorded.
	uncounted func(event.Event) bool
	// late, when set, decides whether the event is decided as with a store
	// that answered after the deadline: degraded, and recorded, since the
	// store's writes still apply.
	late func(event.Event) bool
}

var errRefused = fmt.Errorf("%w: event: time 1970-01-01T00:00:00Z is more than 168h0m0s in the past", event.ErrInvalid)

func (r *recorder) Decide(_ context.Context, ev event.Event) (decision.Decision, error) {
	if r.refuse != nil && r.refuse(ev) {
		return decision.Decision{}, errRefused
	}
	if r.fail != nil && r.fail(ev) {
		return decision.Decision{}, errors.New("store exploded")
	}
	d := decision.Decision{ID: "dec_1", EventID: ev.ID, Action: decision.Allow, Time: time.Unix(0, 0).UTC()}
	if r.uncounted != nil && r.uncounted(ev) {
		d.Degraded, d.Uncounted = true, true
		return d, nil
	}
	d.Degraded = r.late != nil && r.late(ev)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return d, nil
}

func (r *recorder) got() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.events...)
}

// outcomes collects reported outcomes.
type outcomes struct {
	mu   sync.Mutex
	list []Outcome
}

func (o *outcomes) add(x Outcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.list = append(o.list, x)
}

func (o *outcomes) has(x Outcome) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, y := range o.list {
		if y == x {
			return true
		}
	}
	return false
}

// signer is a self-signed certificate standing in for the SNS signing
// certificate.
type signer struct {
	key     *rsa.PrivateKey
	certPEM []byte
}

var testSigner = sync.OnceValue(func() *signer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return &signer{key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
})

const (
	testTopic   = "arn:aws:sns:us-east-1:123456789012:ses-feedback"
	testCertURL = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0123456789abcdef.pem"
)

// sign sets SigningCertURL, SignatureVersion and Signature on m.
func (s *signer) sign(t *testing.T, m *snsMessage, version string) {
	t.Helper()
	if m.SigningCertURL == "" {
		m.SigningCertURL = testCertURL
	}
	m.SignatureVersion = version
	canonical, err := m.stringToSign()
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	switch version {
	case "1":
		sum := sha1.Sum([]byte(canonical))
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, sum[:])
	default:
		sum := sha256.Sum256([]byte(canonical))
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
}

// fetcher serves the test certificate and counts calls.
type fetcher struct {
	calls atomic.Int32
	err   error
}

func (f *fetcher) fetch(_ context.Context, certURL string) ([]byte, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return testSigner().certPEM, nil
}

// notification wraps an SES notification in a signed SNS Notification.
func notification(t *testing.T, ses string) *snsMessage {
	t.Helper()
	m := &snsMessage{
		Type:      snsNotification,
		MessageID: "22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324",
		TopicArn:  testTopic,
		Message:   ses,
		Timestamp: "2026-10-15T12:00:00.000Z",
	}
	testSigner().sign(t, m, "2")
	return m
}

func post(t *testing.T, h http.Handler, body []byte, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postJSON(t *testing.T, h http.Handler, v any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return post(t, h, body, nil)
}

// roundTripper answers requests with a function.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
