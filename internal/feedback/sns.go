package feedback

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SNS message types.
// https://docs.aws.amazon.com/sns/latest/dg/http-subscription-confirmation-json.html
// https://docs.aws.amazon.com/sns/latest/dg/http-notification-json.html
// https://docs.aws.amazon.com/sns/latest/dg/http-unsubscribe-confirmation-json.html
const (
	snsNotification             = "Notification"
	snsSubscriptionConfirmation = "SubscriptionConfirmation"
	snsUnsubscribeConfirmation  = "UnsubscribeConfirmation"
)

// snsHostPattern is the host AWS's own validators accept for the signing
// certificate, including the China partition (amazonaws.com.cn):
// https://github.com/aws/aws-js-sns-message-validator/blob/master/index.js
// https://github.com/aws/aws-php-sns-message-validator/blob/master/src/MessageValidator.php
var snsHostPattern = regexp.MustCompile(`^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$`)

var (
	errBadSignature = errors.New("sns: invalid signature")
	errBadCertURL   = errors.New("sns: signing certificate URL is not an SNS URL")
)

// snsMessage is the JSON document SNS posts to HTTP(S) endpoints.
type snsMessage struct {
	Type      string `json:"Type"`
	MessageID string `json:"MessageId"`
	TopicArn  string `json:"TopicArn"`
	// Subject is a pointer because it is signed only when present.
	Subject          *string `json:"Subject"`
	Message          string  `json:"Message"`
	Timestamp        string  `json:"Timestamp"`
	SignatureVersion string  `json:"SignatureVersion"`
	Signature        string  `json:"Signature"`
	SigningCertURL   string  `json:"SigningCertURL"`
	SubscribeURL     string  `json:"SubscribeURL"`
	Token            string  `json:"Token"`
}

// stringToSign builds the canonical string SNS signs: "Key\nValue\n" for a
// fixed, byte-ordered set of keys that depends on the message type, with a
// single trailing newline.
// https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message-verify-message-signature.html
func (m *snsMessage) stringToSign() (string, error) {
	var b strings.Builder
	add := func(k, v string) {
		b.WriteString(k)
		b.WriteByte('\n')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	switch m.Type {
	case snsNotification:
		add("Message", m.Message)
		add("MessageId", m.MessageID)
		if m.Subject != nil {
			add("Subject", *m.Subject)
		}
		add("Timestamp", m.Timestamp)
		add("TopicArn", m.TopicArn)
		add("Type", m.Type)
	case snsSubscriptionConfirmation, snsUnsubscribeConfirmation:
		add("Message", m.Message)
		add("MessageId", m.MessageID)
		add("SubscribeURL", m.SubscribeURL)
		add("Timestamp", m.Timestamp)
		add("Token", m.Token)
		add("TopicArn", m.TopicArn)
		add("Type", m.Type)
	default:
		return "", fmt.Errorf("sns: unknown message type %q", m.Type)
	}
	return b.String(), nil
}

// verify checks the message signature against the certificate's RSA key.
// SignatureVersion 1 is SHA1withRSA and 2 is SHA256withRSA.
func (m *snsMessage) verify(cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("sns: signing certificate does not hold an RSA key")
	}
	canonical, err := m.stringToSign()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return errBadSignature
	}
	var hash crypto.Hash
	var digest []byte
	switch m.SignatureVersion {
	case "1":
		sum := sha1.Sum([]byte(canonical))
		hash, digest = crypto.SHA1, sum[:]
	case "2":
		sum := sha256.Sum256([]byte(canonical))
		hash, digest = crypto.SHA256, sum[:]
	default:
		return fmt.Errorf("sns: unsupported signature version %q", m.SignatureVersion)
	}
	if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
		return errBadSignature
	}
	return nil
}

// validSNSURL reports whether raw is an HTTPS URL on an SNS host. With pem
// set it also requires a .pem path, as AWS's validators do for the signing
// certificate.
func validSNSURL(raw string, pem bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	if !snsHostPattern.MatchString(u.Hostname()) {
		return false
	}
	return !pem || strings.HasSuffix(u.Path, ".pem")
}

// CertFetcher downloads the PEM-encoded signing certificate at certURL. The
// SES handler validates the URL before calling it, so a fetcher only needs
// to download. Tests inject one that returns a self-signed certificate.
type CertFetcher func(ctx context.Context, certURL string) ([]byte, error)

const maxCertBytes = 64 << 10

// HTTPCertFetcher returns a CertFetcher that downloads certificates with
// client, or with a client that times out after 10 seconds when client is
// nil. Redirects are not followed, so a certificate can only come from the
// validated SNS URL.
func HTTPCertFetcher(client *http.Client) CertFetcher {
	c := noRedirects(client)
	return func(ctx context.Context, certURL string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("sns: certificate request returned %s", resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxCertBytes))
	}
}

// noRedirects returns a copy of client (or of a default client) that does
// not follow redirects.
func noRedirects(client *http.Client) *http.Client {
	var c http.Client
	if client != nil {
		c = *client
	} else {
		c.Timeout = 10 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// certCache keeps parsed signing certificates by URL. SNS rotates
// certificates by publishing them under a new URL, so entries never go
// stale; the cache is only bounded so it cannot grow without limit.
type certCache struct {
	fetch CertFetcher

	mu    sync.RWMutex
	certs map[string]*x509.Certificate
}

const maxCachedCerts = 32

func newCertCache(fetch CertFetcher) *certCache {
	return &certCache{fetch: fetch, certs: map[string]*x509.Certificate{}}
}

func (c *certCache) get(ctx context.Context, certURL string) (*x509.Certificate, error) {
	c.mu.RLock()
	cert, ok := c.certs[certURL]
	c.mu.RUnlock()
	if ok {
		return cert, nil
	}
	raw, err := c.fetch(ctx, certURL)
	if err != nil {
		return nil, err
	}
	cert, err = parseCertPEM(raw)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.certs) >= maxCachedCerts {
		clear(c.certs)
	}
	c.certs[certURL] = cert
	c.mu.Unlock()
	return cert, nil
}

func parseCertPEM(raw []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, errors.New("sns: no certificate in PEM data")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}
