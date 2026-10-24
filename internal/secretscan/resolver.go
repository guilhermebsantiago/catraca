package secretscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/propagation"

	"github.com/guilhermebsantiago/catraca/signature"
)

// HTTPResolverConfig configures an HTTPResolver.
type HTTPResolverConfig struct {
	// URL is the platform endpoint that maps tokens to keys. Required.
	URL string
	// Secret signs each request in signature.Header, the scheme Catraca
	// signs all its outgoing requests with. Required.
	Secret string
	// SendRawToken adds the raw token to the request. By default only its
	// SHA-256 is sent, which is enough for a platform that stores key
	// hashes; enable this only for a platform that cannot look keys up by
	// hash, and only over HTTPS.
	SendRawToken bool
	// Client sends the requests. The default times out after 10 seconds.
	// Redirects are never followed.
	Client *http.Client
}

// HTTPResolver resolves tokens by asking the platform over HTTP.
//
// It POSTs a JSON body:
//
//	{"token_sha256": "<hex>", "type": "acme_api_key", "source": "commit",
//	 "url": "https://github.com/..."}
//
// with "token" added only when SendRawToken is set, signed in
// signature.Header. The platform verifies the signature (in Go, with
// signature.Verify) and answers 200 with {"api_key_id": "key_123",
// "account_id": "acct_456"} when the token is one of its keys, and 404 when
// it is not. Any other answer is an error.
type HTTPResolver struct {
	url    string
	secret string
	raw    bool
	client *http.Client
	now    func() time.Time
}

// NewHTTPResolver returns an HTTPResolver.
func NewHTTPResolver(cfg HTTPResolverConfig) (*HTTPResolver, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("secretscan: resolver URL must be an http(s) URL")
	}
	if cfg.Secret == "" {
		return nil, errors.New("secretscan: resolver secret is required")
	}
	var c http.Client
	if cfg.Client != nil {
		c = *cfg.Client
	} else {
		c.Timeout = 10 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPResolver{url: cfg.URL, secret: cfg.Secret, raw: cfg.SendRawToken, client: &c, now: time.Now}, nil
}

type resolveRequest struct {
	TokenSHA256 string `json:"token_sha256"`
	Token       string `json:"token,omitempty"`
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	URL         string `json:"url,omitempty"`
}

type resolveResponse struct {
	APIKeyID  string `json:"api_key_id"`
	AccountID string `json:"account_id"`
}

// Resolve asks the platform which key t belongs to.
func (r *HTTPResolver) Resolve(ctx context.Context, t Token) (Key, error) {
	in := resolveRequest{TokenSHA256: t.SHA256, Type: t.Type, Source: t.Source, URL: t.URL}
	if r.raw {
		in.Token = t.Raw
	}
	body, err := json.Marshal(in)
	if err != nil {
		return Key{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return Key{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "catraca-secretscan")
	req.Header.Set(signature.Header, signature.Sign(r.secret, r.now(), body))
	// The attempt's trace, with tracing on, so the platform's spans join it.
	traceContext.Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := r.client.Do(req)
	if err != nil {
		return Key{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return Key{}, ErrNotFound
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return Key{}, fmt.Errorf("secretscan: resolver returned %s", resp.Status)
	}
	var out resolveResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return Key{}, fmt.Errorf("secretscan: decoding resolver response: %w", err)
	}
	if out.APIKeyID == "" {
		return Key{}, errors.New("secretscan: resolver response has no api_key_id")
	}
	return Key(out), nil
}
