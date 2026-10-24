package tracing

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// The exporter is Catraca's own, small, OTLP/HTTP client: it posts each
// batch of spans to the collector as an ExportTraceServiceRequest in
// protobuf. OpenTelemetry's Go exporter does the same, but the package that
// holds that request type also holds its gRPC service, so importing it
// links gRPC, its gateway and an HTTP/2 stack into the server: about 12 MB,
// half the binary again, and their vulnerabilities, for a feature that is
// off by default. The request is one repeated field, written here with
// protowire, around the span messages, which import only protobuf.

// Defaults and limits of the exporter. The timeout is the OTLP default.
const (
	defaultExportTimeout = 10 * time.Second
	exportAttempts       = 3
	retryFirst           = 500 * time.Millisecond
	maxResponseBytes     = 64 << 10
)

// errStopped is returned for spans exported after Shutdown.
var errStopped = errors.New("tracing: the exporter is shut down")

// exporter is an sdktrace.SpanExporter that posts spans over OTLP/HTTP.
type exporter struct {
	url       string
	headers   http.Header
	gzip      bool
	timeout   time.Duration
	client    *http.Client
	stopped   atomic.Bool
	retryWait func(attempt int, retryAfter time.Duration) time.Duration
}

// newExporter returns an exporter to endpoint, a URL already normalized by
// EndpointURL, or, when it is empty, to the one the OTEL_* variables name.
// The rest of its settings come from those variables:
// OTEL_EXPORTER_OTLP_HEADERS, _TIMEOUT, _COMPRESSION, _CERTIFICATE,
// _CLIENT_CERTIFICATE and _CLIENT_KEY, each also in a _TRACES_ form that
// wins over it, as the OpenTelemetry specification says.
func newExporter(endpoint, version string) (*exporter, error) {
	if endpoint == "" {
		var err error
		if endpoint, err = endpointFromEnv(); err != nil {
			return nil, err
		}
	}
	e := &exporter{url: endpoint, headers: http.Header{}, timeout: defaultExportTimeout, retryWait: retryWait}
	for k, v := range parseHeaders(otlpEnv("HEADERS")) {
		e.headers.Set(k, v)
	}
	e.headers.Set("Content-Type", "application/x-protobuf")
	e.headers.Set("User-Agent", strings.TrimSpace("Catraca "+version))
	if v := otlpEnv("TIMEOUT"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil || ms <= 0 {
			return nil, fmt.Errorf("tracing: OTEL_EXPORTER_OTLP_TIMEOUT %q is not a number of milliseconds", v)
		}
		e.timeout = time.Duration(ms) * time.Millisecond
	}
	switch v := strings.ToLower(otlpEnv("COMPRESSION")); v {
	case "", "none":
	case "gzip":
		e.gzip = true
		e.headers.Set("Content-Encoding", "gzip")
	default:
		return nil, fmt.Errorf("tracing: OTEL_EXPORTER_OTLP_COMPRESSION %q: want gzip or none", v)
	}
	tlsConfig, err := tlsFromEnv()
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	e.client = &http.Client{
		Transport: transport,
		// A collector that redirects is misconfigured; following it would
		// send the spans and their headers somewhere unexpected.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return e, nil
}

// otlpEnv reads OTEL_EXPORTER_OTLP_TRACES_<name>, or else
// OTEL_EXPORTER_OTLP_<name>.
func otlpEnv(name string) string {
	if v := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_" + name)); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_" + name))
}

// endpointFromEnv returns the traces URL of the OTEL_* variables: the
// signal's own, as is, or the general one with /v1/traces, or the
// collector's default port on this host.
func endpointFromEnv() (string, error) {
	raw := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	if raw == "" {
		if base := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); base != "" {
			raw = strings.TrimSuffix(base, "/") + tracesPath
		} else {
			raw = "http://localhost:4318" + tracesPath
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("tracing: the OTLP endpoint from the environment, %q, is not an http or https URL", raw)
	}
	return raw, nil
}

// parseHeaders reads key=value pairs separated by commas, with values
// percent-encoded, the format of OTEL_EXPORTER_OTLP_HEADERS.
func parseHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		if dv, err := url.PathUnescape(strings.TrimSpace(v)); err == nil {
			v = dv
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

// tlsFromEnv returns the TLS configuration the OTEL_* variables ask for: a
// CA file to trust instead of the system's, and a client certificate.
func tlsFromEnv() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if file := otlpEnv("CERTIFICATE"); file != "" {
		pem, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("tracing: OTEL_EXPORTER_OTLP_CERTIFICATE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tracing: OTEL_EXPORTER_OTLP_CERTIFICATE: no PEM certificate in %s", file)
		}
		cfg.RootCAs = pool
	}
	certFile, keyFile := otlpEnv("CLIENT_CERTIFICATE"), otlpEnv("CLIENT_KEY")
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("tracing: set both OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE and OTEL_EXPORTER_OTLP_CLIENT_KEY, or neither")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tracing: OTLP client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// ExportSpans posts spans to the collector. A 429, 502, 503 or 504 answer,
// or no answer, is retried a few times with backoff, within the export
// timeout; any other failure drops the batch, which the batch processor
// reports to the error handler.
func (e *exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if e.stopped.Load() {
		return errStopped
	}
	if len(spans) == 0 {
		return nil
	}
	body, err := marshalRequest(resourceSpans(spans))
	if err != nil {
		return err
	}
	if e.gzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		if err := zw.Close(); err != nil {
			return err
		}
		body = buf.Bytes()
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	for attempt := 1; ; attempt++ {
		retryAfter, err := e.post(ctx, body)
		var temp *temporaryError
		if err == nil || !errors.As(err, &temp) || attempt == exportAttempts {
			return err
		}
		t := time.NewTimer(e.retryWait(attempt, retryAfter))
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return err
		}
	}
}

// temporaryError is a failure worth another attempt.
type temporaryError struct{ err error }

func (e *temporaryError) Error() string { return e.err.Error() }
func (e *temporaryError) Unwrap() error { return e.err }

// post makes one attempt, and returns the collector's Retry-After with a
// temporary error.
func (e *exporter) post(ctx context.Context, body []byte) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header = e.headers.Clone()
	resp, err := e.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("tracing: export spans: %w", err)
		}
		return 0, &temporaryError{fmt.Errorf("tracing: export spans: %w", err)}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return 0, nil
	}
	err = fmt.Errorf("tracing: export spans: the collector answered %s", resp.Status)
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		retryAfter := time.Duration(0)
		if secs, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && secs > 0 {
			retryAfter = time.Duration(secs) * time.Second
		}
		return retryAfter, &temporaryError{err}
	}
	if len(snippet) > 0 && len(snippet) < 512 && !strings.ContainsFunc(string(snippet), func(r rune) bool { return r < ' ' && r != '\n' }) {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(snippet)))
	}
	return 0, err
}

// retryWait is the wait before attempt+1: 0.5s doubling, jittered to
// between half and all of it, or the collector's Retry-After when longer.
func retryWait(attempt int, retryAfter time.Duration) time.Duration {
	d := retryFirst << (attempt - 1)
	d = d/2 + rand.N(d/2+1)
	return max(d, retryAfter)
}

// Shutdown makes later exports fail at once. The batch processor sends what
// it holds before it calls Shutdown.
func (e *exporter) Shutdown(context.Context) error {
	e.stopped.Store(true)
	e.client.CloseIdleConnections()
	return nil
}

// marshalRequest encodes an ExportTraceServiceRequest: field 1, repeated,
// holds each ResourceSpans.
func marshalRequest(rss []*tracepb.ResourceSpans) ([]byte, error) {
	var b []byte
	for _, rs := range rss {
		m, err := proto.Marshal(rs)
		if err != nil {
			return nil, fmt.Errorf("tracing: encode spans: %w", err)
		}
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, m)
	}
	return b, nil
}
