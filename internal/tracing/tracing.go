// Package tracing sets up OpenTelemetry tracing for the server: a tracer
// provider that samples traces by ratio and exports their spans over
// OTLP/HTTP.
//
// It is the only package that needs the OpenTelemetry SDK. The packages that
// make spans (api, engine, hooks, audit, secretscan) take a
// trace.TracerProvider and make none when it is nil, so with tracing off,
// the default, a decision costs what it did before tracing existed.
//
// The standard OTEL_* environment variables apply where the configuration
// leaves a setting out: OTEL_EXPORTER_OTLP_ENDPOINT and
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, OTEL_SERVICE_NAME, OTEL_TRACES_SAMPLER
// and OTEL_TRACES_SAMPLER_ARG; the ones it has no setting for always do:
// OTEL_EXPORTER_OTLP_HEADERS, _TIMEOUT, _COMPRESSION and _CERTIFICATE (and
// their _TRACES_ forms), OTEL_RESOURCE_ATTRIBUTES and OTEL_BSP_*. And
// OTEL_SDK_DISABLED=true turns tracing off whatever the configuration says.
package tracing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// DefaultSampleRatio is the share of traces kept that start at Catraca,
// when neither Options.SampleRatio nor OTEL_TRACES_SAMPLER says. A trace
// that a caller's traceparent started is kept when the caller kept it,
// whatever the ratio.
const DefaultSampleRatio = 0.1

// DefaultServiceName is the service.name of the spans when neither
// Options.ServiceName nor OTEL_SERVICE_NAME says.
const DefaultServiceName = "catraca"

// tracesPath is where an OTLP/HTTP collector takes spans.
const tracesPath = "/v1/traces"

// Options configure a Provider. Every field may be left out.
type Options struct {
	// Endpoint is the OTLP/HTTP URL spans are sent to, such as
	// http://otel-collector:4318. A URL without a path gets /v1/traces.
	// Empty reads OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, then
	// OTEL_EXPORTER_OTLP_ENDPOINT, then takes http://localhost:4318.
	Endpoint string
	// SampleRatio is the share of the traces that start at Catraca which
	// are kept, from 0 to 1; a trace a caller started is kept when the
	// caller kept it. Nil reads OTEL_TRACES_SAMPLER and
	// OTEL_TRACES_SAMPLER_ARG, and without them takes DefaultSampleRatio.
	SampleRatio *float64
	// ServiceName is the service.name of every span. Empty reads
	// OTEL_SERVICE_NAME, then takes DefaultServiceName.
	ServiceName string
	// Version is the build version, the spans' service.version.
	Version string
	// Logger receives the exporter's errors, at most one a minute, since a
	// collector that is down fails every export. Nil discards them.
	Logger *slog.Logger
}

// Provider is the tracer provider of a server. A nil *Provider is tracing
// off.
type Provider struct {
	tp *sdktrace.TracerProvider
}

// Disabled reports whether OTEL_SDK_DISABLED turns tracing off.
func Disabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true")
}

// New returns a Provider that exports spans as opts says, or nil when
// OTEL_SDK_DISABLED is true. It does not connect to the collector: spans
// are batched and sent in the background, and a collector that is down
// costs dropped spans and a log line, never a decision.
func New(ctx context.Context, opts Options) (*Provider, error) {
	if Disabled() {
		return nil, nil
	}
	if r := opts.SampleRatio; r != nil && (*r < 0 || *r > 1) {
		return nil, fmt.Errorf("tracing: sample ratio %g is not between 0 and 1", *r)
	}
	var expOpts []otlptracehttp.Option
	if opts.Endpoint != "" {
		u, err := EndpointURL(opts.Endpoint)
		if err != nil {
			return nil, err
		}
		expOpts = append(expOpts, otlptracehttp.WithEndpointURL(u))
	}
	exp, err := otlptracehttp.New(ctx, expOpts...)
	if err != nil {
		return nil, fmt.Errorf("tracing: OTLP exporter: %w", err)
	}
	res, err := newResource(ctx, opts)
	if err != nil {
		return nil, err
	}
	tpOpts := []sdktrace.TracerProviderOption{sdktrace.WithBatcher(exp), sdktrace.WithResource(res)}
	// The SDK reads OTEL_TRACES_SAMPLER itself when no sampler is given.
	if opts.SampleRatio != nil || os.Getenv("OTEL_TRACES_SAMPLER") == "" {
		ratio := DefaultSampleRatio
		if opts.SampleRatio != nil {
			ratio = *opts.SampleRatio
		}
		tpOpts = append(tpOpts, sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))))
	}
	setErrorHandler(opts.Logger)
	return &Provider{tp: sdktrace.NewTracerProvider(tpOpts...)}, nil
}

// newResource describes the service: its name and version, the host, the
// SDK, and OTEL_RESOURCE_ATTRIBUTES. Later sources override earlier ones,
// so the configuration's service name beats OTEL_SERVICE_NAME, which beats
// the default.
func newResource(ctx context.Context, opts Options) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{attribute.String("service.name", DefaultServiceName)}
	if opts.Version != "" {
		attrs = append(attrs, attribute.String("service.version", opts.Version))
	}
	ropts := []resource.Option{
		resource.WithAttributes(attrs...),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
	}
	if opts.ServiceName != "" {
		ropts = append(ropts, resource.WithAttributes(attribute.String("service.name", opts.ServiceName)))
	}
	res, err := resource.New(ctx, ropts...)
	if err != nil && res == nil {
		return nil, fmt.Errorf("tracing: resource: %w", err)
	}
	// A partial resource, say with a malformed OTEL_RESOURCE_ATTRIBUTES
	// entry, is still worth tracing with.
	return res, nil
}

// EndpointURL returns the URL spans are posted to for endpoint: endpoint
// itself, with /v1/traces when it has no path.
func EndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("tracing: endpoint %q is not an http or https URL", endpoint)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = tracesPath
	}
	return u.String(), nil
}

// TracerProvider returns the provider to make spans with, or nil with
// tracing off.
func (p *Provider) TracerProvider() trace.TracerProvider {
	if p == nil {
		return nil
	}
	return p.tp
}

// Shutdown sends the spans still batched and stops the exporter, for as
// long as ctx allows. Call it once nothing makes spans any more.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if err := p.tp.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("tracing: flush spans: %w", err)
	}
	return nil
}

// errorLogEvery limits how often export errors are logged.
const errorLogEvery = time.Minute

var lastErrorLog atomic.Int64

// setErrorHandler sends the SDK's errors, such as a failed export, to log,
// at most one a minute. The SDK has a single handler per process; the
// server makes one Provider, so the last one set wins.
func setErrorHandler(log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		now := time.Now().UnixNano()
		last := lastErrorLog.Load()
		if now-last < int64(errorLogEvery) || !lastErrorLog.CompareAndSwap(last, now) {
			return
		}
		log.Warn("tracing: spans could not be exported; decisions are not affected", "error", err)
	}))
}
