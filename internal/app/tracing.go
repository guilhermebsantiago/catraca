package app

import (
	"context"
	"net/url"

	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/tracing"
)

// startTracing sets up tracing when the configuration turns it on and
// OTEL_SDK_DISABLED does not turn it off again. Nothing is sent until a span
// ends, so a collector that is down does not stop the server.
func (a *App) startTracing(ctx context.Context) error {
	if !a.cfg.Tracing.Enabled {
		return nil
	}
	if tracing.Disabled() {
		a.log.Info("tracing is enabled in the configuration, but OTEL_SDK_DISABLED=true turns it off")
		return nil
	}
	opts := a.cfg.Tracing.Options()
	opts.Version = a.version
	opts.Logger = a.log.With("component", "tracing")
	p, err := tracing.New(ctx, opts)
	if err != nil {
		return err
	}
	a.tracing = p
	attrs := []any{}
	if opts.Endpoint != "" {
		if u, err := url.Parse(opts.Endpoint); err == nil {
			attrs = append(attrs, "endpoint", u.Redacted())
		}
	}
	if opts.SampleRatio != nil {
		attrs = append(attrs, "sample_ratio", *opts.SampleRatio)
	}
	a.log.Info("tracing is on: spans go to the OTLP/HTTP endpoint", attrs...)
	return nil
}

// tracerProvider returns what the server makes spans with, nil with tracing
// off.
func (a *App) tracerProvider() trace.TracerProvider {
	return a.tracing.TracerProvider()
}
