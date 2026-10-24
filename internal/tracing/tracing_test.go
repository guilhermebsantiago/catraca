package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TestEndpointURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://otel-collector:4318":            "http://otel-collector:4318/v1/traces",
		"https://otel.example/":                 "https://otel.example/v1/traces",
		"https://otel.example/tenant/v1/traces": "https://otel.example/tenant/v1/traces",
	} {
		if got, err := EndpointURL(in); err != nil || got != want {
			t.Errorf("EndpointURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"otel:4318", "grpc://otel:4317", "http://", "://x"} {
		if _, err := EndpointURL(bad); err == nil {
			t.Errorf("EndpointURL(%q) succeeded", bad)
		}
	}
}

func newProvider(t *testing.T, opts Options) *Provider {
	t.Helper()
	if opts.Endpoint == "" {
		// Nothing listens there; spans that reach it are dropped.
		opts.Endpoint = "http://127.0.0.1:1"
	}
	p, err := New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

func ratio(r float64) *float64 { return &r }

// A trace a caller kept is kept whatever the ratio; one that starts here is
// kept by the ratio.
func TestSamplingFollowsTheCaller(t *testing.T) {
	tracer := newProvider(t, Options{SampleRatio: ratio(0)}).TracerProvider().Tracer("test")
	_, root := tracer.Start(context.Background(), "root")
	if root.SpanContext().IsSampled() {
		t.Error("a ratio of 0 sampled a trace that starts here")
	}
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled, Remote: true,
	})
	_, child := tracer.Start(trace.ContextWithRemoteSpanContext(context.Background(), parent), "child")
	if !child.SpanContext().IsSampled() {
		t.Error("a trace the caller sampled was not sampled")
	}

	tracer = newProvider(t, Options{SampleRatio: ratio(1)}).TracerProvider().Tracer("test")
	if _, s := tracer.Start(context.Background(), "root"); !s.SpanContext().IsSampled() {
		t.Error("a ratio of 1 did not sample")
	}
}

// OTEL_TRACES_SAMPLER applies when the configuration has no ratio.
func TestSamplerFromTheEnvironment(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	tracer := newProvider(t, Options{}).TracerProvider().Tracer("test")
	if _, s := tracer.Start(context.Background(), "root"); s.SpanContext().IsSampled() {
		t.Error("OTEL_TRACES_SAMPLER=always_off was ignored")
	}
	tracer = newProvider(t, Options{SampleRatio: ratio(1)}).TracerProvider().Tracer("test")
	if _, s := tracer.Start(context.Background(), "root"); !s.SpanContext().IsSampled() {
		t.Error("the configured ratio did not win over OTEL_TRACES_SAMPLER")
	}
}

func TestDisabledByTheEnvironment(t *testing.T) {
	t.Setenv("OTEL_SDK_DISABLED", "true")
	p, err := New(context.Background(), Options{})
	if err != nil || p != nil {
		t.Fatalf("New = %v, %v; want no provider", p, err)
	}
	// A nil Provider is tracing off.
	if p.TracerProvider() != nil {
		t.Error("a nil Provider has a TracerProvider")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Error(err)
	}
}

func TestBadRatio(t *testing.T) {
	if _, err := New(context.Background(), Options{SampleRatio: ratio(2)}); err == nil {
		t.Error("New accepted a sample ratio of 2")
	}
}

func serviceName(t *testing.T, opts Options) string {
	t.Helper()
	res, err := newResource(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := res.Set().Value(attribute.Key("service.name"))
	return v.AsString()
}

func TestServiceName(t *testing.T) {
	if got := serviceName(t, Options{}); got != DefaultServiceName {
		t.Errorf("service.name = %q, want %q", got, DefaultServiceName)
	}
	t.Setenv("OTEL_SERVICE_NAME", "from-env")
	if got := serviceName(t, Options{}); got != "from-env" {
		t.Errorf("service.name = %q, want OTEL_SERVICE_NAME's", got)
	}
	if got := serviceName(t, Options{ServiceName: "from-config"}); got != "from-config" {
		t.Errorf("service.name = %q, want the configuration's", got)
	}
}
