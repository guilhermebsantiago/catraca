package tracing

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// collector is a fake OTLP/HTTP endpoint that answers with the next status
// of its script, the last one repeating, and keeps what it was sent.
type collector struct {
	*httptest.Server
	mu       sync.Mutex
	statuses []int
	requests []*http.Request
	bodies   [][]byte
}

func newCollector(t *testing.T, statuses ...int) *collector {
	t.Helper()
	c := &collector{statuses: statuses}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, r)
		c.bodies = append(c.bodies, body)
		status := http.StatusOK
		if len(c.statuses) > 0 {
			status = c.statuses[0]
			if len(c.statuses) > 1 {
				c.statuses = c.statuses[1:]
			}
		}
		c.mu.Unlock()
		w.WriteHeader(status)
		if status == http.StatusBadRequest {
			io.WriteString(w, "span without a name")
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *collector) got() ([]*http.Request, [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*http.Request(nil), c.requests...), append([][]byte(nil), c.bodies...)
}

// decode reads an ExportTraceServiceRequest.
func decode(t *testing.T, b []byte) []*tracepb.ResourceSpans {
	t.Helper()
	var out []*tracepb.ResourceSpans
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 || num != 1 || typ != protowire.BytesType {
			t.Fatalf("unexpected field %d of type %d", num, typ)
		}
		v, m := protowire.ConsumeBytes(b[n:])
		if m < 0 {
			t.Fatal(protowire.ParseError(m))
		}
		b = b[n+m:]
		rs := &tracepb.ResourceSpans{}
		if err := proto.Unmarshal(v, rs); err != nil {
			t.Fatal(err)
		}
		out = append(out, rs)
	}
	return out
}

func anyString(v *commonpb.AnyValue) string { return v.GetStringValue() }

func attr(kvs []*commonpb.KeyValue, key string) *commonpb.AnyValue {
	for _, kv := range kvs {
		if kv.GetKey() == key {
			return kv.GetValue()
		}
	}
	return nil
}

// tracer exports each span as it ends, to e.
func tracer(t *testing.T, e *exporter) trace.Tracer {
	t.Helper()
	res := resource.NewSchemaless(attribute.String("service.name", "catraca-test"))
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(e), sdktrace.WithResource(res))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return tp.Tracer("github.com/guilhermebsantiago/catraca/internal/test", trace.WithInstrumentationVersion("v1"))
}

func TestExporterSendsOTLPProtobuf(t *testing.T) {
	c := newCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "api-key=s%3Dcret%2C1 , x-tenant=catraca,broken")
	e, err := newExporter(c.URL+"/v1/traces", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	tr := tracer(t, e)
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3}, SpanID: trace.SpanID{4, 5, 6}, TraceFlags: trace.FlagsSampled, Remote: true,
	})
	_, s := tr.Start(trace.ContextWithRemoteSpanContext(context.Background(), parent), "POST /v1/decide",
		trace.WithSpanKind(trace.SpanKindServer))
	s.SetAttributes(
		attribute.String("http.route", "/v1/decide"), attribute.Int("http.response.status_code", 503),
		attribute.Bool("catraca.decision.degraded", true), attribute.Float64("ratio", 0.5),
		attribute.StringSlice("catraca.decision.rules", []string{"a", "b"}),
	)
	s.AddEvent("shed", trace.WithAttributes(attribute.Int("limit", 7)))
	s.SetStatus(codes.Error, "Service Unavailable")
	s.End()

	reqs, bodies := c.got()
	if len(reqs) != 1 {
		t.Fatalf("collector got %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" ||
		r.Header.Get("Api-Key") != "s=cret,1" || r.Header.Get("X-Tenant") != "catraca" ||
		r.Header.Get("User-Agent") != "Catraca v1.2.3" || r.Header.Get("Content-Encoding") != "" {
		t.Errorf("request %s %v", r.URL.Path, r.Header)
	}
	rss := decode(t, bodies[0])
	if len(rss) != 1 || len(rss[0].GetScopeSpans()) != 1 || len(rss[0].GetScopeSpans()[0].GetSpans()) != 1 {
		t.Fatalf("request %v, want one span", rss)
	}
	if got := anyString(attr(rss[0].GetResource().GetAttributes(), "service.name")); got != "catraca-test" {
		t.Errorf("service.name = %q", got)
	}
	scope := rss[0].GetScopeSpans()[0].GetScope()
	if scope.GetName() != "github.com/guilhermebsantiago/catraca/internal/test" || scope.GetVersion() != "v1" {
		t.Errorf("scope = %v", scope)
	}
	sp := rss[0].GetScopeSpans()[0].GetSpans()[0]
	sc := s.SpanContext()
	tid, sid := sc.TraceID(), sc.SpanID()
	switch {
	case string(sp.GetTraceId()) != string(tid[:]) || string(sp.GetSpanId()) != string(sid[:]):
		t.Errorf("ids %x %x, want %s %s", sp.GetTraceId(), sp.GetSpanId(), tid, sid)
	case string(sp.GetParentSpanId()) != string([]byte{4, 5, 6, 0, 0, 0, 0, 0}):
		t.Errorf("parent %x", sp.GetParentSpanId())
	case sp.GetName() != "POST /v1/decide" || sp.GetKind() != tracepb.Span_SPAN_KIND_SERVER:
		t.Errorf("name %q kind %v", sp.GetName(), sp.GetKind())
	case sp.GetFlags() != 0x301:
		t.Errorf("flags %#x, want sampled with a remote parent, 0x301", sp.GetFlags())
	case sp.GetStatus().GetCode() != tracepb.Status_STATUS_CODE_ERROR || sp.GetStatus().GetMessage() != "Service Unavailable":
		t.Errorf("status %v", sp.GetStatus())
	case sp.GetStartTimeUnixNano() == 0 || sp.GetEndTimeUnixNano() < sp.GetStartTimeUnixNano():
		t.Errorf("times %d to %d", sp.GetStartTimeUnixNano(), sp.GetEndTimeUnixNano())
	case len(sp.GetEvents()) != 1 || sp.GetEvents()[0].GetName() != "shed" || attr(sp.GetEvents()[0].GetAttributes(), "limit").GetIntValue() != 7:
		t.Errorf("events %v", sp.GetEvents())
	}
	a := sp.GetAttributes()
	if anyString(attr(a, "http.route")) != "/v1/decide" || attr(a, "http.response.status_code").GetIntValue() != 503 ||
		!attr(a, "catraca.decision.degraded").GetBoolValue() || attr(a, "ratio").GetDoubleValue() != 0.5 {
		t.Errorf("attributes %v", a)
	}
	if rules := attr(a, "catraca.decision.rules").GetArrayValue().GetValues(); len(rules) != 2 || anyString(rules[1]) != "b" {
		t.Errorf("rules %v", rules)
	}
}

func TestExporterCompresses(t *testing.T) {
	c := newCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_COMPRESSION", "gzip")
	e, err := newExporter(c.URL+"/v1/traces", "")
	if err != nil {
		t.Fatal(err)
	}
	_, s := tracer(t, e).Start(context.Background(), "catraca.decide")
	s.End()
	reqs, bodies := c.got()
	if len(reqs) != 1 || reqs[0].Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("requests %v", reqs)
	}
	zr, err := gzip.NewReader(strings.NewReader(string(bodies[0])))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if rss := decode(t, body); rss[0].GetScopeSpans()[0].GetSpans()[0].GetName() != "catraca.decide" {
		t.Errorf("request %v", rss)
	}
}

func TestExporterRetriesTemporaryFailures(t *testing.T) {
	c := newCollector(t, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusOK)
	e, err := newExporter(c.URL+"/v1/traces", "")
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	e.retryWait = func(attempt int, retryAfter time.Duration) time.Duration {
		waits = append(waits, retryWait(attempt, retryAfter))
		return 0
	}
	spans := endedSpans(t, 2)
	if err := e.ExportSpans(context.Background(), spans); err != nil {
		t.Fatal(err)
	}
	if reqs, _ := c.got(); len(reqs) != 3 {
		t.Errorf("collector got %d requests, want 3", len(reqs))
	}
	if len(waits) != 2 || waits[0] > retryFirst || waits[1] > 2*retryFirst {
		t.Errorf("waits %v", waits)
	}
}

func TestExporterGivesUp(t *testing.T) {
	c := newCollector(t, http.StatusBadRequest)
	e, err := newExporter(c.URL+"/v1/traces", "")
	if err != nil {
		t.Fatal(err)
	}
	err = e.ExportSpans(context.Background(), endedSpans(t, 1))
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request: span without a name") {
		t.Errorf("err = %v, want the collector's 400 and its message", err)
	}
	if reqs, _ := c.got(); len(reqs) != 1 {
		t.Errorf("a 400 was retried: %d requests", len(reqs))
	}

	// A collector that stays unavailable is tried a few times only.
	down := newCollector(t, http.StatusServiceUnavailable)
	e, _ = newExporter(down.URL+"/v1/traces", "")
	e.retryWait = func(int, time.Duration) time.Duration { return 0 }
	if err := e.ExportSpans(context.Background(), endedSpans(t, 1)); err == nil {
		t.Error("ExportSpans succeeded against a collector that answers 503")
	}
	if reqs, _ := down.got(); len(reqs) != exportAttempts {
		t.Errorf("%d attempts, want %d", len(reqs), exportAttempts)
	}

	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.ExportSpans(context.Background(), endedSpans(t, 1)); !errors.Is(err, errStopped) {
		t.Errorf("after Shutdown: %v", err)
	}
}

// endedSpans returns n ended spans, from a provider that keeps them.
func endedSpans(t *testing.T, n int) []sdktrace.ReadOnlySpan {
	t.Helper()
	exp := &keep{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	for range n {
		_, s := tp.Tracer("test").Start(context.Background(), "span")
		s.End()
	}
	return exp.spans
}

type keep struct{ spans []sdktrace.ReadOnlySpan }

func (k *keep) ExportSpans(_ context.Context, s []sdktrace.ReadOnlySpan) error {
	k.spans = append(k.spans, s...)
	return nil
}
func (k *keep) Shutdown(context.Context) error { return nil }

func TestEndpointFromEnv(t *testing.T) {
	if got, err := endpointFromEnv(); err != nil || got != "http://localhost:4318/v1/traces" {
		t.Errorf("default = %q, %v", got, err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example:4318/")
	if got, _ := endpointFromEnv(); got != "https://otel.example:4318/v1/traces" {
		t.Errorf("from OTEL_EXPORTER_OTLP_ENDPOINT = %q", got)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://otel.example/custom/path")
	if got, _ := endpointFromEnv(); got != "https://otel.example/custom/path" {
		t.Errorf("from OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = %q, want it as is", got)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "otel:4317")
	if _, err := endpointFromEnv(); err == nil {
		t.Error("an endpoint without a scheme was accepted")
	}
}

func TestExporterEnvErrors(t *testing.T) {
	for name, env := range map[string][2]string{
		"timeout":     {"OTEL_EXPORTER_OTLP_TIMEOUT", "10s"},
		"compression": {"OTEL_EXPORTER_OTLP_COMPRESSION", "zstd"},
		"certificate": {"OTEL_EXPORTER_OTLP_CERTIFICATE", "testdata/missing.pem"},
		"client key":  {"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "testdata/missing.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			if _, err := newExporter("http://127.0.0.1:1/v1/traces", ""); err == nil {
				t.Errorf("%s=%s was accepted", env[0], env[1])
			}
		})
	}
	t.Run("timeout in ms", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "2500")
		e, err := newExporter("http://127.0.0.1:1/v1/traces", "")
		if err != nil || e.timeout != 2500*time.Millisecond {
			t.Errorf("timeout = %v, %v", e.timeout, err)
		}
	})
}
