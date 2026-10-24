package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
)

// The trace and the span a platform's request comes from.
const (
	parentTraceID   = "4bf92f3577b34da6a3ce929d0e0e4736"
	parentSpanID    = "00f067aa0ba902b7"
	sampledParent   = "00-" + parentTraceID + "-" + parentSpanID + "-01"
	unsampledParent = "00-" + parentTraceID + "-" + parentSpanID + "-00"
)

type tracedServer struct {
	s     *Server
	spans *tracetest.SpanRecorder
	logs  *bytes.Buffer
	reg   *prometheus.Registry
}

// newTracedServer returns a server that traces, with tracing on when
// traced is set, around a decider that answers allow, or err.
func newTracedServer(t *testing.T, traced bool, err error) tracedServer {
	t.Helper()
	ts := tracedServer{spans: tracetest.NewSpanRecorder(), logs: &bytes.Buffer{}, reg: prometheus.NewRegistry()}
	d := deciderFunc(func(context.Context, event.Event) (decision.Decision, error) {
		return decision.Decision{ID: "01M50Q9TE1EPGZCTSX7N6NPC78", Action: decision.Allow}, err
	})
	ts.s = newTestServer(t, d, slog.New(slog.NewJSONHandler(ts.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), func(o *Options) {
		o.Registerer = ts.reg
		o.Gatherer = ts.reg
		if traced {
			o.TracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(ts.spans))
		}
	})
	return ts
}

func (ts tracedServer) post(path, traceparent string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"type":"send","account_id":"acct_1"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	if traceparent != "" {
		req.Header.Set("traceparent", traceparent)
	}
	rec := httptest.NewRecorder()
	ts.s.ServeHTTP(rec, req)
	return rec
}

// accessLog returns the last access log line.
func (ts tracedServer) accessLog(t *testing.T) map[string]any {
	t.Helper()
	var last map[string]any
	for line := range strings.Lines(ts.logs.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if m["msg"] == "request" {
			last = m
		}
	}
	if last == nil {
		t.Fatalf("no access log line in %s", ts.logs)
	}
	return last
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := map[attribute.Key]attribute.Value{}
	for _, kv := range s.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

func TestRequestContinuesTheCallersTrace(t *testing.T) {
	ts := newTracedServer(t, true, nil)
	if rec := ts.post("/v1/decide", sampledParent); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	spans := ts.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("%d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name() != "POST /v1/decide" || s.SpanKind() != trace.SpanKindServer {
		t.Errorf("span %q of kind %v, want POST /v1/decide, server", s.Name(), s.SpanKind())
	}
	if s.SpanContext().TraceID().String() != parentTraceID || s.Parent().SpanID().String() != parentSpanID || !s.Parent().IsRemote() {
		t.Errorf("span is not a child of the traceparent: trace %s, parent %s", s.SpanContext().TraceID(), s.Parent().SpanID())
	}
	a := spanAttrs(s)
	if a["http.route"].AsString() != "/v1/decide" || a["http.request.method"].AsString() != "POST" ||
		a["http.response.status_code"].AsInt64() != 200 || a["catraca.client"].AsString() != "b" ||
		a["catraca.decision_id"].AsString() != "01M50Q9TE1EPGZCTSX7N6NPC78" || a["catraca.action"].AsString() != "allow" {
		t.Errorf("attributes = %v", s.Attributes())
	}
	for _, kv := range s.Attributes() {
		if strings.Contains(string(kv.Key), "address") || strings.Contains(string(kv.Key), "user_agent") {
			t.Errorf("the span records the client: %s", kv.Key)
		}
	}

	line := ts.accessLog(t)
	if line["trace_id"] != parentTraceID || line["span_id"] != s.SpanContext().SpanID().String() {
		t.Errorf("access log trace_id %v, span_id %v; want %s and the server span's %s",
			line["trace_id"], line["span_id"], parentTraceID, s.SpanContext().SpanID())
	}
}

// A trace the caller did not keep is not kept here either, but its log line
// still names it.
func TestUnsampledTraceIsLoggedNotRecorded(t *testing.T) {
	ts := newTracedServer(t, true, nil)
	ts.post("/v1/decide", unsampledParent)
	if n := len(ts.spans.Ended()); n != 0 {
		t.Errorf("%d spans recorded for an unsampled trace", n)
	}
	if line := ts.accessLog(t); line["trace_id"] != parentTraceID {
		t.Errorf("access log trace_id = %v, want %s", line["trace_id"], parentTraceID)
	}
}

func TestServerErrorFailsTheSpan(t *testing.T) {
	ts := newTracedServer(t, true, errors.New("store: catraca:acct:acct_1 is gone"))
	if rec := ts.post("/v1/decide", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	s := ts.spans.Ended()[0]
	if s.Status().Code != codes.Error || s.Status().Description != "Service Unavailable" {
		t.Errorf("status = %+v", s.Status())
	}
	// A new trace starts here when the caller sent none.
	if s.Parent().IsValid() {
		t.Errorf("span has parent %s without a traceparent", s.Parent().SpanID())
	}
}

func TestProbesAndScrapesAreNotTraced(t *testing.T) {
	ts := newTracedServer(t, true, nil)
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		ts.s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if n := len(ts.spans.Ended()); n != 0 {
		t.Errorf("%d spans for probes and scrapes", n)
	}
}

func TestNoTraceInLogsWithTracingOff(t *testing.T) {
	ts := newTracedServer(t, false, nil)
	ts.post("/v1/decide", sampledParent)
	line := ts.accessLog(t)
	if _, ok := line["trace_id"]; ok {
		t.Errorf("access log has a trace_id with tracing off: %v", line)
	}
}

// With tracing on, Prometheus's request for OpenMetrics gets it, with the
// trace of a sampled request as an exemplar; with tracing off, the text
// format as before.
func TestMetricsCarryExemplarsWithTracingOn(t *testing.T) {
	for _, traced := range []bool{true, false} {
		ts := newTracedServer(t, traced, nil)
		ts.post("/v1/decide", sampledParent)
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Accept", "application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5")
		rec := httptest.NewRecorder()
		ts.s.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		openMetrics := strings.HasPrefix(rec.Header().Get("Content-Type"), "application/openmetrics-text")
		exemplar := strings.Contains(string(body), `# {trace_id="`+parentTraceID+`"}`)
		if openMetrics != traced || exemplar != traced {
			t.Errorf("tracing %v: OpenMetrics %v, exemplar %v; want both %v", traced, openMetrics, exemplar, traced)
		}
	}
}
