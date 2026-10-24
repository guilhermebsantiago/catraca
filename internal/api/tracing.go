package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation scope of the server's spans.
const tracerName = "github.com/guilhermebsantiago/catraca/internal/api"

// traceContext reads the W3C traceparent and tracestate headers. Baggage is
// not read: it is free-form, and could carry what a trace must not.
var traceContext propagation.TraceContext

// untraced are the paths probes and scrapers poll every few seconds; a
// trace of each would bury the ones worth reading.
var untraced = map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true}

// startSpan starts the server span of r, as a child of the trace its
// traceparent header names, if any. The span is named after the route once
// it is known; see endSpan. Nothing about the client, such as its address,
// is recorded.
func (s *Server) startSpan(ctx context.Context, r *http.Request, ri *reqInfo) context.Context {
	ctx = traceContext.Extract(ctx, propagation.HeaderCarrier(r.Header))
	ctx, ri.span = s.tracer.Start(ctx, r.Method, trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", r.Method)))
	return ctx
}

// endSpan ends the request's span with the route, the status and what the
// handlers annotated. A 5xx is an error of the server; a 4xx is the
// client's, and leaves the span's status unset.
func endSpan(ri *reqInfo, status int) {
	if ri.route != "unmatched" {
		ri.span.SetName(ri.route)
		_, path, _ := strings.Cut(ri.route, " ")
		ri.span.SetAttributes(attribute.String("http.route", path))
	}
	ri.span.SetAttributes(
		attribute.Int("http.response.status_code", status),
		attribute.String("catraca.request_id", ri.id),
	)
	if ri.client != "" {
		ri.span.SetAttributes(attribute.String("catraca.client", ri.client))
	}
	if status >= 500 {
		ri.span.SetStatus(codes.Error, http.StatusText(status))
	}
	ri.span.End()
}

// spanAttribute converts an access log attribute that a handler annotated,
// such as the decision id or the action, to a span attribute.
func spanAttribute(a slog.Attr) attribute.KeyValue {
	key := "catraca." + a.Key
	switch v := a.Value; v.Kind() {
	case slog.KindBool:
		return attribute.Bool(key, v.Bool())
	case slog.KindInt64:
		return attribute.Int64(key, v.Int64())
	case slog.KindFloat64:
		return attribute.Float64(key, v.Float64())
	default:
		return attribute.String(key, v.String())
	}
}

// observeTraced observes v with the trace of sc as its exemplar when sc was
// sampled, so a slow bucket links to a trace that was kept.
func observeTraced(o prometheus.Observer, v float64, sc trace.SpanContext) {
	if eo, ok := o.(prometheus.ExemplarObserver); ok && sc.IsSampled() {
		eo.ObserveWithExemplar(v, prometheus.Labels{"trace_id": sc.TraceID().String()})
		return
	}
	o.Observe(v)
}
