package tracing

import (
	"math"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// The conversion of spans to OTLP below follows the OpenTelemetry Go
// exporter's (otlptrace/internal/tracetransform), which cannot be imported.

// resourceSpans groups spans by resource and instrumentation scope, as an
// OTLP export request holds them, keeping their order within each group.
func resourceSpans(spans []sdktrace.ReadOnlySpan) []*tracepb.ResourceSpans {
	type scopeKey struct {
		res   attribute.Distinct
		scope instrumentation.Scope
	}
	var out []*tracepb.ResourceSpans
	byResource := map[attribute.Distinct]*tracepb.ResourceSpans{}
	byScope := map[scopeKey]*tracepb.ScopeSpans{}
	for _, s := range spans {
		if s == nil {
			continue
		}
		res := s.Resource()
		rkey := resourceKey(res)
		rs, ok := byResource[rkey]
		if !ok {
			rs = &tracepb.ResourceSpans{Resource: otlpResource(res), SchemaUrl: res.SchemaURL()}
			byResource[rkey] = rs
			out = append(out, rs)
		}
		scope := s.InstrumentationScope()
		// The scope's attributes are a Set, not comparable as a map key;
		// its name, version and schema tell scopes apart.
		skey := scopeKey{rkey, instrumentation.Scope{Name: scope.Name, Version: scope.Version, SchemaURL: scope.SchemaURL}}
		ss, ok := byScope[skey]
		if !ok {
			ss = &tracepb.ScopeSpans{
				Scope: &commonpb.InstrumentationScope{
					Name: scope.Name, Version: scope.Version, Attributes: keyValues(scope.Attributes.ToSlice()),
				},
				SchemaUrl: scope.SchemaURL,
			}
			byScope[skey] = ss
			rs.ScopeSpans = append(rs.ScopeSpans, ss)
		}
		ss.Spans = append(ss.Spans, span(s))
	}
	return out
}

func resourceKey(r *resource.Resource) attribute.Distinct {
	if r == nil {
		return attribute.Distinct{}
	}
	return r.Equivalent()
}

func otlpResource(r *resource.Resource) *resourcepb.Resource {
	if r == nil {
		return &resourcepb.Resource{}
	}
	return &resourcepb.Resource{Attributes: keyValues(r.Attributes())}
}

func span(s sdktrace.ReadOnlySpan) *tracepb.Span {
	sc := s.SpanContext()
	tid, sid := sc.TraceID(), sc.SpanID()
	out := &tracepb.Span{
		TraceId:                tid[:],
		SpanId:                 sid[:],
		TraceState:             sc.TraceState().String(),
		Flags:                  flags(sc.TraceFlags(), s.Parent()),
		Name:                   s.Name(),
		Kind:                   kind(s.SpanKind()),
		StartTimeUnixNano:      unixNano(s.StartTime().UnixNano()),
		EndTimeUnixNano:        unixNano(s.EndTime().UnixNano()),
		Attributes:             keyValues(s.Attributes()),
		DroppedAttributesCount: count(s.DroppedAttributes()),
		DroppedEventsCount:     count(s.DroppedEvents()),
		DroppedLinksCount:      count(s.DroppedLinks()),
		Status:                 status(s.Status()),
	}
	if psid := s.Parent().SpanID(); psid.IsValid() {
		out.ParentSpanId = psid[:]
	}
	for _, e := range s.Events() {
		out.Events = append(out.Events, &tracepb.Span_Event{
			TimeUnixNano:           unixNano(e.Time.UnixNano()),
			Name:                   e.Name,
			Attributes:             keyValues(e.Attributes),
			DroppedAttributesCount: count(e.DroppedAttributeCount),
		})
	}
	for _, l := range s.Links() {
		ltid, lsid := l.SpanContext.TraceID(), l.SpanContext.SpanID()
		out.Links = append(out.Links, &tracepb.Span_Link{
			TraceId:                ltid[:],
			SpanId:                 lsid[:],
			TraceState:             l.SpanContext.TraceState().String(),
			Attributes:             keyValues(l.Attributes),
			DroppedAttributesCount: count(l.DroppedAttributeCount),
			Flags:                  flags(l.SpanContext.TraceFlags(), l.SpanContext),
		})
	}
	return out
}

// flags packs the W3C trace flags in the low byte and whether the parent,
// or a link's span, is remote in the two bits above.
func flags(tf trace.TraceFlags, other trace.SpanContext) uint32 {
	f := uint32(tf) | uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK)
	if other.IsRemote() {
		f |= uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK)
	}
	return f
}

func kind(k trace.SpanKind) tracepb.Span_SpanKind {
	switch k {
	case trace.SpanKindInternal:
		return tracepb.Span_SPAN_KIND_INTERNAL
	case trace.SpanKindServer:
		return tracepb.Span_SPAN_KIND_SERVER
	case trace.SpanKindClient:
		return tracepb.Span_SPAN_KIND_CLIENT
	case trace.SpanKindProducer:
		return tracepb.Span_SPAN_KIND_PRODUCER
	case trace.SpanKindConsumer:
		return tracepb.Span_SPAN_KIND_CONSUMER
	}
	return tracepb.Span_SPAN_KIND_UNSPECIFIED
}

func status(s sdktrace.Status) *tracepb.Status {
	switch s.Code {
	case codes.Ok:
		return &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK}
	case codes.Error:
		return &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: s.Description}
	}
	return &tracepb.Status{Code: tracepb.Status_STATUS_CODE_UNSET}
}

func keyValues(kvs []attribute.KeyValue) []*commonpb.KeyValue {
	if len(kvs) == 0 {
		return nil
	}
	out := make([]*commonpb.KeyValue, 0, len(kvs))
	for _, kv := range kvs {
		out = append(out, &commonpb.KeyValue{Key: string(kv.Key), Value: anyValue(kv.Value)})
	}
	return out
}

func anyValue(v attribute.Value) *commonpb.AnyValue {
	av := &commonpb.AnyValue{}
	switch v.Type() {
	case attribute.BOOL:
		av.Value = &commonpb.AnyValue_BoolValue{BoolValue: v.AsBool()}
	case attribute.INT64:
		av.Value = &commonpb.AnyValue_IntValue{IntValue: v.AsInt64()}
	case attribute.FLOAT64:
		av.Value = &commonpb.AnyValue_DoubleValue{DoubleValue: v.AsFloat64()}
	case attribute.STRING:
		av.Value = &commonpb.AnyValue_StringValue{StringValue: v.AsString()}
	case attribute.BYTESLICE:
		av.Value = &commonpb.AnyValue_BytesValue{BytesValue: v.AsByteSlice()}
	case attribute.BOOLSLICE:
		av.Value = array(v.AsBoolSlice(), func(b bool) attribute.Value { return attribute.BoolValue(b) })
	case attribute.INT64SLICE:
		av.Value = array(v.AsInt64Slice(), attribute.Int64Value)
	case attribute.FLOAT64SLICE:
		av.Value = array(v.AsFloat64Slice(), attribute.Float64Value)
	case attribute.STRINGSLICE:
		av.Value = array(v.AsStringSlice(), attribute.StringValue)
	case attribute.SLICE:
		av.Value = array(v.AsSlice(), func(v attribute.Value) attribute.Value { return v })
	case attribute.MAP:
		av.Value = &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: keyValues(v.AsMap())}}
	}
	return av
}

func array[T any](xs []T, value func(T) attribute.Value) *commonpb.AnyValue_ArrayValue {
	vs := make([]*commonpb.AnyValue, len(xs))
	for i, x := range xs {
		vs[i] = anyValue(value(x))
	}
	return &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: vs}}
}

func unixNano(n int64) uint64 { return uint64(max(0, n)) }

// count converts a number of dropped attributes, events or links, which the
// SDK's limits keep far below the clamp.
func count(n int) uint32 { return uint32(max(0, min(n, math.MaxInt32))) }
