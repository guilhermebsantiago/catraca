package app_test

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// collector is an OTLP/HTTP endpoint that keeps the spans it is sent.
type collector struct {
	*httptest.Server
	mu       sync.Mutex
	paths    []string
	spans    []*tracepb.Span
	resource map[string]string
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{resource: map[string]string{}}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			body = zr
		}
		data, err := io.ReadAll(body)
		if err != nil {
			t.Error(err)
			return
		}
		rss, err := decodeExportRequest(data)
		if err != nil {
			t.Errorf("collector: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.paths = append(c.paths, r.URL.Path)
		for _, rs := range rss {
			for _, kv := range rs.GetResource().GetAttributes() {
				c.resource[kv.GetKey()] = kv.GetValue().GetStringValue()
			}
			for _, ss := range rs.GetScopeSpans() {
				c.spans = append(c.spans, ss.GetSpans()...)
			}
		}
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.Close)
	return c
}

// decodeExportRequest reads an OTLP ExportTraceServiceRequest, whose one
// field, 1, holds each ResourceSpans.
func decodeExportRequest(b []byte) ([]*tracepb.ResourceSpans, error) {
	var out []*tracepb.ResourceSpans
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num != 1 || typ != protowire.BytesType {
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		rs := &tracepb.ResourceSpans{}
		if err := proto.Unmarshal(v, rs); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, nil
}

// byName returns the spans the collector got, by name.
func (c *collector) byName() map[string][]*tracepb.Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := map[string][]*tracepb.Span{}
	for _, s := range c.spans {
		m[s.GetName()] = append(m[s.GetName()], s)
	}
	return m
}

func spanAttr(s *tracepb.Span, key string) string {
	for _, kv := range s.GetAttributes() {
		if kv.GetKey() == key {
			v := kv.GetValue()
			if v.GetStringValue() != "" {
				return v.GetStringValue()
			}
			return fmt.Sprint(v.GetIntValue())
		}
	}
	return ""
}

// TestTracingEndToEnd runs a server that traces every request into a fake
// collector: the trace a platform's traceparent starts goes through the
// HTTP layer, the decision and the store; the access log names it; the
// metrics carry it as an exemplar; and the spans reach the collector over
// OTLP/HTTP when the server closes.
func TestTracingEndToEnd(t *testing.T) {
	t.Parallel()
	c := newCollector(t)
	h := newHarness(t, options{extra: fmt.Sprintf(`
tracing:
  enabled: true
  endpoint: %s
  sample_ratio: 1
  service_name: catraca-test
`, c.URL)})

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	ev := send("acct_person_7", "maria@shop.example")
	r := h.do("POST", "/v1/decide", token, ev, "traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
	if r.status != http.StatusOK {
		t.Fatalf("decide: %d %s", r.status, r.body)
	}
	// A key_leak calls for revoke_key, so a webhook is queued and sent.
	leak := map[string]any{"type": "key_leak", "account_id": "acct_person_7", "api_key_id": "key_person_7"}
	if r := h.do("POST", "/v1/events", token, leak); r.status != http.StatusAccepted {
		t.Fatalf("key_leak: %d %s", r.status, r.body)
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(h.hook.calls()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the hook was never called")
		}
		time.Sleep(10 * time.Millisecond)
	}

	var line map[string]any
	for l := range strings.Lines(h.logs.String()) {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "request" && m["route"] == "POST /v1/decide" {
			line = m
		}
	}
	if line["trace_id"] != traceID || line["span_id"] == nil {
		t.Errorf("access log line %v, want trace_id %s and a span_id", line, traceID)
	}

	m := h.do("GET", "/metrics", "", nil, "Accept", "application/openmetrics-text;version=1.0.0")
	if !strings.Contains(string(m.body), `catraca_decision_duration_seconds_bucket`) ||
		!strings.Contains(string(m.body), `# {trace_id="`+traceID+`"}`) {
		t.Errorf("metrics have no exemplar for trace %s", traceID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.app.Close(ctx); err != nil {
		t.Fatal(err)
	}

	spans := c.byName()
	for _, name := range []string{"POST /v1/decide", "POST /v1/events", "catraca.decide", "catraca.store.observe",
		"catraca.store.mark_leaked", "catraca.hooks.enqueue", "catraca.hooks.deliver", "catraca.audit.write_batch"} {
		if len(spans[name]) == 0 {
			names := make([]string, 0, len(spans))
			for n := range spans {
				names = append(names, n)
			}
			slices.Sort(names)
			t.Errorf("the collector got no %s span; it got %v", name, names)
		}
	}
	var decide *tracepb.Span
	for _, s := range spans["catraca.decide"] {
		if hex.EncodeToString(s.GetTraceId()) == traceID {
			decide = s
		}
	}
	if decide == nil {
		t.Fatalf("no catraca.decide span in trace %s", traceID)
	}
	if spanAttr(decide, "catraca.event.type") != "send" || spanAttr(decide, "catraca.decision.action") != "allow" {
		t.Errorf("decide span attributes: %v", decide.GetAttributes())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resource["service.name"] != "catraca-test" || c.resource["service.version"] != "test" {
		t.Errorf("resource %v, want service catraca-test version test", c.resource)
	}
	for _, p := range c.paths {
		if p != "/v1/traces" {
			t.Errorf("spans were posted to %s, want /v1/traces", p)
		}
	}
	for _, s := range c.spans {
		for _, kv := range s.GetAttributes() {
			v := kv.GetValue().String()
			if strings.Contains(v, "acct_person_7") || strings.Contains(v, "key_person_7") || strings.Contains(v, "maria") {
				t.Errorf("span %s: %s = %s", s.GetName(), kv.GetKey(), v)
			}
		}
	}
}
