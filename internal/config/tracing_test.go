package config

import (
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/tracing"
)

func TestTracingIsOffByDefault(t *testing.T) {
	cfg := mustParse(t, minimal, nil)
	if tr := cfg.Tracing; tr.Enabled || tr.Endpoint != "" || tr.SampleRatio != nil || tr.ServiceName != "" {
		t.Errorf("tracing = %+v, want everything left to the environment and off", tr)
	}
	if o := cfg.Tracing.Options(); o != (tracing.Options{}) {
		t.Errorf("Options() = %+v, want the zero value", o)
	}
}

func TestTracingConfig(t *testing.T) {
	cfg := mustParse(t, minimal+`
tracing:
  enabled: true
  endpoint: ${OTLP}
  sample_ratio: 0.25
  service_name: catraca-eu
`, map[string]string{"OTLP": "https://otel.internal:4318"})
	tr := cfg.Tracing
	if !tr.Enabled || tr.Endpoint != "https://otel.internal:4318" || tr.SampleRatio == nil || *tr.SampleRatio != 0.25 || tr.ServiceName != "catraca-eu" {
		t.Fatalf("tracing = %+v", tr)
	}
	o := tr.Options()
	if o.Endpoint != tr.Endpoint || o.SampleRatio != tr.SampleRatio || o.ServiceName != "catraca-eu" {
		t.Errorf("Options() = %+v", o)
	}
}

// A ratio of 0 is a setting, not a request for the default: it keeps only
// the traces callers kept.
func TestTracingSampleRatioZero(t *testing.T) {
	cfg := mustParse(t, minimal+"tracing: {enabled: true, sample_ratio: 0}\n", nil)
	if r := cfg.Tracing.SampleRatio; r == nil || *r != 0 {
		t.Errorf("sample_ratio = %v, want 0", r)
	}
}

func TestTracingValidation(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"endpoint scheme", "tracing: {endpoint: 'otel:4317'}", `tracing.endpoint: want an http or https URL, such as http://otel-collector:4318, got "otel:4317"`},
		{"endpoint grpc", "tracing: {endpoint: 'grpc://otel:4317'}", "tracing.endpoint: want an http or https URL"},
		{"ratio above 1", "tracing: {sample_ratio: 1.5}", "tracing.sample_ratio: must be from 0 to 1, got 1.5"},
		{"ratio negative", "tracing: {sample_ratio: -0.1}", "tracing.sample_ratio: must be from 0 to 1, got -0.1"},
		{"ratio type", "tracing: {sample_ratio: half}", `tracing.sample_ratio: want a number, got "half"`},
		{"service name", "tracing: {service_name: ' '}", "tracing.service_name: is empty"},
		{"unknown field", "tracing: {exporter: otlp}", "tracing.exporter: unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireError(t, parseErrors(t, minimal+tt.yaml+"\n", nil), tt.want)
		})
	}
}
