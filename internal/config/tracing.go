package config

import (
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/tracing"
)

// Tracing configures OpenTelemetry tracing, which is off unless Enabled.
// Settings left out are read from the standard OTEL_* environment variables
// where there is one, then take their defaults; see package tracing.
type Tracing struct {
	// Enabled turns tracing on. OTEL_SDK_DISABLED=true turns it off again.
	Enabled bool `yaml:"enabled"`
	// Endpoint is the OTLP/HTTP URL spans are sent to, such as
	// http://otel-collector:4318; a URL without a path gets /v1/traces.
	// Unset, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or
	// OTEL_EXPORTER_OTLP_ENDPOINT, else http://localhost:4318.
	Endpoint string `yaml:"endpoint"`
	// SampleRatio is the share of traces kept among those that start at
	// Catraca, from 0 to 1; a request whose traceparent says its caller
	// kept the trace is always traced. Unset, OTEL_TRACES_SAMPLER and
	// OTEL_TRACES_SAMPLER_ARG, else 0.1.
	SampleRatio *float64 `yaml:"sample_ratio"`
	// ServiceName is the spans' service.name. Unset, OTEL_SERVICE_NAME,
	// else "catraca".
	ServiceName string `yaml:"service_name"`
}

// Options returns the tracing options the section describes. The caller
// sets the version and the logger.
func (t Tracing) Options() tracing.Options {
	return tracing.Options{Endpoint: t.Endpoint, SampleRatio: t.SampleRatio, ServiceName: t.ServiceName}
}

func (v *validator) tracing(t Tracing) {
	if t.Endpoint != "" {
		if _, err := tracing.EndpointURL(t.Endpoint); err != nil {
			v.add("tracing.endpoint", "want an http or https URL, such as http://otel-collector:4318, got %q", t.Endpoint)
		}
	}
	if r := t.SampleRatio; r != nil && (*r < 0 || *r > 1) {
		v.add("tracing.sample_ratio", "must be from 0 to 1, got %g", *r)
	}
	if v.isSet("tracing.service_name") && strings.TrimSpace(t.ServiceName) == "" {
		v.add("tracing.service_name", "is empty; leave it out to use OTEL_SERVICE_NAME or catraca")
	}
}
