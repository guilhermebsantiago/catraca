# Tracing

Catraca can trace its work with [OpenTelemetry](https://opentelemetry.io)
and send the spans to a collector over OTLP/HTTP. It is off by default, and
off it costs nothing: the code that would make spans checks for a tracer
and finds none ([benchmarks](benchmark.md#tracing)).

```yaml
tracing:
  enabled: true
  endpoint: http://otel-collector:4318
  sample_ratio: 0.1
```

[`tracing`](config.md#tracing) in the configuration reference has every
field.

## What is traced

| span | kind | what it covers |
|---|---|---|
| `POST /v1/decide`, `POST /v1/events`, ... | server | an HTTP request, named after its route; probes and scrapes (`/healthz`, `/readyz`, `/metrics`) are not traced |
| `catraca.decide` | internal | a decision, from any route, feedback endpoint or leaked-key report |
| `catraca.store.observe`, `catraca.store.mark_leaked` | client | the decision's calls to the store, under its deadline; calls its breaker skipped make none |
| `catraca.hooks.enqueue` | internal | the outbox write of a decision's effects, in the decision's trace |
| `catraca.hooks.deliver` | client | an attempt at an effect webhook, starting a trace of its own |
| `catraca.audit.write_batch` | client | a batch of decisions written to the audit database, starting a trace of its own |
| `catraca.secretscan.process_report` | consumer | an attempt at a leaked-key report, starting a trace of its own |
| `catraca.secretscan.resolve` | client | the resolver call of that attempt, followed by its `catraca.decide` |

A request that carries a W3C `traceparent` header continues that trace, so
a platform that traces its sends sees Catraca's decision inside them.
Deliveries, audit batches and leaked-key reports are worked on in the
background, after the request that caused them was answered, maybe by
another instance, so each attempt starts a trace of its own; the decision
id in its attributes leads back to the decision.

### No personal data

Spans say what was decided and why, never about whom. They carry the event
type, the decision id and action, the rules that matched, errored or
matched in shadow, whether the decision was degraded, uncounted or a
duplicate, the ruleset version, the route, the status, the request id and
the name of the token the client used. They never carry an account id, an
API key id, an IP address, an email address, a subject, a link, a leaked
token or the URL it was found at. An error's text, which may quote any of
those, is replaced by its kind, such as `invalid event` or `timeout`; the
log has the details.

## Propagation

Catraca sends the W3C `traceparent` header of the span it is in with every
request it makes, so receivers that trace can join:

- each [effect webhook](hooks.md#the-request) attempt, with the attempt's
  span;
- each [resolver](secret-scanning.md#the-resolver-contract) call, with the
  resolve span.

The header is sent only while tracing is on. Baggage is neither read nor
sent: it is free-form, and could carry what a trace must not.

## Sampling

`sample_ratio` is the share of traces kept among those that start at
Catraca: requests without a `traceparent`, and the background work above.
A request whose `traceparent` says the caller kept its trace is always
traced, and one whose caller dropped it never is, so a trace is either
whole or absent. The default, 0.1, keeps one in ten; at a few thousand
decisions a second, a collector that samples by its own rules (tail
sampling) may want all of them, and a ratio of 0 traces only what callers
trace.

## Logs and metrics

With tracing on:

- every access log line has the request's `trace_id` and `span_id`, sampled
  or not ([logs](api.md#logs)), so a log line leads to its trace, and the
  platform's trace id to Catraca's log line;
- the latency histograms (`catraca_http_request_duration_seconds`,
  `catraca_decision_duration_seconds`, `catraca_store_call_duration_seconds`,
  `catraca_audit_write_duration_seconds`, the webhook and leaked-key ones)
  keep, in each bucket, the trace of a sampled event that fell in it as an
  exemplar, labeled `trace_id`. `/metrics` serves them in the OpenMetrics
  format, which Prometheus asks for; it stores them with
  `--enable-feature=exemplar-storage`, and Grafana shows them on the
  latency panels of [the dashboard](../deploy/grafana/catraca.json).

Without tracing, `/metrics` serves the Prometheus text format as before.

## Environment variables

The standard OpenTelemetry variables apply where the configuration leaves
a setting out, and for the settings it does not have:

| variable | |
|---|---|
| `OTEL_SDK_DISABLED` | `true` turns tracing off, whatever `tracing.enabled` says |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` | the collector, when `tracing.endpoint` is not set; the first is the full URL, the second gets `/v1/traces` |
| `OTEL_EXPORTER_OTLP_HEADERS`, `_TIMEOUT`, `_COMPRESSION`, `_CERTIFICATE`, `_CLIENT_CERTIFICATE`, `_CLIENT_KEY` (and their `_TRACES_` forms) | headers such as an API key, the export timeout, `gzip`, and TLS |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | the sampler, when `tracing.sample_ratio` is not set |
| `OTEL_SERVICE_NAME` | the service name, when `tracing.service_name` is not set |
| `OTEL_RESOURCE_ATTRIBUTES` | more resource attributes, such as `deployment.environment.name=prod` |
| `OTEL_BSP_*` | the batch span processor: queue size, batch size, delay |

## OTLP over HTTP

Spans go to the collector with OTLP over HTTP (protobuf), port 4318 by
convention, rather than gRPC: plain HTTPS works through the proxies, load
balancers and TLS setups a platform already has, and an API key in a header
is all most hosted backends need. The OpenTelemetry Collector, Jaeger,
Tempo and most vendors accept it.

Spans are batched and sent in the background. A collector that is down or
slow costs dropped spans and a warning in the log, at most once a minute,
never a decision. On shutdown, the server sends what is left, within
`server.shutdown_timeout`.
