# Changelog

Notable changes to Catraca. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions will
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from the
first tagged release. What may change before 1.0, and how a change is
announced, is in [docs/compatibility.md](docs/compatibility.md).

## [Unreleased]

Everything since the public launch on 2026-10-15
([b326e38](https://github.com/guilhermebsantiago/catraca/commit/b326e38)):
three waves of reliability work, then fixes to the TypeScript client and
the docs.

### Added

- **Hooks:** each hook is delivered from its own lane, with its own
  `concurrency`, `max_attempts` and `max_age`, so a slow receiver cannot
  hold up the others; `outbox.workers` sizes the pool they share, and
  `engine.dispatch_timeout` bounds how long a decision waits for its
  effects to be written. `catraca outbox list`, `retry` and `stats` show
  and redrive deliveries.
- **Secret scanning:** leaked-key reports are stored in the audit database
  before GitHub is answered, and processed from there with leases and
  retries. `catraca secretscan list` and `retry` show and requeue them.
- **Load:** a circuit breaker around the store (`engine.breaker`) skips it
  while it keeps failing, and adaptive admission control
  (`server.max_inflight`, `inflight_wait`, `inflight_limit`) bounds the
  decisions in flight and decides the rest at once without the store.
- **Idempotency:** an event with an id counts once per id for
  `engine.dedupe_ttl` (10 minutes by default), so a retried send does not
  count twice.
- **Lifecycle:** an optional admin listener (`server.admin_addr`) for
  `/healthz`, `/readyz` and `/metrics`; a drain on SIGTERM
  (`server.drain_delay`) before shutting down; `/readyz?verbose` and
  `catraca_dependency_up` report Redis and the audit database.
- **Store:** Redis Sentinel and Cluster (`store.redis.mode`).
- **Audit log:** retention (`audit.retention`, `audit.labeled_retention`)
  and connection pool limits.
- **Rulesets:** each instance reloads the ruleset when its file changes
  (`rules.watch_interval`), and `gate.on_load` holds in shadow mode a rule
  that would newly enforce without passing the precision gate.
- **Secret rotation:** `previous_secrets` on every shared secret and
  `previous_tokens` on every API token, for rotations without a gap;
  [docs/rotation.md](docs/rotation.md) is the runbook. The access log marks
  requests made with a previous token.
- **Observability:** latency histograms for store calls, audit writes,
  webhook attempts and leaked-key reports; seven SLOs with recording rules,
  burn-rate alerts and a Grafana dashboard ([docs/slo.md](docs/slo.md));
  optional OpenTelemetry tracing over OTLP/HTTP
  ([docs/tracing.md](docs/tracing.md)).
- **Releases:** binaries and a multi-arch image built by GoReleaser from
  `v*` tags, with checksums, SBOMs, build provenance and a cosign
  signature. Dependabot, CodeQL, the OpenSSF Scorecard and govulncheck run
  in CI.
- **Tests:** fault scenarios that break Redis, Postgres, webhook receivers
  and the resolver mid-run ([docs/faults.md](docs/faults.md)); fuzz targets
  for every parser, signature and endpoint, run in CI; fuzzers that check
  the memory and Redis stores agree.
- **Docs:** this changelog, and [docs/compatibility.md](docs/compatibility.md)
  on what is stable before 1.0.
- **Kubernetes:** a Helm chart in `deploy/helm/catraca`, with the probes on
  the admin port, the ruleset in a ConfigMap that reloads without a
  restart and secrets from an existing Secret
  ([docs/kubernetes.md](docs/kubernetes.md)).

### Changed

- **TypeScript client:** `decide` and `record` fail open by default, as
  the docs said they did: when Catraca is unavailable they return an
  allow decision with `fail_open` set. `failOpen: false` makes them throw
  instead.
- **API:** the routes that read or label decisions answer an audit
  database error with `503 unavailable` and `Retry-After`, not
  `500 internal`; `503 audit_unavailable` carries `Retry-After` too.
- **API:** the feedback endpoints answer `503` when an event could not be
  counted, so the provider sends it again, and the secret scanning
  endpoint answers GitHub only once the reports are stored.
- **Events:** an event dated more than `engine.max_event_age` (168 hours)
  in the past is refused with `400 invalid_event`, and one more than
  `engine.max_future_skew` (5 seconds) ahead takes Catraca's clock; sizes
  are bounded before events reach the counters.
- **Readiness:** `/readyz` depends only on the server's own state, so a
  failing dependency no longer takes every instance out of the load
  balancer at once.
- **Server:** it starts and serves decisions while the audit database is
  unreachable, and opens it when it can.
- **Store:** Redis calls are never retried, since a resent script can
  count an event twice.
- **Configuration:** `catraca.example.yaml` leaves its `revoke_key` hook
  commented out, so the quick start no longer retries deliveries to a
  placeholder URL.
- **Build:** Go 1.26.10, which fixes standard library vulnerabilities
  govulncheck found reachable.

### Fixed

- A decision the audit database refused no longer loses its whole batch.
- A read or label sent right after a decision's response finds the
  decision.
- A decision no longer waits seconds for a slow outbox write: its effects
  have a dispatch budget of their own.
- The leaked-key write of a `key_leak` event is bounded by the engine
  deadline.
- Claims of the outbox and the leaked-key queue give up after 10 seconds
  on a connection the network dropped, instead of stopping every delivery.
- A client no longer gets a kept-alive connection after `/readyz` reports
  draining.
- `signature.Verify` refuses a header with two `t` values even when one is
  empty.
- A normalized event stays within the size limits that validation checked.
- The memory store keeps a first-seen record written late, as Redis does.
- docs/api.md said `retry_after` is in nanoseconds; it is whole seconds.
  docs/design.md's route table lacked `GET /v1/rules/{id}/review`, and
  docs/signals.md called the first-seen retention configurable.

[Unreleased]: https://github.com/guilhermebsantiago/catraca/compare/b326e38...HEAD
