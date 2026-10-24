# Service level objectives

What it means for Catraca to do its job, as numbers Prometheus can check:
seven service level indicators (SLIs), each with an objective (SLO) over
30 days, built on [Catraca's own metrics](api.md#get-metrics).
[`deploy/prometheus/rules.yaml`](../deploy/prometheus/rules.yaml) records
them and alerts on them, [`rules.test.yaml`](../deploy/prometheus/rules.test.yaml)
tests the alerts with `promtool`, and
[`deploy/grafana/catraca.json`](../deploy/grafana/catraca.json) is a
dashboard of them and of the metrics behind them.

| SLO | the SLI: the share of... | objective | budget, 30 days | alerts |
|---|---|---|---|---|
| [`decide-availability`](#decide-availability) | decisions answered, not failed (no 5xx) | 99.9% | 43 minutes of failing everything | page, ticket |
| [`decide-latency`](#decide-latency) | `POST /v1/decide` answered within 25 ms | 99% | 7.2 hours of slow everything | page, ticket |
| [`decide-completeness`](#decide-completeness) | decisions made with every signal | 99.5% | 3.6 hours of Redis down | page, ticket |
| [`feedback-acceptance`](#feedback-acceptance) | feedback events counted | 99.5% | 3.6 hours | page, ticket |
| [`webhook-freshness`](#webhook-freshness) | effect webhooks delivered within 60 s of the decision | 99% | 1 effect in 100 | ticket; the backlog pages |
| [`audit-completeness`](#audit-completeness) | decisions written to the audit log | 99.9% | 43 minutes | page, ticket |
| [`leak-processing`](#leak-processing) | leaked-key reports done within 5 minutes | 99% | 1 report in 100 | dead and waiting reports page |

Each is measured per Prometheus `job`, one Catraca deployment however many
instances it runs. A rule set like this one is a starting point: the
numbers fit the defaults (`engine.deadline` 10 ms, the default backoffs) and
a platform whose sends depend on Catraca; change them to fit yours, in the
rules and the tests together.

## Reading an objective

An objective of 99.9% over 30 days leaves an **error budget** of 0.1% of
the events in those 30 days: about 43 minutes, if every event failed for
that long. The **burn rate** is how fast the budget goes: at 1 it lasts
exactly 30 days, at 14.4 it is gone in two days. Each SLI is recorded as
an error ratio over several windows,
`catraca:slo_errors:ratio_rate<window>{job, slo}`, from 0 (no errors) to 1,
and the alerts compare those ratios with multiples of the budget.

The SLIs are measured by the server, so they leave out what never reaches
it: an instance that is down, a load balancer with no instance to send to,
the network in between. Watch `up` for the instances, and the load
balancer's own errors or a probe of `POST /v1/decide` from outside for the
rest. Nor do they say whether the decisions were right: that is the
[precision gate](audit.md#the-precision-gate)'s job.

## decide-availability

**SLI:** the share of `POST /v1/decide` and `POST /v1/events` requests
answered with a status below 500.

```promql
sum(rate(catraca_http_request_duration_seconds_count{route=~"POST /v1/(decide|events)", status=~"5.."}[1h]))
/ sum(rate(catraca_http_request_duration_seconds_count{route=~"POST /v1/(decide|events)"}[1h]))
```

**A degraded decision is available.** When Redis fails, is slow, its
breaker is open or the request was shed, Catraca still answers, within the
deadline, with the decision its rules make without the missing signals:
the fail-safe answer [the design](design.md) asks for, which the platform
acts on as on any other. Counting it as a failure would page for the
outages Catraca is built to ride out, and push operators to make rules fail
closed so that degraded decisions look better. Detection does suffer, so
degraded decisions have an objective of their own,
[decide-completeness](#decide-completeness).

A `4xx` is the caller's: an invalid event, a missing token. Every `5xx` is
a failure, including the `503`s Catraca answers on purpose (`no_ruleset`,
a key_leak the store did not take, a feedback event shed by admission
control) and those a caller retries: the event was not decided when it was
sent.

**Why 99.9%:** Catraca sits on the send path. A platform that waits for it
before each send should not have it fail more often than its own
dependencies; one that does not wait should still get an answer for nearly
every event. 43 minutes a month leaves room for a bad deploy or a ruleset
that does not load, caught and rolled back.

**What burns it:** a ruleset that does not load (`503 no_ruleset`, see
`CatracaNoRuleset`), key_leak events the store did not take, panics (logged
with their stack).

## decide-latency

**SLI:** the share of `POST /v1/decide` requests the server answers within
25 ms.

```promql
sum(rate(catraca_http_request_duration_seconds_bucket{route="POST /v1/decide", le="0.025"}[1h]))
/ sum(rate(catraca_http_request_duration_seconds_count{route="POST /v1/decide"}[1h]))
```

**Why 25 ms:** a decision's time is bounded by design. The store gets
`engine.deadline` (10 ms), the outbox write of effects the dispatch budget
(`engine.dispatch_timeout`, the deadline again), and the rest, the JSON,
the token, the rules, takes microseconds ([benchmarks](benchmark.md)). A
decision that takes more than 25 ms means Catraca itself stalled: starved
of CPU, paused for garbage collection, or waiting on its own host. Shed and
breaker-open decisions are fast, so overload does not burn this budget;
[decide-completeness](#decide-completeness) counts them.

If you change `engine.deadline` or `engine.dispatch_timeout`, move the
threshold to the first bucket of `catraca_http_request_duration_seconds`
above their sum plus a few milliseconds (0.025, 0.05, 0.1...): change
`le="0.025"` in the rules and the alerts' text.

**Why 99%:** nearly every decision lands under 5 ms; 1% leaves room for the
pauses of a shared host without paging for them. Only `/v1/decide` counts:
it is the one a send waits for.

**What burns it:** CPU limits too low for the traffic (throttling), memory
pressure and long GC pauses, a slow outbox write when decisions have
effects. `job:catraca_decision_duration_seconds:p99_rate5m` (the engine)
next to `job_route:catraca_http_request_duration_seconds:p99_rate5m` (the
whole request) tells the engine from the HTTP layer, and with
[tracing](tracing.md) on, an exemplar in the slow bucket is a trace of one
of them.

## decide-completeness

**SLI:** the share of decisions made with every signal, not degraded.

```promql
1 - sum(rate(catraca_degraded_decisions_total[1h])) / sum(rate(catraca_decisions_total[1h]))
```

Every decision counts: sends, feedback, account events and key leaks, from
every route.

**Why 99.5%:** a degraded decision lets abuse through that the rules would
have caught; 3.6 hours a month is about what a single Redis can be down or
saturated without anyone acting on it.

**What burns it:** Redis down (`CatracaDependencyDown`,
`CatracaStoreBreakerOpen`), Redis slower than the deadline
(`catraca_store_call_duration_seconds{result="timeout"}`), or more traffic
than Redis serves (`catraca_admission_shed_total`, and a low
`catraca_admission_limit`). The [benchmarks](benchmark.md#overload-and-outages)
show each.

## feedback-acceptance

**SLI:** the share of feedback events on `POST /v1/feedback`,
`/v1/feedback/ses` and `/v1/feedback/usesend` that were counted, out of
those counted, those that failed (`decide_failed`), those the store did not
take (`uncounted`, answered 503) and the requests admission control shed.

```promql
1 - (
  sum(rate(catraca_feedback_outcomes_total{outcome=~"decide_failed|uncounted"}[1h]))
  + sum(rate(catraca_admission_shed_total{route=~"POST /v1/feedback.*"}[1h]))
) / (
  sum(rate(catraca_feedback_outcomes_total{outcome=~"decided|decide_failed|uncounted"}[1h]))
  + sum(rate(catraca_admission_shed_total{route=~"POST /v1/feedback.*"}[1h]))
)
```

A bad signature, a malformed body or a notification without an account are
the sender's problems, with outcomes of their own
([feedback metrics](feedback.md#metrics)), and do not count. Feedback sent
to `POST /v1/events` counts under [availability](#decide-availability).

**Why 99.5%:** providers send a notification again after a 503, so a
failure is usually a delay. But not for long: SNS gives up after about a
minute by default ([details](feedback.md#amazon-ses)), and a bounce or a
complaint that never counts hides the abuse the bounce and complaint rate
rules look for.

**What burns it:** the store failing (`uncounted`), a feedback flood past
the feedback slots (shed), no ruleset (`decide_failed`).

## webhook-freshness

**SLI:** the share of effect webhook deliveries answered with a `2xx` within
60 seconds of being queued, out of those delivered and those given up.

```promql
1 - sum(rate(catraca_hooks_delivery_latency_seconds_bucket{le="60"}[6h]))
  / (sum(rate(catraca_hooks_delivery_latency_seconds_count[6h])) + sum(rate(catraca_hooks_dead_total[6h])))
```

Prometheus 3 stores that bucket as `le="60.0"`; the rules match both.

**Why 60 s and 99%:** effects are what make a decision stick: the leaked
key revoked, the account suspended. A delivery is queued with the decision
and attempted at once, so most take milliseconds; a minute absorbs four
failed attempts with the default backoff (2 s, doubling). The receiver is
the platform's, and its failures burn this budget on purpose: the objective
is about the effect, not about Catraca's half of it.

**Alerts:** effects are few, a handful an hour, too few for a burn rate
over one hour to mean anything, so only the 3-day ticket is a burn-rate
alert. A delivery still pending is not in the SLI until it is delivered or
given up, so the outbox pages by itself: `CatracaHooksBacklogStale` when
the oldest delivery of a hook has waited 10 minutes, and
`CatracaHooksEffectsLost` when effects could not even be written to the
outbox.

## audit-completeness

**SLI:** the share of decisions written to the audit log, out of those
written and those lost: dropped because the engine's queue
(`catraca_records_dropped_total`) or the audit log's buffer
(`catraca_audit_dropped_total`) was full, or failed to write
(`catraca_audit_failed_total`).

```promql
1 - (
  sum(rate(catraca_audit_dropped_total[1h])) + sum(rate(catraca_audit_failed_total[1h]))
  + sum(rate(catraca_records_dropped_total[1h]))
) / (
  sum(rate(catraca_audit_recorded_total[1h])) + sum(rate(catraca_audit_dropped_total[1h]))
  + sum(rate(catraca_audit_failed_total[1h])) + sum(rate(catraca_records_dropped_total[1h]))
)
```

**Why 99.9%:** decisions go on without the audit log, but a lost one cannot
be read, labeled or reverted, and the precision gate counts labels: losing
decisions biases the numbers rules are promoted on. The two buffers hold
about 12,000 decisions, so a database that blips for a few seconds costs
nothing; 43 minutes covers an outage someone had to fix.

**What burns it:** the audit database down or too slow
(`catraca_dependency_up{dependency="audit"}`,
`catraca_audit_write_duration_seconds`, `catraca_audit_queued` climbing),
or values it refuses (`catraca_audit_rejected_total`).

## leak-processing

**SLI:** the share of leaked-key reports done within 5 minutes of being
queued (they arrived, or were requeued): the token resolved to a key and
its key_leak was decided, or it is not one of the platform's keys. Out of
those done and those given up.

```promql
1 - sum(rate(catraca_secret_scanning_report_latency_seconds_bucket{outcome=~"leaked|not_found", le="300"}[30d]))
  / sum(rate(catraca_secret_scanning_report_latency_seconds_count[30d]))
```

**Why 5 minutes and 99%:** a leaked key is a live credential in public; the
sooner it is revoked, the less it is used. Reports are retried from 1 s,
doubling, so 5 minutes holds about eight attempts through a resolver or
store blip.

**Alerts:** a platform gets a few reports a month, too few for any burn
rate, so the queue is watched instead. `CatracaLeakReportsDead` pages for
any report given up (`catraca secretscan retry --dead` requeues them once
the cause is fixed), and `CatracaLeakReportsStale` when the oldest pending
report has waited 10 minutes. The 30-day ratio is recorded for reports.

## Alerts

### Burn rate

Every objective has the alerts of the Google SRE workbook's
[multiwindow, multi-burn-rate alerts](https://sre.google/workbook/alerting-on-slos/),
under one name, `CatracaErrorBudgetBurn`, with labels saying which:
`slo`, `severity` and `long_window`.

| `severity` | `long_window` | fires when both the long and the short window burn faster than | budget spent when it fires |
|---|---|---|---|
| `page` | `1h` | 14.4 (and the last 5 minutes) | 2% |
| `page` | `6h` | 6 (and the last 30 minutes) | 5% |
| `ticket` | `3d` | 1 (and the last 6 hours) | 10% |

The long window makes an alert worth acting on; the short one ends it soon
after the errors stop, instead of an hour later. For a 99.9% objective,
the fast page fires at 1.44% of requests failing; for 99%, at 14.4%. Route
`severity="page"` to whoever is on call and `ticket` to a queue.

When Redis goes down, `decide-completeness` pages and
`CatracaDependencyDown` says why. An Alertmanager inhibition can keep the
cause from opening a second ticket while the page is on:

```yaml
inhibit_rules:
  - source_matchers: [alertname="CatracaErrorBudgetBurn", slo="decide-completeness", severity="page"]
    target_matchers: [alertname=~"CatracaDependencyDown|CatracaStoreBreakerOpen", dependency=~"store|"]
    equal: [job]
```

### Cause alerts

What is wrong, whichever objective it costs:

| alert | fires when | severity |
|---|---|---|
| `CatracaStoreBreakerOpen` | an instance's store breaker has not been closed for a minute: it decides without Redis | ticket |
| `CatracaDependencyDown` | an instance has failed to reach `store` (Redis) or `audit` for 2 minutes | ticket |
| `CatracaHooksBacklogStale` | the oldest pending delivery of a hook has waited 10 minutes, for 5 minutes | page |
| `CatracaHooksDeadDeliveries` | deliveries were given up in the last 15 minutes; requeue them with `catraca outbox retry` | ticket |
| `CatracaHooksEffectsLost` | effects could not be written to the outbox: nothing will retry them, and the log names them to carry out by hand | page |
| `CatracaLeakReportsDead` | a leaked-key report was given up | page |
| `CatracaLeakReportsStale` | the oldest pending leaked-key report has waited 10 minutes | page |
| `CatracaAuditDecisionsLost` | decisions were dropped or failed to write in the last 10 minutes | ticket |
| `CatracaAuditRetentionFailing` | an audit retention run failed in the last hour | ticket |
| `CatracaRulesetLoadFailed` | a ruleset failed to load; the instance decides with the previous one | ticket |
| `CatracaNoRuleset` | an instance has had no ruleset for 5 minutes, and answers 503 | ticket |
| `CatracaRulesHeldByGate` | for 10 minutes, rules the ruleset newly enforces have not passed the [precision gate](config.md#gate): in shadow mode with `gate.on_load: enforce`, enforcing unproven with `warn` | ticket |

Every alert links to the section of this page that explains it
(`runbook_url`).

## Recording rules

| rule | |
|---|---|
| `catraca:slo_errors:ratio_rate5m`, `_rate30m`, `_rate1h`, `_rate6h`, `_rate3d`, `_rate30d` `{job, slo}` | the error ratio of each SLI over each window; `leak-processing` over 30 days only |
| `catraca:slo_objective:ratio{slo}` | each objective, such as 0.999 |
| `catraca:slo_error_budget_remaining:ratio30d{job, slo}` | the share of the budget left over the last 30 days; below 0 the objective is missed |
| `job_route:catraca_http_request_duration_seconds:p99_rate5m` | the 99th percentile of each `/v1` route |
| `job:catraca_decision_duration_seconds:p99_rate5m` | the engine's |
| `job_call:catraca_store_call_duration_seconds:p99_rate5m` | the store's, by call, for calls that answered |

A ratio with nothing to measure, such as feedback on a platform that sends
none, is `NaN`, and no alert fires on it.

## Setting it up

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/catraca/rules.yaml
scrape_configs:
  - job_name: catraca
    # The admin port when server.admin_addr is set.
    static_configs: [{targets: ["catraca:9090"]}]
```

- The 30-day ratios and the budget left need 30 days of data: a retention
  of at least `--storage.tsdb.retention.time=31d`.
- Exemplars, which link a latency bucket to a trace while
  [tracing](tracing.md) is on, need `--enable-feature=exemplar-storage`.
- Import [`deploy/grafana/catraca.json`](../deploy/grafana/catraca.json) in
  Grafana and pick the Prometheus data source and the job.

To check a change to the rules:

```sh
promtool check rules deploy/prometheus/rules.yaml
promtool test rules deploy/prometheus/rules.test.yaml
```

CI runs both with a pinned promtool, and a Go test checks that every metric
the rules and the dashboard name is one the server registers.
