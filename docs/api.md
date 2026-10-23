# HTTP API

Catraca's server speaks JSON over HTTP. The platform calls it before each
send and reports feedback and account activity; people and tools read and
label decisions and manage the ruleset; providers post feedback and leaked
keys; probes and Prometheus read health and metrics.

| route | auth | |
|---|---|---|
| [`POST /v1/decide`](#post-v1decide) | token | decide an event, synchronously |
| [`POST /v1/events`](#post-v1events) | token | record an event (feedback, account, key leak): 202 + decision |
| [`GET /v1/decisions/{id}`](#get-v1decisionsid) | token | a decision, its stored event and its labels |
| [`POST /v1/decisions/{id}/labels`](#post-v1decisionsidlabels) | token | label a decision (a reversal is a `false_positive`) |
| [`GET /v1/rules`](#get-v1rules) | token | the loaded ruleset and its version |
| [`POST /v1/rules/reload`](#post-v1rulesreload) | token | reload the ruleset from disk |
| [`GET /v1/rules/{id}/review`](#get-v1rulesidreview) | token | unlabeled matches of a rule, for reviewers |
| [`GET /v1/stats/rules`](#get-v1statsrules) | token | precision per rule against the gate |
| [`POST /v1/feedback`](#post-v1feedback) | signature | a feedback event in Catraca's format |
| [`POST /v1/feedback/ses`](#post-v1feedbackses-and-post-v1feedbackusesend) | SNS signature | Amazon SES notifications through SNS |
| [`POST /v1/feedback/usesend`](#post-v1feedbackses-and-post-v1feedbackusesend) | useSend signature | useSend webhooks |
| [`POST /v1/secret-scanning/github`](#post-v1secret-scanninggithub) | GitHub signature | GitHub secret scanning partner endpoint |
| [`GET /healthz`](#get-healthz-and-get-readyz) | none | liveness |
| [`GET /readyz`](#get-healthz-and-get-readyz) | none | readiness |
| [`GET /metrics`](#get-metrics) | none | Prometheus metrics |

The examples use two shell variables:

```sh
CATRACA=http://localhost:8080
TOKEN=...   # one of auth.tokens in catraca.yaml
```

## Conventions

**Authentication.** Every `/v1` route takes an API token,
`Authorization: Bearer <token>`, except the feedback and secret scanning
routes, which authenticate each request by its signature instead. Tokens are
configured in `auth.tokens`; the token's name appears in access logs as
`client`. A missing or wrong token gets `401` with
`WWW-Authenticate: Bearer realm="catraca"`.

`/healthz`, `/readyz` and `/metrics` take no token. Keep them off the
public internet, for example by exposing only `/v1` through the load
balancer.

**Request ids.** Every response carries `X-Request-Id`. Send your own (up
to 128 letters, digits, `-`, `_`, `.` or `:`) to follow a request across
the platform and Catraca's logs; otherwise Catraca generates one.

**Bodies.** Request bodies are JSON, decoded strictly: an unknown field such
as a misspelled `acount_id` is an error, not silently ignored. Bodies of the
JSON `/v1` routes are limited to `server.max_body_bytes` (1 MiB by default).

**Errors.** Every `/v1` error, `404` and `405` has the same shape:

```json
{"error": {"code": "invalid_event", "message": "event: account_id is required"}}
```

`code` is stable and meant for programs; `message` is for people. A failed
ruleset reload adds `details`, one entry per problem. The provider routes
(feedback and secret scanning) answer in the format their providers expect,
`{"error": "invalid signature"}`.

| status | code | meaning |
|---|---|---|
| 400 | `invalid_json` | the body is not the JSON the route expects |
| 400 | `invalid_event` | the event is missing what its type needs |
| 400 | `invalid_label` | the label's verdict or `by` is missing or wrong |
| 400 | `invalid_parameter` | a query parameter is out of range |
| 401 | `unauthorized` | no token, or not a configured one |
| 404 | `not_found` | no such decision, or no such route |
| 404 | `not_configured` | a provider route whose section is not in catraca.yaml |
| 405 | `method_not_allowed` | the route exists for another method (see `Allow`) |
| 413 | `body_too_large` | the body is over the limit |
| 422 | `rule_not_matched` | a label names a rule that did not match the decision |
| 422 | `invalid_ruleset` | a reload found errors; the current ruleset keeps serving |
| 500 | `internal` | the audit log could not be read; details are in the server log |
| 503 | `no_ruleset` | no ruleset is loaded: decisions cannot be made |
| 503 | `unavailable` | the event could not be decided; retry it |

**Decisions.** `POST /v1/decide` and `POST /v1/events` answer
`{"decision": {...}}`:

| field | |
|---|---|
| `id` | the decision id (a ULID); use it to label the decision |
| `event_id` | the event's id: the one you sent, or a generated one |
| `time` | when the decision was made |
| `action` | `allow`, `flag`, `throttle`, `hold` or `block`: what to do |
| `retry_after` | for `throttle`, how long to wait, in **nanoseconds** (a Go duration); the `Retry-After` header has it in seconds |
| `matches` | the enforced rules that matched: `rule_id`, `reason`, `action`, `mode`, `effects`, `retry_after`, and `errored` when the rule matched only because it fails closed |
| `shadow` | shadow rules that matched: what would have happened |
| `errors` | rules that could not be evaluated, with why |
| `degraded` | true when signals were missing, for example because the store timed out |
| `ruleset_version` | the version of the ruleset that decided |
| `latency_us` | time to decide, in microseconds |

Act on `action` alone; `matches` explain it. Show a match's `reason` to the
sender when you refuse or delay a send.

## Deciding

### POST /v1/decide

Decides an event and answers `200` with the decision for any valid event,
whatever the action. Call it before each send, inside the request that
sends; the decision is usually made in well under a millisecond, and the
signal lookup is bounded by `engine.deadline` (10 ms).

```sh
curl -s -X POST "$CATRACA/v1/decide" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "send",
    "account_id": "acct_42",
    "api_key_id": "key_7d3e",
    "ip": "203.0.113.7",
    "from": "hello@shop.example",
    "to": ["ana@mail.example"],
    "subject": "Your receipt",
    "links": ["https://shop.example/r/1"]
  }'
```

```json
{
  "decision": {
    "id": "01M50QGN32570CX37SPKGJDZ7A",
    "event_id": "01M50QGN32570CX37SPKGJDZ79",
    "time": "2026-10-15T21:29:27.394212Z",
    "action": "allow",
    "ruleset_version": "098086f42c27",
    "latency_us": 182
  }
}
```

The event fields:

| field | | |
|---|---|---|
| `type` | required | `send`, `feedback`, `account` or `key_leak` |
| `account_id` | required except for `key_leak` | the platform's account id |
| `id` | | your id for the event; generated when left out |
| `time` | | RFC 3339; defaults to when Catraca receives it. Counters slide on event time |
| `api_key_id`, `ip` | | the key and IP the send used |
| `from`, `to`, `subject`, `links` | | the email: sender, recipients, subject, the URLs in the body |
| `feedback` | `feedback` events | `kind` (`bounce`, `complaint`, `delivery`), `bounce_type` (`permanent`, `transient`), `recipient`, `message_id` |
| `account` | | `action` (`signup`, `login`, `api_key_created`, ...), `created_at`, `plan` |
| `leak` | | `source`, `url`, for `key_leak` events |
| `attributes` | | string pairs exposed to rules as `event.attributes` |

A throttle carries `Retry-After` in whole seconds, rounded up:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Retry-After: 60
X-Request-Id: 55687d9a883498bc98d265346364514f

{"decision":{"id":"01M50QGQK25X1NM2J4XR59GJW8","event_id":"01M50QGQK25X1NM2J4XR59GJW7","time":"2026-10-15T21:29:29.9547537Z","action":"throttle","retry_after":60,"matches":[{"rule_id":"new-account-burst","reason":"New account sending at burst volume; slow down and retry later","action":"throttle","mode":"enforce","retry_after":60}],"ruleset_version":"098086f42c27","latency_us":211}}
```

A block names the rule and, for effects such as revoking a key, what
Catraca asked the platform's hooks to do:

```json
{
  "decision": {
    "id": "01M50QGQP8YVGSY487W3YJ8J24",
    "event_id": "01M50QGQP8YVGSY487W3YJ8J23",
    "time": "2026-10-15T21:29:30.0567392Z",
    "action": "block",
    "matches": [
      {
        "rule_id": "leaked-key-send",
        "reason": "This API key was found in public and must be rotated before it can send again",
        "action": "block",
        "mode": "enforce",
        "effects": ["revoke_key"]
      }
    ],
    "ruleset_version": "098086f42c27",
    "latency_us": 240
  }
}
```

A shadow rule that matched does not change the action; it is listed under
`shadow` and recorded for review.

Errors: `400 invalid_event` or `invalid_json` for an event that cannot be
decided, `503 no_ruleset` while no ruleset is loaded, `503 unavailable` when
nothing could be observed (retry). When Catraca is unreachable or answers
`5xx`, the platform should send anyway: a broken anti-abuse service must not
stop every good sender.

```sh
curl -s -X POST "$CATRACA/v1/decide" -H "Authorization: Bearer $TOKEN" -d '{"type": "send"}'
```

```json
{"error": {"code": "invalid_event", "message": "event: account_id is required"}}
```

### POST /v1/events

Records an event that is not a send decision, such as account activity,
feedback the platform collects itself, or a key leak it learned of, and
answers `202 Accepted` with the decision. The event goes through the same
engine as `/v1/decide`: it feeds the counters, and rules may act on it.

```sh
curl -s -X POST "$CATRACA/v1/events" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "type": "account",
    "account_id": "acct_new",
    "ip": "198.51.100.4",
    "account": {"action": "signup", "created_at": "2026-10-15T12:00:00Z"}
  }'
```

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{"decision":{"id":"01M50QGN558TQ3J7E7A64AXNNE","event_id":"01M50QGN558TQ3J7E7A64AXNND","time":"2026-10-15T21:29:27.4615934Z","action":"allow","ruleset_version":"098086f42c27","latency_us":95}}
```

A key the platform found leaked itself (a support ticket, a scan of its own)
is a `key_leak` event; `account_id` is optional for it. From then on
`key.leaked` is true for every event with the key:

```sh
curl -s -X POST "$CATRACA/v1/events" -H "Authorization: Bearer $TOKEN" \
  -d '{"type": "key_leak", "account_id": "acct_42", "api_key_id": "key_7d3e", "leak": {"source": "support-ticket"}}'
```

The leak is written to the store before the event is decided, within
`engine.deadline`. If the store does not take it in time, the answer is
`503 unavailable`: send the event again until it is accepted.

## Decisions and labels

### GET /v1/decisions/{id}

A decision as the audit log keeps it: the decision, the stored copy of the
event (no message content unless `audit.event_detail` is `full`; see
[audit](audit.md#what-is-stored)), and its labels, oldest first.

```sh
curl -s "$CATRACA/v1/decisions/01M50QGQP8YVGSY487W3YJ8J24" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "decision": {
    "id": "01M50QGQP8YVGSY487W3YJ8J24",
    "event_id": "01M50QGQP8YVGSY487W3YJ8J23",
    "time": "2026-10-15T21:29:30.0567392Z",
    "action": "block",
    "matches": [
      {
        "rule_id": "leaked-key-send",
        "reason": "This API key was found in public and must be rotated before it can send again",
        "action": "block",
        "mode": "enforce",
        "effects": ["revoke_key"]
      }
    ],
    "ruleset_version": "098086f42c27",
    "latency_us": 240
  },
  "event": {
    "id": "01M50QGQP8YVGSY487W3YJ8J23",
    "type": "send",
    "time": "2026-10-15T21:29:30.0567392Z",
    "account_id": "acct_42",
    "api_key_id": "key_7d3e",
    "ip": "203.0.113.7",
    "from_domain": "shop.example",
    "recipients": 1,
    "recipient_domains": ["mail.example"]
  },
  "labels": []
}
```

`404 not_found` when the decision is not in the log.

### POST /v1/decisions/{id}/labels

Labels a decision and answers `201 Created` with the decision and all its
labels.

| field | | |
|---|---|---|
| `verdict` | required | `true_positive` (the rule was right) or `false_positive` (it was wrong) |
| `by` | required | who gives the label: a reviewer, or a system such as the appeals flow |
| `reason` | | why: an appeal or ticket number |
| `rule_id` | | label only this rule's match; without it the label covers every rule that matched |
| `time` | | when the verdict was given; defaults to now. The latest label of a match counts |

**A reversal is a false positive.** When the platform undoes an enforced
decision, such as unblocking a sender after an appeal, it should label the
decision `false_positive`: every reversal counts against the rules that
caused it, which is what keeps a bad rule from staying enforced.

```sh
curl -s -X POST "$CATRACA/v1/decisions/01M50QGQP8YVGSY487W3YJ8J24/labels" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"verdict": "true_positive", "by": "security@platform.example", "reason": "key confirmed public in a gist"}'
```

```json
{
  "decision": {"id": "01M50QGQP8YVGSY487W3YJ8J24", "action": "block", "...": "..."},
  "event": {"id": "01M50QGQP8YVGSY487W3YJ8J23", "type": "send", "...": "..."},
  "labels": [
    {
      "verdict": "true_positive",
      "by": "security@platform.example",
      "reason": "key confirmed public in a gist",
      "time": "2026-10-15T21:29:39.210011Z"
    }
  ]
}
```

Errors: `404 not_found` for an unknown decision, `400 invalid_label` for a
missing `by` or an unknown verdict, `422 rule_not_matched` when `rule_id`
names a rule that did not match the decision. `catraca label` sends the
same request from the command line.

## Rules

### GET /v1/rules

The ruleset decisions are made with, with defaults applied: its version,
lists and rules. `503 no_ruleset` while none is loaded.

```sh
curl -s "$CATRACA/v1/rules" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "version": "098086f42c27",
  "format": 1,
  "lists": {
    "url_shorteners": ["bit.ly", "bl.ink", "buff.ly", "..."]
  },
  "rules": [
    {
      "id": "new-account-burst",
      "description": "Throttles accounts younger than a day that send more than 100 emails in a minute. ...",
      "when": "event.type == \"send\" && account.age_hours < 24 && account.sends_1m > 100",
      "action": "throttle",
      "mode": "shadow",
      "on_error": "open",
      "retry_after": "1m0s",
      "reason": "New account sending at burst volume; slow down and retry later",
      "tags": ["volume", "new-account"]
    }
  ]
}
```

### POST /v1/rules/reload

Reads the ruleset file (`rules.path`) again and swaps it in atomically.
Decisions in flight finish on the ruleset they started with. On Unix,
`SIGHUP` does the same.

```sh
curl -s -X POST "$CATRACA/v1/rules/reload" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "version": "5b1e0c7d9a42",
  "previous_version": "098086f42c27",
  "changed": true,
  "rules": 9,
  "warnings": []
}
```

`warnings` are the lint findings of the new ruleset (see
[rules](rules.md#load-time-checks-and-lint)). A file that does not load
leaves the current ruleset serving and answers `422`:

```json
{
  "error": {
    "code": "invalid_ruleset",
    "message": "the ruleset did not load; still serving version 098086f42c27",
    "details": [
      "rules.yaml:183: rule Bad Rule: id must be kebab-case: lowercase letters and digits separated by single dashes, starting with a letter",
      "rules.yaml:183: rule Bad Rule: reason is required: it is shown to the platform and written to the audit log",
      "rules.yaml:184: rule Bad Rule: when: Syntax error: mismatched input '<EOF>' expecting ... (at column 19 of the expression)"
    ]
  }
}
```

### GET /v1/rules/{id}/review

The most recent unlabeled matches of a rule, newest first, each with its
reason and stored event: the queue a reviewer works through to label a
shadow rule toward the precision gate. Labeling a match removes it from the
queue. The rule does not need to be in the current ruleset.

| parameter | default | |
|---|---|---|
| `mode` | any | `shadow` or `enforce` |
| `limit` | 50 | 1 to 1000 |

```sh
curl -s "$CATRACA/v1/rules/signup-farm-ip/review?mode=shadow&limit=2" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "rule_id": "signup-farm-ip",
  "mode": "shadow",
  "items": [
    {
      "decision_id": "01M50QHDASSXKA264FKW4MD3PC",
      "rule_id": "signup-farm-ip",
      "mode": "shadow",
      "action": "flag",
      "reason": "Many signups from the same IP address in the last 24 hours",
      "time": "2026-10-15T21:29:52.217212Z",
      "event": {
        "id": "01M50QHDASSXKA264FKW4MD3PB",
        "type": "account",
        "time": "2026-10-15T21:29:52.2172124Z",
        "account_id": "acct_94",
        "ip": "198.51.100.20",
        "account_action": "signup"
      }
    }
  ]
}
```

To label one, post to `/v1/decisions/{decision_id}/labels` with the rule's
`rule_id`.

### GET /v1/stats/rules

The precision of every rule of the current ruleset over a window, evaluated
against the precision gate (`gate` in catraca.yaml), with the rules worth
acting on: `promote` lists shadow rules that pass the gate, `retire`
enforced rules below it. See [audit](audit.md#the-precision-gate) for what
the numbers mean.

`since` is where the window starts: a duration back from now (`720h`, the
default), a number of days (`30d`), or an RFC 3339 time or date
(`2026-10-01`).

```sh
curl -s "$CATRACA/v1/stats/rules?since=30d" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "since": "2026-09-15T21:29:52.6372444Z",
  "ruleset_version": "098086f42c27",
  "gate": {"min_labeled": 30, "min_precision": 0.9},
  "rules": [
    {
      "rule_id": "leaked-key-send",
      "mode": "enforce",
      "matches": 1,
      "errored": 0,
      "labeled": 1,
      "true_positives": 1,
      "false_positives": 0,
      "precision": 1,
      "precision_lower": 0.20654931437723742,
      "precision_upper": 1,
      "status": "insufficient_labels",
      "override": true
    },
    {
      "rule_id": "signup-farm-ip",
      "mode": "shadow",
      "matches": 1,
      "errored": 0,
      "labeled": 0,
      "true_positives": 0,
      "false_positives": 0,
      "precision": 0,
      "precision_lower": 0,
      "precision_upper": 1,
      "status": "insufficient_labels"
    }
  ],
  "promote": [],
  "retire": []
}
```

`status` is `passes`, `insufficient_labels` or `below_precision`. Counts add
up a rule's matches in both modes. `catraca report` prints the same report
from the audit database directly.

## Provider endpoints

These routes take no API token: each request is authenticated by its
signature, and refused before its body is read as feedback when the
signature does not verify. A route whose section is missing from
catraca.yaml answers `404 not_configured`.

### POST /v1/feedback

A feedback event in Catraca's own format, for providers without an adapter,
signed with `feedback.generic.secret` in `Catraca-Signature`:
`t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">`, within five
minutes of Catraca's clock. In Go, `signature.Sign` from
`github.com/guilhermebsantiago/catraca/signature` builds the header. See
[feedback](feedback.md#generic-endpoint) for the fields.

```sh
BODY='{"account_id":"acct_42","time":"2026-10-15T12:00:00Z","from":"news@shop.example","feedback":{"kind":"bounce","bounce_type":"permanent","recipient":"gone@mail.example"}}'
T=$(date +%s)
SIG=$(printf '%s.%s' "$T" "$BODY" | openssl dgst -sha256 -hmac "$CATRACA_FEEDBACK_SECRET" -hex | sed 's/^.* //')
curl -s -X POST "$CATRACA/v1/feedback" -H "Catraca-Signature: t=$T,v1=$SIG" -d "$BODY"
```

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{"decision":{"id":"01M50QHDZF72SP76W0ADN0HEBA","event_id":"01M50QHDZF72SP76W0ADN0HEB9","time":"2026-10-15T21:29:52.8796937Z","action":"allow","ruleset_version":"098086f42c27","latency_us":120}}
```

`401` when the signature does not verify, `400` with what is wrong with the
event.

### POST /v1/feedback/ses and POST /v1/feedback/usesend

Amazon SES notifications delivered by SNS (signature verified, subscriptions
confirmed for the configured topics), and useSend webhooks (signature
verified). They are set up in the provider, not called by hand; see
[feedback](feedback.md) for the setup and the status codes each provider's
retry policy needs.

### POST /v1/secret-scanning/github

GitHub's secret scanning partner endpoint. GitHub posts a signed batch of
tokens it found in public; Catraca verifies the ECDSA signature with
GitHub's published keys, answers at once, resolves each token through the
platform's resolver and emits a `key_leak` event for every key it finds. See
[secret scanning](secret-scanning.md).

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

[]
```

With `secret_scanning.github.feedback: true` the answer is `200` with a
true or false positive label per token.

## Operations

### GET /healthz and GET /readyz

`/healthz` answers `200 {"status": "ok"}` while the process serves HTTP: use
it as the liveness probe.

`/readyz` is the readiness probe. It is ready when a ruleset is loaded and
the server is not shutting down, and otherwise answers `503` with the
failing check:

```sh
curl -s "$CATRACA/readyz"
```

```json
{"status": "ready", "checks": {"rules": "ok", "shutdown": "ok"}}
```

```json
{"status": "not_ready", "checks": {"rules": "no ruleset loaded", "shutdown": "ok"}}
```

A server whose ruleset failed to load at start keeps running, not ready,
until a reload succeeds, so a broken edit never takes down instances that
are already serving.

A server that received SIGTERM is not ready while it drains
(`server.drain_delay`, 5s by default), and still serves every route:

```json
{"status": "not_ready", "checks": {"rules": "ok", "shutdown": "draining"}}
```

Readiness looks at the server's own state only. Redis and the audit
database are shared by every instance: if readiness depended on them, an
outage of either would take every instance out of the load balancer at
once, while Catraca can still decide without them (degraded without Redis,
unrecorded without the audit database). Their health is reported
separately, with `?verbose`:

```sh
curl -s "$CATRACA/readyz?verbose"
```

```json
{"status": "ready", "checks": {"rules": "ok", "shutdown": "ok"},
 "dependencies": {
   "audit": {"status": "ok", "since": "2026-10-23T12:00:00Z", "checked_at": "2026-10-23T12:41:05Z", "duration_ms": 0.41},
   "store": {"status": "timeout", "since": "2026-10-23T12:40:10Z", "checked_at": "2026-10-23T12:41:05Z", "duration_ms": 2000}}}
```

The server checks each dependency every 5 seconds in the background, all at
once and each within 2 seconds, so `?verbose` answers from the last checks
and never waits on a dependency itself. `status` is `ok`, `unavailable` or
`timeout` (`unknown` before the first check); `since` is when it took that
value. Only Redis is listed as `store`; the memory store is not a
dependency. The reason for a failure is in the log, once when a dependency
goes down and once when it is back. The same checks feed
`catraca_dependency_up` and the other metrics below.

### GET /metrics

Prometheus metrics in the text format.

| metric | type | |
|---|---|---|
| `catraca_decisions_total{action}` | counter | decisions, by action |
| `catraca_rule_matches_total{rule,mode}` | counter | rule matches |
| `catraca_rule_errors_total{rule}` | counter | rules that could not be evaluated |
| `catraca_degraded_decisions_total` | counter | decisions made without some signals |
| `catraca_decision_duration_seconds` | histogram | time to decide |
| `catraca_records_dropped_total` | counter | decisions the engine could not hand to the audit log |
| `catraca_http_request_duration_seconds{route,status}` | histogram | HTTP requests, by route pattern (`POST /v1/decide`, `unmatched`) and status |
| `catraca_audit_recorded_total`, `_dropped_total`, `_failed_total` | counter | audit log writes |
| `catraca_audit_queued` | gauge | decisions waiting to be written |
| `catraca_hooks_enqueued_total`, `_enqueue_errors_total`, `_delivered_total`, `_retries_total`, `_dead_total` | counter | effect webhook deliveries |
| `catraca_feedback_outcomes_total{provider,outcome}` | counter | what the feedback endpoints did ([outcomes](feedback.md#metrics)) |
| `catraca_secret_scanning_outcomes_total{outcome}` | counter | batches and tokens ([outcomes](secret-scanning.md#metrics)) |
| `catraca_ruleset_info{version}` | gauge | 1, labeled with the current ruleset version |
| `catraca_ruleset_rules{mode}` | gauge | rules by mode |
| `catraca_ruleset_loads_total{result}` | counter | loads at start and reloads, `ok` or `error` |
| `catraca_dependency_up{dependency}` | gauge | 1 when the last check of `store` (Redis) or `audit` succeeded, else 0 |
| `catraca_dependency_check_duration_seconds{dependency}` | gauge | how long the last check took; a timeout counts as 2s |
| `catraca_dependency_check_failures_total{dependency}` | counter | checks that failed or timed out |
| `catraca_build_info{version,goversion}` | gauge | 1, labeled with the build |

plus the standard `go_*` and `process_*` metrics. Worth alerting on:
`catraca_degraded_decisions_total` and `catraca_audit_dropped_total` rising,
`catraca_dependency_up` at 0, `catraca_hooks_dead_total`,
`catraca_ruleset_loads_total{result="error"}`, and the `decide_failed` and
`resolve_failed` outcomes.

```sh
curl -s "$CATRACA/metrics" | grep '^catraca_decisions_total'
```

```
catraca_decisions_total{action="allow"} 109
catraca_decisions_total{action="block"} 1
catraca_decisions_total{action="flag"} 0
catraca_decisions_total{action="hold"} 0
catraca_decisions_total{action="throttle"} 2
```

## Logs

Every request is logged once, as JSON by default (`logging.format`):

```json
{"time":"2026-10-15T21:25:43.490Z","level":"INFO","msg":"request","request_id":"b2dfbafcacbab0f963ec8b7177322d5c","method":"POST","route":"POST /v1/decide","path":"/v1/decide","status":200,"bytes":387,"duration_ms":0.498,"remote":"127.0.0.1:58358","decision_id":"01M50Q9TE1EPGZCTSX7N6NPC78","action":"block","client":"platform"}
```

Requests to `/healthz`, `/readyz` and `/metrics` are logged at debug level.
Tokens, secrets and message content are never logged.
