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
| [`GET /v1/accounts/{id}/state`](#account-states) | token | an account's state: active, review, suspended or trusted |
| [`PUT /v1/accounts/{id}/state`](#account-states) | token | set an account's state, optionally until a time |
| [`DELETE /v1/accounts/{id}/state`](#account-states) | token | reset an account to active |
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
`client`, and a request with a token being rotated out (`previous_tokens`)
also has `"previous_token": true` ([rotating secrets](rotation.md#api-tokens)).
A missing or wrong token gets `401` with
`WWW-Authenticate: Bearer realm="catraca"`.

**Scopes.** Each route that takes a token needs one scope, and a token
calls only the routes of the [scopes it lists](config.md#auth). The token
on the send path, deployed on every app server, needs `decide` alone; with
it, a leaked app server cannot read the audit log, label decisions or
reload the rules:

| route | scope |
|---|---|
| `POST /v1/decide` | `decide` |
| `POST /v1/events` | `decide` |
| `GET /v1/decisions/{id}` | `read` |
| `GET /v1/rules` | `read` |
| `GET /v1/rules/{id}/review` | `read` |
| `GET /v1/stats/rules` | `read` |
| `GET /v1/accounts/{id}/state` | `read` |
| `POST /v1/decisions/{id}/labels` | `label` |
| `POST /v1/rules/reload` | `admin` |
| `PUT /v1/accounts/{id}/state` | `admin` |
| `DELETE /v1/accounts/{id}/state` | `admin` |

`read` reads what the audit log holds: account ids, IPs, recipient
domains, and addresses and links with `audit.event_detail: full`. `admin`
is for what changes how Catraca decides: reloading the ruleset and setting an
account's state. The feedback and secret scanning
routes take no token, so no scope: their signature proves the provider sent
them. A token configured without `scopes` has every scope, so
configurations written before scopes keep working; `catraca config check`
warns about each one.

A token without the route's scope gets `403 insufficient_scope` with
`WWW-Authenticate: Bearer realm="catraca", error="insufficient_scope", scope="read"`
(the scope the route needs), and its access log line has the token's
`client` name, the `scope` and `"scope_check": "denied"`; a request the
token may make has `"scope_check": "allowed"`.

A new route takes one of these scopes, or a new one: add it to `Scopes` in
`internal/api/scope.go` and `TokenScopes` in `internal/config`, and to this
table. Tokens without `scopes` get it too; tokens that list theirs do not
until it is added to them.

`/healthz`, `/readyz` and `/metrics` take no token. Keep them off the
public internet: serve them on a port of their own with
[`server.admin_addr`](config.md#server), or expose only `/v1` through the
load balancer.

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
| 400 | `invalid_event` | the event is missing what its type needs, or is over a [limit](#limits) |
| 400 | `invalid_label` | the label's verdict or `by` is missing or wrong |
| 400 | `invalid_parameter` | a query parameter is out of range |
| 400 | `invalid_state` | an account state that is not one of the four, an `until` that has passed, or a `reason` over 1024 bytes |
| 400 | `invalid_account_id` | an account id over 256 bytes |
| 401 | `unauthorized` | no token, or not a configured one |
| 403 | `insufficient_scope` | the token does not have the route's [scope](#conventions); `WWW-Authenticate` names it |
| 404 | `not_found` | no such decision, or no such route |
| 404 | `not_configured` | a provider route whose section is not in catraca.yaml |
| 405 | `method_not_allowed` | the route exists for another method (see `Allow`) |
| 413 | `body_too_large` | the body is over the limit |
| 422 | `rule_not_matched` | a label names a rule that did not match the decision |
| 422 | `invalid_ruleset` | a reload found errors; the current ruleset keeps serving |
| 500 | `internal` | an unexpected error; details are in the server log |
| 503 | `no_ruleset` | no ruleset is loaded: decisions cannot be made |
| 503 | `unavailable` | the event could not be decided, or the audit database failed to answer (details are in the server log); retry it after `Retry-After` |
| 503 | `overloaded` | too many events are being decided, and this one is a `feedback` or `key_leak` event that a decision without the store would not record ([admission](config.md#admission)); send it again after `Retry-After` |
| 503 | `store_unavailable` | the store did not answer an account state request; retry it |
| 503 | `audit_unavailable` | the audit database has not opened yet (see [audit](config.md#audit)); decisions are still made, the routes that read or label them answer this, with `Retry-After`, until it opens |

**Decisions.** `POST /v1/decide` and `POST /v1/events` answer
`{"decision": {...}}`:

| field | |
|---|---|
| `id` | the decision id (a ULID); use it to label the decision |
| `event_id` | the event's id: the one you sent, or a generated one |
| `time` | when the decision was made |
| `action` | `allow`, `flag`, `throttle`, `hold` or `block`: what to do |
| `retry_after` | for `throttle`, how long to wait, in whole seconds rounded up, the same number as the `Retry-After` header |
| `matches` | the enforced rules that matched: `rule_id`, `reason`, `action`, `mode`, `effects`, `retry_after` (whole seconds, for a throttle rule), and `errored` when the rule matched only because it fails closed |
| `shadow` | shadow rules that matched: what would have happened |
| `errors` | rules that could not be evaluated, with why |
| `degraded` | true when signals were missing, for example because the store timed out |
| `uncounted` | true when the decision is degraded because the store failed rather than answered late, so the event may be missing from the counters; send it again with the same `id` to count it |
| `duplicate` | true when an event with the same `id` had counted already, so this one did not count again ([retries](#retries)) |
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
| `id` | | your id for the event, so that sending it again counts it once ([retries](#retries)); generated when left out |
| `time` | | RFC 3339; defaults to when Catraca receives it. Counters slide on event time. Bounded by Catraca's clock: see [limits](#limits) |
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

Under load Catraca keeps answering this route with decisions. When more
decisions are in flight than it lets in at once, the excess is decided at
once without the store, and when Redis keeps failing, its breaker skips it
for a while: either way the decision is `degraded`, exactly as when Redis
misses the deadline, and comes back in well under the deadline. See
[admission](config.md#admission) and [the store breaker](config.md#engine). A `400` is about the event itself: the same event
gets the same answer, so fix the integration rather than retrying.

```sh
curl -s -X POST "$CATRACA/v1/decide" -H "Authorization: Bearer $TOKEN" -d '{"type": "send"}'
```

```json
{"error": {"code": "invalid_event", "message": "event: account_id is required"}}
```

### Retries

Send each event with an `id` of your own, such as your message id, and use
the same one when you send the event again, after a timeout say. An event
whose `id` has counted already (same type and account) does not count again
for [`engine.dedupe_ttl`](config.md#engine) (10 minutes) after it first did:
its decision is made on the counters as they are, with the first sending
counted once, and has `"duplicate": true`. Without an `id`, Catraca
generates one, and every sending counts. A decision with
`"uncounted": true` was made while the store failed, so its event may be
missing from the counters: when it is not a send you are about to make,
send it again with its `id`. `catraca_duplicate_events_total` counts the
duplicates by event type.

An `id` names one event: reusing one for another event of the same type and
account within the window drops that event from the counters.

### Limits

Every event is checked against these limits, whichever route brings it in
(the feedback and secret scanning endpoints included), and an event over one
is answered `400 invalid_event` with what is wrong:

| what | limit |
|---|---|
| `id`, `account_id`, `api_key_id`, `ip`, attribute names | 256 bytes of valid UTF-8, without control characters (U+0000 to U+001F, U+007F to U+009F) |
| `to` | 1,000 addresses |
| `links` | 1,000 links |
| `attributes` | 64 pairs |
| any other string: `from`, each address and link, `subject`, attribute values, the fields of `feedback`, `account` and `leak` | 8 KiB, without NUL (U+0000) |
| `time` | at most `engine.max_future_skew` (5 s) ahead of Catraca's clock and `engine.max_event_age` (7 days) behind it; see below |

```json
{"error": {"code": "invalid_event", "message": "event: to has 1200 addresses; at most 1000 are accepted"}}
```

Real email stays far below them: providers take 50 recipients per message
(SES, Postmark, Resend) up to 1,000 (Mailgun and SendGrid batches), and
Postfix refuses more than 1,000 by default. They exist because every
decision shares the store and the audit log. Each distinct recipient domain
of a send is a few Redis calls inside the script that holds Redis while it
runs, so an unbounded `to` let one request slow every decision.
Identifiers become store keys and audit columns: Postgres cannot store NUL,
and a control character in an id can rewrite a terminal that shows it. Send
a larger batch as several events.

**Time.** Counters slide on event time and first-seen times keep the
earliest one, so unbounded, one send dated a month ahead would empty its
account's windows until the clock caught up, and one event dated 1970 would
make its account look 56 years old. Catraca bounds event times by its own
clock:

- A time more than `engine.max_future_skew` ahead is replaced by Catraca's
  clock: an event cannot come from the future, so it counts when it arrived.
- A late time is kept, so feedback that arrives hours late lands in the
  window it belongs to.
- An event more than `engine.max_event_age` old is rejected: seven days is
  the longest window, so it could change nothing but first-seen times. A
  `key_leak` is the exception: it takes Catraca's clock instead, since a key
  is leaked however long ago it was found.

`catraca_event_times_out_of_bounds_total` counts both. To give Catraca an
account's real age, send `account.created_at`, not old events.

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
`engine.deadline`. If the store does not take it in time, or its
[breaker](config.md#engine) is open, the answer is `503 unavailable`, and
when too many events are being decided it is `503 overloaded`: either way,
send the event again after `Retry-After` until it is accepted. A `feedback`
event shed for load gets `503 overloaded` too, so that it is counted when
sent again; other events shed for load are decided without the store
([admission](config.md#admission)).

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

`404 not_found` when the decision is not in the log, `503 unavailable` with
`Retry-After` when the audit database fails to answer.

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

Catraca adds `client` to the label: the name of the token that sent it,
whatever the body says. `by` is what the caller says; `client` is which
credential said it.

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
      "client": "ops",
      "time": "2026-10-15T21:29:39.210011Z"
    }
  ]
}
```

Errors: `404 not_found` for an unknown decision, `400 invalid_label` for a
missing `by` or an unknown verdict, `422 rule_not_matched` when `rule_id`
names a rule that did not match the decision, `503 unavailable` with
`Retry-After` when the audit database fails to answer. Sending a label again
after a `503` is safe: precision counts the latest label of each match.
`catraca label` sends the same request from the command line.

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
`SIGHUP` does the same, and every instance also reloads the file by itself
when its content changes ([`rules.watch_interval`](config.md#rules)). A
reload always loads the file, changed or not, so it also runs the
[precision gate](config.md#gate) again on the rules it holds.

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
[rules](rules.md#load-time-checks-and-lint)). With
[`gate.on_load`](config.md#gate) at `enforce`, `held` lists the rules the
file enforces that are held in shadow mode because they have not passed
the precision gate, with why (`insufficient_labels`, `below_precision`, or
`unavailable` when the audit database could not answer); `version` is then
the version of the ruleset as applied, with those rules in shadow mode.
With `warn`, `ungated` lists the rules that enforce without having passed:

```json
{
  "version": "7c2f9e1a0b3d",
  "previous_version": "5b1e0c7d9a42",
  "changed": true,
  "rules": 9,
  "warnings": [],
  "held": [{"rule": "new-account-burst", "status": "insufficient_labels"}]
}
```

A file that does not load leaves the current ruleset serving and answers
`422`:

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

## Account states

An operator's decision about an account, which rules read as
[`account.state`](signals.md#account-states): suspend it, put it under
review, or trust it, without editing the ruleset. The state is kept in the
counter store, so every replica sees it, and it survives restarts when the
store is Redis with persistence (RDB or AOF); the memory store loses it.

| state | | default ruleset |
|---|---|---|
| `active` | no state: the default | |
| `review` | a person should look at its sends | `account-review` holds every send |
| `suspended` | the account must not send | `account-suspended` blocks every send |
| `trusted` | the operator vouches for it | the volume heuristics skip it |

### PUT /v1/accounts/{id}/state

Sets the account's state, replacing any other, and answers `200` with it.

| field | | |
|---|---|---|
| `state` | required | `review`, `suspended` or `trusted`; `active` resets the account, as `DELETE` does |
| `until` | | when the state expires and the account is active again, in RFC 3339; without it the state lasts until it is changed |
| `reason` | | why, for whoever reads the state later: a ticket number, say. At most 1024 bytes |

```sh
curl -s -X PUT "$CATRACA/v1/accounts/acct_123/state"   -H "Authorization: Bearer $TOKEN"   -d '{"state": "suspended", "until": "2026-11-01T18:00:00Z", "reason": "chargeback fraud, ticket 4411"}'
```

```json
{
  "account_id": "acct_123",
  "state": "suspended",
  "until": "2026-11-01T18:00:00Z",
  "reason": "chargeback fraud, ticket 4411",
  "set_at": "2026-10-29T21:02:11.402115Z",
  "set_by": "platform"
}
```

`set_at` is when the state was set and `set_by` the name of the API token
that set it. Every change is logged at info level as `account state
changed`, with the account, the state, `until`, `reason`, `set_by` and the
request id; the audit log does not record it.

Errors: `400 invalid_state` for another state, an `until` that has passed
or a `reason` over 1024 bytes; `503 store_unavailable` when the store does
not answer, in which case the state may or may not have changed: send the
request again.

### GET /v1/accounts/{id}/state

Answers `200` with the account's state, in the shape above. An account
with no state, or whose state expired or was reset, is
`{"account_id": "acct_123", "state": "active"}`. A stored state Catraca
cannot read, written to the store by something else, answers
`500 internal`; `PUT` or `DELETE` replaces it.

### DELETE /v1/accounts/{id}/state

Resets the account to `active` and answers `200` with
`{"account_id": "acct_123", "state": "active"}`, whether or not it had a
state.

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
event, including an event over a [limit](#limits) or older than
`engine.max_event_age`, and `503` with `Retry-After` when the event could
not be counted: send it again, with the same `id`, so it counts once.

### POST /v1/feedback/ses and POST /v1/feedback/usesend

Amazon SES notifications delivered by SNS (signature verified, subscriptions
confirmed for the configured topics), and useSend webhooks (signature
verified). They are set up in the provider, not called by hand; see
[feedback](feedback.md) for the setup and the status codes each provider's
retry policy needs.

### POST /v1/secret-scanning/github

GitHub's secret scanning partner endpoint. GitHub posts a signed batch of
tokens it found in public; Catraca verifies the ECDSA signature with
GitHub's published keys, stores a report per token in the audit database
and answers, then resolves each token through the platform's resolver and
emits a `key_leak` event for every key it finds, retrying failures. See
[secret scanning](secret-scanning.md).

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

[]
```

With `secret_scanning.github.feedback: true` the answer is `200` with a
true or false positive label per token resolved in time. A batch whose
reports cannot be stored, for example while the audit database is not open
yet, gets `503` with `Retry-After`, so GitHub sends it again.

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
   "store": {"status": "timeout", "since": "2026-10-23T12:40:10Z", "checked_at": "2026-10-23T12:41:05Z", "duration_ms": 2000}},
 "ruleset": {"version": "7c2f9e1a0b3d", "file_version": "5b1e0c7d9a42", "path": "/etc/catraca/rules/default.yaml",
   "source": "watch", "loaded_at": "2026-10-23T12:30:02Z", "gate": "enforce",
   "held": [{"rule": "new-account-burst", "status": "insufficient_labels"}]}}
```

`ruleset` is the ruleset the instance decides with, so comparing it across
instances shows whether a change reached them all:

| field | |
|---|---|
| `version` | the version decisions are made with and record |
| `file_version` | the version of the file as written, present when the [gate](config.md#gate) holds rules in shadow mode and the two differ |
| `path` | the ruleset file, `rules.path` |
| `source` | what loaded it: `start`, `watch` (the file changed), `signal` (SIGHUP) or `api` (`POST /v1/rules/reload`) |
| `loaded_at` | when it took effect |
| `gate` | `gate.on_load`: `enforce`, `warn` or `off` |
| `held`, `ungated` | the rules the gate held in shadow mode (`enforce`) or let enforce without passing (`warn`), with why |
| `failed_at` | present when a later attempt to load the file failed: the file is then not what the instance runs, and the log says why |

The server checks each dependency every 5 seconds in the background, all at
once and each within 2 seconds, so `?verbose` answers from the last checks
and never waits on a dependency itself. `status` is `ok`, `unavailable`,
`timeout`, `not_open` for an audit database still being opened (see
[audit](config.md#audit)), or `unknown` before the first check; `since` is
when it took that value. Only Redis is listed as `store`; the memory store is not a
dependency. The reason for a failure is in the log, once when a dependency
goes down and once when it is back. The same checks feed
`catraca_dependency_up` and the other metrics below.

**In Kubernetes**, with the image's configuration (`deploy/catraca.yaml`),
which reads `CATRACA_ADMIN_ADDR` and `CATRACA_DRAIN_DELAY`, the probes go to
the admin port, and the Service exposes only the API's:

```yaml
spec:
  # At least server.drain_delay + server.shutdown_timeout (5s + 30s).
  terminationGracePeriodSeconds: 40
  containers:
    - name: catraca
      env:
        - {name: CATRACA_ADMIN_ADDR, value: ":9090"}
      ports:
        - {name: http, containerPort: 8080}
        - {name: admin, containerPort: 9090}
      livenessProbe:
        httpGet: {path: /healthz, port: admin}
      readinessProbe:
        httpGet: {path: /readyz, port: admin}
```

No `preStop` hook is needed: on SIGTERM the server drains for
`server.drain_delay` by itself, still serving while the endpoint is
removed. Health checks of a load balancer outside the cluster should use
`/readyz` too, so they see the drain. The [Helm chart](kubernetes.md) sets
all of this up.

### GET /metrics

Prometheus metrics in the text format. While [tracing](tracing.md) is on,
the OpenMetrics format is offered too, and Prometheus, which asks for it,
gets the latency histograms with exemplars: the trace of a sampled request
in each bucket.

| metric | type | |
|---|---|---|
| `catraca_decisions_total{action}` | counter | decisions, by action |
| `catraca_rule_matches_total{rule,mode}` | counter | rule matches |
| `catraca_rule_errors_total{rule}` | counter | rules that could not be evaluated |
| `catraca_degraded_decisions_total` | counter | decisions made without some signals: the store failed or missed the deadline, or was skipped because the breaker was open or the decision was shed |
| `catraca_decision_duration_seconds` | histogram | time to decide |
| `catraca_store_call_duration_seconds{call,result}` | histogram | time the store took over a decision's call, `observe` or `mark_leaked`, by `result`: `ok`, `error`, or `timeout` past the deadline. Calls the breaker skipped are not counted |
| `catraca_records_dropped_total` | counter | decisions the engine could not hand to the audit log |
| `catraca_event_times_out_of_bounds_total{bound}` | counter | event times too far from Catraca's clock: `future` ones replaced by the clock's, `past` ones rejected ([limits](#limits)) |
| `catraca_duplicate_events_total{type}` | counter | events sent again with an `id` that had counted already, which did not count again ([retries](#retries)) |
| `catraca_store_breaker_state{state}` | gauge | 1 for the state the [store breaker](config.md#engine) is in, `closed`, `open` or `half_open`, and 0 for the others |
| `catraca_store_breaker_transitions_total{from,to}` | counter | changes of the breaker's state |
| `catraca_short_circuited_decisions_total` | counter | decisions that skipped the store because the breaker was open |
| `catraca_http_request_duration_seconds{route,status}` | histogram | HTTP requests, by route pattern (`POST /v1/decide`, `unmatched`) and status |
| `catraca_admission_inflight{route}` | gauge | decisions on `/v1/decide` and `/v1/events`, and feedback requests, holding an [admission](config.md#admission) slot |
| `catraca_admission_shed_total{route}` | counter | requests that found no slot in time: decided without the store, or answered `503` with `Retry-After` |
| `catraca_admission_limit{group}` | gauge | how many slots there are for `decisions` (adaptive unless `server.inflight_limit` is `static`) and for `feedback` |
| `catraca_audit_recorded_total`, `_dropped_total`, `_failed_total` | counter | audit log writes |
| `catraca_audit_rejected_total` | counter | decisions the audit database refused one at a time while it wrote the rest of their batch, also counted as failed ([details](audit.md#how-decisions-are-written)) |
| `catraca_audit_queued` | gauge | decisions waiting to be written |
| `catraca_audit_write_duration_seconds{result}` | histogram | each attempt to write a batch of decisions, by `result`: `ok`, `refused` (a value was refused; the batch is then written a decision at a time) or `error` |
| `catraca_audit_retention_deleted_total{table}` | counter | rows deleted by [retention](audit.md#retention): `decisions` (with their matches and labels), `outbox` and `leak_reports` |
| `catraca_audit_retention_errors_total` | counter | retention runs that failed |
| `go_sql_*{db_name="audit"}` | gauge, counter | the audit database's connection pool: open, in use, idle, waits for a connection and their duration |
| `catraca_hooks_enqueued_total`, `_enqueue_errors_total`, `_enqueue_deferred_total`, `_delivered_total`, `_retries_total`, `_dead_total`, `_expired_total` | counter | effect webhook deliveries ([metrics](hooks.md#metrics)) |
| `catraca_hooks_attempts_total{hook,outcome}` | counter | delivery attempts of each hook, by what became of the delivery: `delivered`, `retry` or `dead` |
| `catraca_hooks_attempt_duration_seconds{hook}` | histogram | how long each hook's requests took, until the answer or the error |
| `catraca_hooks_delivery_latency_seconds{hook}` | histogram | from when a delivery was queued to its `2xx`, retries included: how late the effect was carried out |
| `catraca_hooks_pending{hook}`, `_pending_due{hook}`, `_oldest_pending_age_seconds{hook}` | gauge | the outbox backlog of each hook, counted every 15s; aggregate several instances with `max` |
| `catraca_feedback_outcomes_total{provider,outcome}` | counter | what the feedback endpoints did ([outcomes](feedback.md#metrics)) |
| `catraca_secret_scanning_outcomes_total{outcome}` | counter | batches and leaked-key reports ([outcomes](secret-scanning.md#metrics)) |
| `catraca_secret_scanning_reports{status}` | gauge | leaked-key reports `pending` and `dead`, read from the audit database at scrape time |
| `catraca_secret_scanning_oldest_pending_seconds` | gauge | how long ago the oldest pending leaked-key report arrived |
| `catraca_secret_scanning_attempt_duration_seconds{outcome}` | histogram | each attempt at a leaked-key report, resolving and deciding, by outcome |
| `catraca_secret_scanning_report_latency_seconds{outcome}` | histogram | from when a report was queued to when it was done (`leaked`, `not_found`) or given up (`resolve_failed`, `decide_failed`) |
| `catraca_ruleset_info{version}` | gauge | 1, labeled with the current ruleset version |
| `catraca_ruleset_rules{mode}` | gauge | rules by mode, as applied: a rule the gate holds counts as shadow |
| `catraca_ruleset_loads_total{result}` | counter | loads at start and reloads, by SIGHUP, the API or the watch, `ok` or `error` |
| `catraca_ruleset_loaded_timestamp_seconds{source}` | gauge | when the current ruleset took effect, labeled with what loaded it: `start`, `watch`, `signal` or `api` |
| `catraca_ruleset_gate_failures{status}` | gauge | rules the file newly enforces that had not passed the [precision gate](config.md#gate) when it loaded, by `insufficient_labels`, `below_precision` and `unavailable`: held in shadow mode with `gate.on_load: enforce`, enforcing with `warn` |
| `catraca_dependency_up{dependency}` | gauge | 1 when the last check of `store` (Redis) or `audit` succeeded, else 0 |
| `catraca_dependency_check_duration_seconds{dependency}` | gauge | how long the last check took; a timeout counts as 2s |
| `catraca_dependency_check_failures_total{dependency}` | counter | checks that failed or timed out |
| `catraca_build_info{version,goversion}` | gauge | 1, labeled with the build |

plus the standard `go_*` and `process_*` metrics. Every series of a
labeled metric whose values are known up front (each action, each
configured hook, each outcome) exists from the start at 0, so a rate over
it is 0 rather than missing.

[docs/slo.md](slo.md) builds service level objectives on these metrics, and
[`deploy/prometheus/rules.yaml`](../deploy/prometheus/rules.yaml) has the
recording rules and alerts: burn-rate alerts on the objectives, and alerts
on the causes behind them, such as the breaker open, a dependency down, an
outbox or leaked-key queue falling behind, dead deliveries and reports,
lost effects and audit records, a ruleset that fails to load, and rules
the [gate on load](config.md#gate) holds in shadow mode.

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
{"time":"2026-10-15T21:25:43.490Z","level":"INFO","msg":"request","request_id":"b2dfbafcacbab0f963ec8b7177322d5c","method":"POST","route":"POST /v1/decide","path":"/v1/decide","status":200,"bytes":387,"duration_ms":0.498,"remote":"127.0.0.1:58358","scope":"decide","scope_check":"allowed","decision_id":"01M50Q9TE1EPGZCTSX7N6NPC78","action":"block","client":"send-path"}
```

`client` is the name of the token, and `scope` and `scope_check` the scope
the route needs and whether the token had it (`allowed` or `denied`), on
every route that takes a token.

Requests to `/healthz`, `/readyz` and `/metrics` are logged at debug level.
Tokens, secrets and message content are never logged.

While [tracing](tracing.md) is on, each line also has the request's
`trace_id` and `span_id`, whether or not the trace was sampled, so a line
leads to its trace and a trace to its line. A request that sent a W3C
`traceparent` header gets that trace's id.
