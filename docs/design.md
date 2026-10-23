# Catraca design

Catraca is a self-hosted anti-abuse engine for platforms that send email: an
email API, a newsletter tool, a SaaS app with transactional mail, or a
self-hosted platform such as useSend or Postal. The platform asks Catraca
before each send, reports delivery feedback and account activity, and gets
back a decision with the rules behind it.

Principles, in order:

1. **Default to trust.** Good senders should never notice Catraca. Friction
   goes where it costs abusers the most.
2. **A false positive is a bug.** Every rule starts in shadow mode, every
   decision carries its reasons, every reversal is a label, and a rule is
   enforced only after its measured precision clears a gate.
3. **Fail safe.** Each rule declares what happens when it cannot be
   evaluated. A broken store degrades detection; it never blocks everyone.
4. **Fast.** A send decision is one store round trip plus CEL evaluation,
   inside a deadline measured in milliseconds.
5. **Traceable.** Logs, metrics and an audit trail for every action.

## Packages

```
cmd/catraca          CLI: serve, config check, rules check|test|gate, replay, report, label
internal/event       Event types (shared)
internal/decision    Decision, Match, Action, Mode, OnError (shared)
internal/signal      Signal Set + Catalog interface (shared); catalog impl
internal/store       Counter store: memory and Redis
internal/rules       YAML ruleset, CEL environment, compile, lint, evaluate, fixtures
internal/engine      Decide: signals under a deadline, rules, combine, fail-safe
internal/replay      Backtest a ruleset on labeled events (precision, recall)
internal/audit       Decision log, labels, rule stats: SQLite and Postgres
internal/precision   Wilson interval, promotion gate, report
internal/hooks       Signed outgoing webhooks for effects, with a durable outbox
internal/feedback    SES (via SNS, signature verified), useSend, generic
internal/secretscan  GitHub secret scanning partner endpoint
internal/api         HTTP server, auth, metrics
internal/config      catraca.yaml
internal/app         Wiring: build everything from a config, serve, shut down in order
signature            Catraca-Signature: sign and verify (public, for receivers)
```

Dependency direction: `event` and `decision` import nothing internal.
`signal`, `rules` import `event`/`decision`. `engine` imports `signal`,
`rules`, `decision`, `event` and defines the interfaces it calls
(`Recorder`, `Dispatcher`). `audit`, `hooks` implement those. `feedback` and
`secretscan` produce events and call a `Decider` interface they define
(`Decide(ctx, event.Event) (decision.Decision, error)`). `app` wires
everything together behind `api`, and `cmd` runs `app` and the offline
tools. Only `app` and `cmd` import `api`, only `cmd` imports `app`, and
nothing imports `cmd`. `signature` is the one public
package, so platforms in Go can verify Catraca's requests and sign their own;
it imports nothing from the module, and `hooks`, `feedback` and
`secretscan` use it.

## Signals

Signals are computed by `signal.Catalog.Observe`, which records the event and
reads the values in one store round trip. With Redis that round trip is one
Lua script call (one per hash slot on a cluster) that returns only the
counts; [benchmarks](benchmark.md) has the measurements. Counters are sliding windows keyed
by event time. Windows are written as suffixes: `_1m`, `_1h`, `_24h`, `_7d`.
Rates are `float64` in [0, 1]; counts are `int64`; ages are hours as
`float64`.

`event` (computed from the event alone, always present):

| name | type | meaning |
|---|---|---|
| type | string | event type |
| account_id, api_key_id, ip | string | as sent |
| from_domain | string | domain of From |
| recipients | int | len(To) |
| to_domains | list(string) | distinct recipient domains |
| link_domains | list(string) | distinct hostnames of Links |
| links | int | len(Links) |
| subject_length | int | runes in Subject |
| feedback_kind, bounce_type | string | for feedback events |
| account_action | string | for account events |
| attributes | map(string,string) | platform attributes |

`account`:

| name | meaning |
|---|---|
| sends_1m, sends_1h, sends_24h, sends_7d | send events |
| recipients_1h, recipients_24h | sum of recipients |
| distinct_recipient_domains_1h, distinct_recipient_domains_24h | distinct To domains |
| distinct_ips_24h, distinct_keys_24h | distinct IPs / API keys used |
| bounces_24h, hard_bounces_24h, complaints_24h, deliveries_24h | feedback events |
| bounce_rate_24h | bounces_24h / max(sends_24h, 1) |
| hard_bounce_rate_24h | hard_bounces_24h / max(sends_24h, 1) |
| complaint_rate_24h | complaints_24h / max(sends_24h, 1) |
| age_hours | since AccountInfo.CreatedAt, else since first seen |
| hourly_baseline_7d | sends_7d / 168 |
| volume_ratio_1h | sends_1h / max(hourly_baseline_7d, 1) |
| new_ip | IP not used by the account in the last 30 days |
| ip_sends_24h, ip_sends_7d | send events of the account from this IP |
| recent_ip | no send from this IP between 24h and 7d ago: ip_sends_7d == ip_sends_24h, so it stays true for the account's first day on the IP |

`key` (present when the event has api_key_id):

| name | meaning |
|---|---|
| sends_1m, sends_1h | send events with the key |
| distinct_ips_1h, distinct_ips_24h | distinct IPs using the key |
| new_ip | IP not used with the key in the last 30 days |
| age_hours | since first seen |
| leaked | the key was reported leaked (MarkLeaked) |

When the store fails, every store-backed map is absent except that, for a
key this process knows was leaked, `key` holds `leaked: true`. The catalog
keeps a bounded in-memory set of leaked key ids, filled by `MarkLeaked`,
`key_leak` events and store reads that see a leaked key, so a rule that
fails open still blocks known leaked keys through an outage.

`ip` (present when the event has an IP): `sends_1m`, `sends_1h`,
`distinct_accounts_24h`, `distinct_keys_24h`, `signups_24h` (account events
with action "signup").

`domain` (sender domain, present when From has one): `sends_1h`,
`distinct_accounts_24h`, `complaints_24h`.

Which counters an event increments: send events increment sends, recipients
and distinct sets; feedback events increment bounces/complaints/deliveries on
the account and sender domain of the original send (the feedback event
carries account_id and, when known, from); account events increment
`ip.signups_24h` for signups and record first-seen.

## Rules

A ruleset is a YAML file kept in git and reviewed like code.

```yaml
version: 1
defaults:
  mode: shadow        # new rules never enforce by accident
  on_error: open
lists:
  url_shorteners: [bit.ly, tinyurl.com, t.co, is.gd]
rules:
  - id: leaked-key-send
    description: A key reported leaked is used to send
    when: event.type == "send" && key.leaked
    action: block
    mode: enforce
    on_error: open      # known leaked keys stay blocked when the store is down
    effects: [revoke_key]
    reason: API key was found in public and must be rotated
  - id: new-account-burst
    when: event.type == "send" && account.age_hours < 24.0 && account.sends_1m > 100
    action: throttle
    retry_after: 60s
    reason: New account sending at burst volume
```

Fields: `id` (required, unique, kebab-case), `description`, `when` (CEL,
must return bool), `action` (flag|throttle|hold|block), `mode`
(shadow|enforce), `on_error` (open|closed), `effects` (names of hooks to call
when the rule is enforced and its `when` is true), `retry_after` (for throttle),
`reason` (required: shown to the platform and in the audit log), `owner`,
`tags`, and `override` (`{by, reason, at}`: a recorded decision to enforce a
rule that has not passed the gate).

CEL environment: variables `event`, `account`, `key`, `ip`, `domain`, all
`map(string, dyn)`. Functions: `in_list(name, value) bool`,
`any_in_list(name, list) bool`, `domain_of(address) string`,
`ratio(a, b) double` (a / max(b, 1)). Rules are compiled at load; an unknown
list name, a non-bool expression or a syntax error fails the load. A rule
that reads an absent signal errors at evaluation and follows `on_error`.

The ruleset version is a short hash of the file's canonical content and is
stored in every decision.

Fixtures (`catraca rules test`) are YAML files of events with signal values
and the expected matches, so a rule change comes with a test like code does.

## Engine

`Decide(ctx, ev)`:

1. Validate and normalize the event, assign IDs.
2. `Observe` signals under the configured deadline (default 10 ms). On error,
   mark the decision degraded and continue with what was returned.
3. Evaluate every rule. A matching enforced rule contributes its action; a
   matching shadow rule is recorded in `Shadow`. An evaluation error follows
   `on_error`: open skips the rule, closed counts it as matched (`Errored`):
   its action applies, its effects do not, so an outage never fires effects
   for every event.
4. The action is the most severe enforced match; Throttle carries the largest
   retry_after among enforced throttles.
5. For key_leak events, call `Catalog.MarkLeaked` before evaluating.
6. Hand the decision to the Recorder (non-blocking) and, when enforced
   matches that are not `Errored` have effects, to the Dispatcher.
7. Metrics: decisions by action, matches by rule and mode, errors by rule,
   degraded decisions, latency histogram.

## Audit and labels

Every decision is recorded with a minimal copy of the event by default
(type, account, key, IP, from domain, recipient count, recipient domains, a
hash of the subject): no message content. Labels attach to a decision:
`true_positive`, `false_positive` (a reversal of an enforced decision, or a
reviewer's verdict on a shadow match), with who, why and when. Labels are
per decision and rule.

The writer inserts decisions in batches; a batch the database refuses is
written one decision at a time, so a decision it cannot store loses only
itself. An optional retention deletes unlabeled decisions and finished
deliveries in small batches, and keeps labeled decisions longer (forever by
default), because the precision gate counts them.

## Precision gate

For each rule and window: matches, labeled matches, true positives, false
positives, precision and its Wilson 95% lower bound. A shadow rule may be
promoted to enforce when it has at least `gate.min_labeled` labeled matches
(default 30) and the lower bound is at least `gate.min_precision` (default
0.9). `catraca rules gate` checks every enforced rule of a ruleset against
the audit database and fails (exit 1) when one is below the gate without an
`override`: run it in CI. `catraca report` lists rules whose precision
dropped below the gate as candidates to retire.

## Effects and hooks

An enforced rule with `effects` triggers outgoing webhooks configured by
name (`revoke_key`, `suspend_account`, `notify`, ...). Payload: effect,
decision id, event type, account, key, rule, reason. Signed with
HMAC-SHA256 over `timestamp.body` in a `Catraca-Signature: t=..,v1=..`
header (package `signature`; the generic feedback endpoint and the secret
scanning resolver use the same scheme). Deliveries are written to an outbox table in the audit database
first, retried with exponential backoff and jitter, and are idempotent per
(decision id, effect).

## Feedback

- `POST /v1/feedback/ses`: Amazon SES notifications delivered through SNS.
  The SNS signature is verified (certificate fetched only from an
  `sns.<region>.amazonaws.com` host over HTTPS, cached), subscription
  confirmations are confirmed when the topic ARN is allowed, and bounce,
  complaint and delivery notifications become feedback events. The account
  is read from a configurable SES message tag or header.
- `POST /v1/feedback/usesend`: useSend webhooks, signature verified.
- `POST /v1/feedback`: a generic JSON feedback event.

## Leaked keys

`POST /v1/secret-scanning/github` implements GitHub's secret scanning partner
endpoint: verify the ECDSA signature with GitHub's published keys (cached,
refreshed on an unknown key id), accept the batch and answer quickly, then,
for each token, ask the platform's resolver hook which API key it is, emit a
key_leak event, and answer GitHub's feedback format (true or false
positive) when configured.

## API

All `/v1` routes need a bearer token, except the feedback and secret
scanning routes, which authenticate by signature.

| route | |
|---|---|
| POST /v1/decide | decide an event (sends: synchronous) |
| POST /v1/events | record an event (feedback, account): 202 + decision |
| GET /v1/decisions/{id} | a decision and its labels |
| POST /v1/decisions/{id}/labels | label a decision (reversal = false_positive) |
| GET /v1/rules | the loaded ruleset and its version |
| POST /v1/rules/reload | reload the ruleset from disk |
| GET /v1/stats/rules?since=720h | precision per rule |
| POST /v1/feedback, /v1/feedback/ses, /v1/feedback/usesend | feedback |
| POST /v1/secret-scanning/github | GitHub partner endpoint |
| GET /healthz, /readyz, /metrics | health and Prometheus metrics |
