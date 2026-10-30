# Writing rules

A Catraca ruleset is a YAML file kept in git and reviewed like code. Each rule
is a [CEL](https://cel.dev) expression over the signals of an event, the
action to take when it matches, and what to do when it cannot be evaluated.
This page covers the file format, the expression environment, how decisions
are combined, fixtures, versioning and reloading. The starter ruleset in
[`rules/default.yaml`](../rules/default.yaml) is a working example of all of
it.

The life of a rule:

1. Write it in **shadow** mode, with a fixture that shows when it matches
   and when it does not (`catraca rules test`).
2. Backtest it on labeled traffic (`catraca replay`) to tune thresholds.
3. Ship it. Shadow rules are evaluated and recorded on every decision but
   never change the action.
4. Label its matches. Once its measured precision clears the gate
   (`catraca rules gate`), switch it to **enforce**. The server checks the
   gate too, and keeps a rule that has not cleared it in shadow mode.

## The file

```yaml
version: 1

defaults:
  mode: shadow        # new rules never enforce by accident
  on_error: open

lists:
  url_shorteners: [bit.ly, tinyurl.com, t.co, is.gd]

rules:
  - id: new-account-burst
    description: Accounts younger than a day sending over 100 emails a minute
    when: event.type == "send" && account.age_hours < 24 && account.sends_1m > 100
    action: throttle
    retry_after: 60s
    reason: New account sending at burst volume
```

| key | |
|---|---|
| `version` | Required. The file format; `1` is the only one so far. |
| `defaults` | Optional. `mode` and `on_error` for rules that do not set them. Without it, rules are `shadow` and fail `open`. |
| `lists` | Optional. Named lists of strings, read with `in_list` and `any_in_list`. Names are `[a-z][a-z0-9_]*`. |
| `rules` | Required, may be empty. Evaluated in file order on every event. |

Parsing is strict: an unknown or repeated key is an error, reported with its
line and, for likely typos, a suggestion (`unknown field "retry"`,
`did you mean retry_after?`). YAML anchors and aliases work; merge keys (`<<`)
do not, since `defaults` covers what they would be used for.

## Rule fields

| field | required | |
|---|---|---|
| `id` | yes | Unique, kebab-case (`new-account-burst`). It names the rule in decisions, metrics, labels and the audit log, so treat a rename as a new rule. |
| `description` | | What the rule catches and why the thresholds are what they are. Written for the reviewer and the on-call person reading a decision. |
| `when` | yes | A CEL expression that must return a bool. |
| `action` | | `flag`, `throttle`, `hold` or `block`. Defaults to `flag`. |
| `mode` | | `shadow` or `enforce`. Defaults to `defaults.mode`, else `shadow`. |
| `on_error` | | `open` or `closed`. Defaults to `defaults.on_error`, else `open`. |
| `effects` | | Names of hooks to call when the rule is enforced and matches, such as `revoke_key`. Names are `[a-z][a-z0-9_]*`. |
| `retry_after` | throttle only | How long the platform should wait before retrying, as a Go duration (`30s`, `5m`). Required for `throttle`, rejected for other actions. |
| `reason` | yes | A sentence shown to the platform and written to the audit log. Say what happened, not what the rule is called. |
| `owner` | | Who to ask about the rule. |
| `tags` | | Free-form labels for grouping. |
| `override` | | `{by, reason, at}`: a recorded decision to enforce a rule that has not passed the precision gate. See [Overrides](#overrides). |

## Actions and how they combine

Every rule is evaluated for every event. Then:

- The decision's action is the **most severe** action among the enforced
  rules that matched: `allow` < `flag` < `throttle` < `hold` < `block`. With
  no enforced match it is `allow`.
- When the action is `throttle`, `retry_after` is the **largest** among the
  enforced throttle rules that matched. When something more severe wins, it
  is empty.
- Shadow rules that matched are listed in the decision's `shadow` field with
  the action they would have taken. They never change the action.
- Every decision lists the enforced matches, the shadow matches and the
  rules that could not be evaluated, each with its reason, plus the ruleset
  version.

| action | what the platform should do |
|---|---|
| `flag` | Send, and record the event for review. |
| `throttle` | Reject this attempt and retry after `retry_after`. |
| `hold` | Queue the email until a person reviews it. |
| `block` | Refuse the event. |

There is no `allow` action for rules: a rule cannot overrule another one. If
a rule is too broad, narrow its `when`.

## Modes

A **shadow** rule is evaluated and recorded but does not act. Its matches can
be labeled true or false positives, which is how its precision is measured.
An **enforce** rule changes the action and triggers its effects.

The promotion gate (`catraca rules gate`, in CI) fails when an enforced rule
has fewer than `gate.min_labeled` labeled matches or the Wilson lower bound
of its precision is below `gate.min_precision`, unless the rule carries an
`override`. The server applies the same gate when it loads a ruleset
([`gate.on_load`](config.md#gate)): a rule switched to enforce that has not
passed it stays in shadow mode, and the rest of the file loads.

## When a rule cannot be evaluated: `on_error`

A rule fails to evaluate when its expression reads a signal that is absent,
uses a value of the wrong type, or goes over the cost limit. Signals are
absent when:

- the store failed or did not answer within the deadline (the decision is
  then marked `degraded`, and the `event` signals may be all there is);
- the event has no API key, IP or sender domain, so the `key`, `ip` or
  `domain` map is empty;
- the signal does not exist, usually a typo (lint warns about these).

An absent signal is an **error, never `false`**, so the rule's `on_error`
policy decides:

- `open` skips the rule. Detection degrades; good senders are not stopped.
  This is the right choice for almost every rule.
- `closed` counts the rule as matched, with `errored: true` in the decision.
  The rule's action applies but its effects do not run (see
  [Effects](#effects)). Use it only when letting abuse through is worse
  than stopping good traffic while the store is down.

Either way the rule is listed in the decision's `errors`, and
`catraca_rule_errors_total` counts it.

CEL's `&&` and `||` absorb an error when the other side alone decides the
result: `false && <error>` is `false` and `true || <error>` is `true`, in
either order. That makes guards on `event` signals, which are always
present, work as expected:

```yaml
# Fails closed, but only for sends that carry a key: a send without one
# never reads key.leaked, so it is not blocked when the store is down.
when: event.type == "send" && event.api_key_id != "" && key.leaked
on_error: closed
```

Without the `event.api_key_id != ""` guard, every send without a key would
fail to evaluate and, failing closed, be blocked. Lint warns about closed
rules that read `key`, `ip` or `domain` signals without checking
`event.api_key_id`, `event.ip` or `event.from_domain`.

Even guarded, that rule blocks every send with a key while the store is
down, which is why the starter ruleset's `leaked-key-send` fails **open**
instead. It loses little: each Catraca process remembers the leaked keys it
marked or read from the store, and while the store is down `key.leaked` is
`true` for those keys (with no other `key` signal) and absent for the rest.
Known leaked keys stay blocked and everyone else keeps sending. The cost is
a key reported to another replica during the outage: this one does not see
it until the store recovers. See
[Signals](signals.md#leaked-keys-while-the-store-is-down).

`has(account.sends_1m)` and `account.?sends_1m.orValue(0)` test for or
default a missing signal. They turn "unknown" into "known false", which
bypasses `on_error`: use them for optional data such as platform attributes,
not to make a counter look like zero when the store is down.

## The CEL environment

Rules see five variables, each a `map(string, dyn)`:

| variable | signals | present |
|---|---|---|
| `event` | computed from the event alone: `type`, `account_id`, `api_key_id`, `ip`, `from_domain`, `recipients`, `to_domains`, `link_domains`, `links`, `subject_length`, `feedback_kind`, `bounce_type`, `account_action`, `attributes`, `role_recipients`; and from the recipient memory, `suppressed_recipients` and `suppressed_ratio` | always; the two `suppressed_` signals when the store answers |
| `account` | sends, sends from the event's IP, recipients, distinct domains/IPs/keys, bounces, complaints and their rates, `age_hours`, `hourly_baseline_7d`, `volume_ratio_1h`, `new_ip`, `recent_ip` | when the store answers |
| `key` | `sends_1m`, `sends_1h`, `distinct_ips_1h`, `distinct_ips_24h`, `new_ip`, `age_hours`, `leaked` | when the event has an API key; while the store is down, only `leaked`, for keys known to be leaked |
| `ip` | `sends_1m`, `sends_1h`, `distinct_accounts_24h`, `distinct_keys_24h`, `signups_24h` | when the event has an IP |
| `domain` | `sends_1h`, `distinct_accounts_24h`, `complaints_24h` | when From has a domain |

The full list, with windows and definitions, is in the
[Signals section of the design](design.md#signals). Window suffixes are
`_1m`, `_1h`, `_24h` and `_7d`. Counts are ints, rates are doubles in
[0, 1], and ages are hours as doubles. Ints and doubles compare directly
(`account.age_hours < 24` works), but arithmetic needs matching types; use
`ratio` to divide.

Signals include the event being decided: the first send of a new account
sees `account.sends_1m == 1`.

### Functions

| function | |
|---|---|
| `in_list(name, value) bool` | `value` is in the list `name`. Exact, case-sensitive match. |
| `any_in_list(name, values) bool` | Some item of the list `values` is in the list `name`. |
| `domain_of(address) string` | The lowercased domain of an email address, `""` when it has none. Accepts `Name <user@host>`. |
| `ratio(a, b) double` | `a / max(b, 1)`, for any numbers. Safe on zero denominators. |

The list name must be a string literal, so the load checks that the list
exists: `in_list("url_shortener", ...)` fails with `unknown list
"url_shortener" (did you mean url_shorteners?)`.

The standard CEL library is available: `size`, `contains`, `startsWith`,
`endsWith`, `matches` (RE2), `in`, the macros `all`, `exists`,
`exists_one`, `map` and `filter`, and optional field syntax:

```yaml
when: >-
  event.type == "send"
  && event.attributes.?plan.orValue("") == "free"
  && event.to_domains.exists(d, d.endsWith(".edu"))
```

### Cost limit

Expressions without comprehensions evaluate each node once, so their cost
is bounded by their size and inputs. Expressions with a comprehension (`all`,
`exists`, `exists_one`, `map`, `filter`) are limited to a runtime cost of
10,000 (`rules.MaxCost`), about ten thousand comparisons, so a nested loop
over a large list cannot stall the decision. A rule over the limit fails to
evaluate and follows `on_error`.

## Lists

```yaml
lists:
  url_shorteners: [bit.ly, tinyurl.com, t.co]
  disposable_domains: [mailinator.com, guerrillamail.com]
```

Lists are sets of exact strings; lookups are constant time, so long lists are
fine. Matching is case-sensitive and addresses are lowercased before signals
are computed, so write domain entries in lowercase. Lint warns about lists that
no rule uses, empty lists and duplicate entries.

## Effects

```yaml
effects: [revoke_key, notify]
```

An effect is the name of an outgoing webhook configured in `catraca.yaml`.
Effects run only when the rule is **enforced** and its `when` is true. A
rule that matches only because it fails closed (`errored: true`) takes its
action but runs no effects: during a store outage it would otherwise revoke
or suspend everything it covers. Deliveries go through a durable outbox,
are retried, and are idempotent per decision and effect, so a webhook may be
delivered more than once but represents one decision. Effects on a shadow
rule never run; lint points them out.

## Overrides

The precision gate needs labeled matches, which a new rule does not have. An
`override` records a deliberate decision to enforce anyway:

```yaml
- id: leaked-key-send
  when: event.type == "send" && event.api_key_id != "" && key.leaked
  action: block
  mode: enforce
  on_error: open
  effects: [revoke_key]
  reason: This API key was found in public and must be rotated
  override:
    by: alice@example.com
    reason: >-
      A reported leaked key is a fact, not a guess, so the rule enforces
      before it has labeled matches.
    at: 2026-10-15
```

`by`, `reason` and `at` (a date or an RFC 3339 time) are all required. The
override lives next to the rule, so it is reviewed with it and shows up in
`git blame`.

Rules that carry out an operator's decision are the other natural case.
[`account.state`](signals.md#account-states) is set through the API, so a
rule on it has no false positives for the gate to measure:

```yaml
- id: account-suspended
  when: event.type == "send" && event.account_id != "" && account.state == "suspended"
  action: block
  mode: enforce
  on_error: open
  reason: This account is suspended
  override:
    by: alice@example.com
    reason: >-
      An operator suspended the account; the rule carries out that
      decision.
    at: 2026-10-29
```

To exempt accounts the operator trusts from a noisy heuristic, add
`&& account.state != "trusted"` to its `when`, as the starter ruleset does
for its volume rules.

## Load-time checks and lint

A ruleset that fails any of these checks does not load, and every problem is
reported with its line:

- unknown or repeated keys, missing `version`, `rules`, `id`, `when` or
  `reason`;
- an `id` that is not kebab-case or is used twice;
- an unknown `action`, `mode` or `on_error`, or `allow` as an action;
- `retry_after` missing on a throttle rule, set on any other, or not a
  positive duration;
- malformed effect or list names, or an incomplete `override`;
- a CEL syntax or type error, an expression that cannot return a bool, an
  unknown function, or an unknown list name.

Lint warnings do not stop a load; `catraca rules check` prints them:

- an enforced rule that inherits `on_error` from `defaults` instead of
  stating it;
- effects or an override on a shadow rule;
- a signal name that does not exist, such as `account.send_1m`;
- a closed rule reading `key`, `ip` or `domain` signals without a guard;
- a constant `when`;
- unused, empty or duplicate list entries.

## Fixtures

A fixture file describes events by their signals and states what the
ruleset should conclude, so a rule change comes with a test like code does.
[`rules/default.test.yaml`](../rules/default.test.yaml) covers every rule of
the starter ruleset. A short one, for a ruleset with the rules
`leaked-key-send` and `new-account-burst`:

```yaml
# Signals every case starts from: a healthy, established sender.
base:
  event: {type: send, api_key_id: key_1, link_domains: [example.com]}
  account: {sends_1m: 2, age_hours: 4000}
  key: {leaked: false}

cases:
  - name: a day-old account sending 150 a minute bursts
    signals:
      account: {age_hours: 5, sends_1m: 150}
    expect:
      matches: [new-account-burst]

  - name: an established account may send 150 a minute
    signals:
      account: {sends_1m: 150}
    expect:
      matches: []

  - name: when the store is down a send with an API key is allowed
    signals:
      account: null    # null removes a map or a signal: absent
      key: null
    expect:
      action: allow
      errors: [leaked-key-send, new-account-burst]
```

- `base` is optional. Each case's `signals` are applied on top of it, map by
  map and key by key. A `null` value removes a signal or a whole map, which
  is how a case simulates a store failure or an event without a key.
- Values take the types the catalog produces: `age_hours: 5` becomes the
  double `5.0` and `sends_1m: 150` the int `150`, so fixtures behave like
  production. A value of the wrong type, such as `new_ip: 1`, fails the load.
- `expect` needs at least one of:

| field | checks |
|---|---|
| `action` | the final action |
| `retry_after` | the final retry_after (`"0"` for none) |
| `enforced` | the enforced rules that matched |
| `shadow` | the shadow rules that matched |
| `matches` | the rules that matched in either mode |
| `errors` | the rules that failed to evaluate |

Rule lists are compared as sets and must be exact: `[]` means none, and a
field left out is not checked. `matches` does not depend on modes, so it
keeps passing when a rule is promoted from shadow to enforce; `action`,
`enforced` and `shadow` pin down what the current modes do. Prefer `matches`
unless the case is about the action.

A failing case shows what differed and why rules failed to evaluate:

```
FAIL  a day-old account sending 150 a minute bursts (line 12)
        matches: want [new-account-burst], got [] (missing new-account-burst)
        note: rule new-account-burst failed to evaluate: signal account.age_hours is absent
```

Fixtures run with `catraca rules test`, or from Go:

```go
rs, err := rules.LoadFile("rules/default.yaml")
cases, err := rules.LoadFixtures("rules/default.test.yaml")
if err := rules.RunFixtures(rs, cases).Err(); err != nil {
	t.Fatal(err)
}
```

Give every rule at least one case where it matches and one, close to the
threshold, where it does not.

## Explaining a decision

To see the signals a real event has, and what each rule made of them, send
the event to [`POST /v1/rules/explain`](api.md#post-v1rulesexplain). It
answers every signal by map and, for every rule, whether it matched, its
action and mode, and why it could not be evaluated, without deciding the
event. Without `?observe=true` only the `event` signals are present, and
nothing counts; with it, which needs the `decide` scope too, the signals
come from the store, which counts the event unless it is sent with the `id`
of a decision made within `engine.dedupe_ttl`. The answer's `counted` says
which.

Its `signals` object is written as a fixture case's `signals`, so it can be
saved, edited and explained again offline, with no server or store:

```sh
curl -s -X POST "$CATRACA/v1/rules/explain?observe=true" -H "Authorization: Bearer $TOKEN" \
  -d @event.json > explained.json
catraca rules explain rules/default.yaml explained.json
```

A signals file can also be written by hand, in YAML or JSON. Signals it
leaves out are absent, which the output makes plain:

```yaml
event: {type: send, recipients: 40, link_domains: [bit.ly]}
account: {sends_1m: 150, age_hours: 5}
key: null    # absent, as for an event without an API key
```

```
RULE                               MATCHED  MODE     ACTION    ERROR
leaked-key-send                    no       enforce  block     signal event.api_key_id is absent (on_error: open)
account-suspended                  no       enforce  block     signal event.account_id is absent (on_error: open)
new-account-burst                  no       shadow   throttle  signal account.state is absent (on_error: open)
account-takeover-volume            no       shadow   hold      -
...

action: allow, ruleset version 257a38fdadb5
```

A rule that could not be evaluated shows as matched when its `on_error` is
`closed`, as it counts in a decision. Turn a case worth keeping into a
fixture by copying its signals into one.

## Versioning

The ruleset version is the first 12 hex characters of a SHA-256 over the
ruleset's canonical content: the rules with defaults applied, in order, and
the lists. Comments, formatting, key order and writing a default explicitly
do not change it; any change to a rule's behavior, reason, description,
owner, tags or override, to a list, or to rule order does. Every decision
stores the version it was made with, so each one traces back to a commit.

## Reloading

The server reloads the ruleset when the file's content changes (every
instance checks it every [`rules.watch_interval`](config.md#rules), 5
seconds by default, and loads a change once it has settled for two
seconds), on `POST /v1/rules/reload` and, on Unix, on `SIGHUP`. A load
parses and compiles the file, as `catraca rules check` does, holds back in
shadow mode the rules the [precision gate](config.md#gate) does not let
enforce yet, and swaps the result in atomically:

- decisions in flight finish on the ruleset they started with;
- a file that fails to load leaves the current ruleset serving, the error
  is logged once, and a reload through the API returns it;
- a `Ruleset` encodes to JSON with defaults applied and its version, which
  is what `GET /v1/rules` serves; held rules show as `shadow` there, and
  `/readyz?verbose` lists them with the file's own version.

In a Go program, a `rules.Holder` keeps a ruleset and swaps it the same
way:

```go
var holder rules.Holder
if _, err := holder.Load("rules/default.yaml"); err != nil {
	log.Fatal(err)
}
// Later, after editing the file:
rs, err := holder.Reload()
```

## Backtesting

`catraca replay` runs a ruleset over a JSONL file of labeled events, one per
line, in time order:

```json
{"event": {"type": "send", "account_id": "acct_1", "time": "2026-10-01T10:00:00Z", "to": ["a@example.com"]}, "label": "legit"}
{"event": {"type": "send", "account_id": "acct_2", "time": "2026-10-01T10:00:02Z", "to": ["b@example.org"]}, "label": "abusive"}
```

Events go through a fresh in-memory catalog and the same engine that serves
production, so counters rebuild as they were. Lines without a label feed
the counters but are not scored. The report gives, for every rule and for
the enforced and shadow rules together, true and false positives and
negatives, precision, recall and F1, treating a match as a prediction of
"abusive", plus the effective action broken down by label.

The labels given in production make such a file: `catraca audit export`
writes the audit log's decisions in this format, labeled from them.
With the default `audit.event_detail: minimal` the exported events lack
recipients, subject and links, so rules that read them cannot be measured
this way; see [exporting labeled decisions](audit.md#exporting-labeled-decisions-for-a-backtest).

## Checklist for a new rule

- [ ] It starts in shadow mode.
- [ ] `when` checks `event.type` first, and guards `key`, `ip` and `domain`
      reads with the matching `event` signal.
- [ ] Thresholds need enough volume to mean something (rates over a minimum
      number of sends).
- [ ] `reason` tells the platform what happened in one sentence.
- [ ] `description` says what it catches, why, and what legitimate traffic
      looks similar.
- [ ] A fixture shows a match and a near miss.
- [ ] `on_error: closed` only if letting abuse through is worse than
      blocking good senders while the store is down.
