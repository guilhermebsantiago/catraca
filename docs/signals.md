# Signals

Signals are the values rules read. For every event, Catraca records the event
in its counters and reads them back in one store round trip, then hands the
results to the rules as five CEL maps: `event`, `account`, `key`, `ip` and
`domain`.

```yaml
when: event.type == "send" && account.age_hours < 24.0 && account.sends_1m > 100
```

Types are CEL types: `int` (a 64-bit integer), `double`, `bool`, `string`,
`list(string)` and `map(string, string)`. Compare doubles with double literals
(`24.0`, not `24`) and ints with int literals.

## Windows

Counters are sliding windows over **event time**: the `time` the platform
reports, not the time Catraca processed the event. Replaying old events in
order therefore reproduces the values they had. The window is the suffix:
`_1m`, `_1h`, `_24h`, `_7d`.

The server bounds event times by its clock, so one wrong time cannot move
the windows of everyone after it: a time more than `engine.max_future_skew`
(5 s) ahead counts as the time the event arrived, and an event more than
`engine.max_event_age` (7 days, the longest window) old is rejected. A late
event within those bounds keeps its time and lands in the windows it belongs
to. See [limits](api.md#limits).

Every count includes the event being decided. The first send of an account
sees `account.sends_1m == 1`.

Each window is split into 60 buckets. An event is always counted while it is
younger than the window minus one bucket, never once it is as old as the
window, and in between it is counted until its bucket leaves the window:

| window | bucket | an event counts for at least | and at most |
|---|---|---|---|
| `_1m` | 1 s | 59 s | 1 min |
| `_1h` | 1 min | 59 min | 1 h |
| `_24h` | 24 min | 23 h 36 min | 24 h |
| `_7d` | 2 h 48 min | 6 d 21 h 12 min | 7 d |

Distinct counts (`distinct_*`) are exact with the memory store. The Redis store
estimates them with HyperLogLog: exact for small sets, within 0.81% (one
standard error) for large ones.

## When a signal is absent

A rule that reads an absent signal fails, and its `on_error` policy decides:
`open` skips the rule, `closed` counts it as matched.

- `event` is always present, with every signal in it.
- `account` is present when the event has an `account_id`.
- `key` is present when the event has an `api_key_id`.
- `ip` is present when the event has an `ip`.
- `domain` is present when `from` has a domain.
- `account.new_ip`, `account.ip_sends_24h`, `account.ip_sends_7d`,
  `account.recent_ip` and `key.new_ip` are absent when the event has no `ip`.
- When the counter store fails or does not answer within the deadline, only
  `event` is present and the decision is marked degraded, with one
  exception: for a key this Catraca process knows was leaked, `key` holds
  `leaked: true` and nothing else.

### Leaked keys while the store is down

Each Catraca process keeps the ids of the leaked keys it knows in memory:
those it marked (a `key_leak` event or `MarkLeaked`, even when the store
write failed) and those a store read showed as leaked, so a key reported to
another replica is learned the next time it is used here. When the store
fails, `key.leaked` is `true` for those keys and absent for every other
key, so a rule like `leaked-key-send` can fail open without letting known
leaked keys send. The trade-off: a key reported to another replica during
the outage is not seen here until the store recovers. Keys this process
knows are written back to the store when they are next used, so a report
whose store write failed reaches every replica once the store is back.

The set holds up to 10,000 keys, about 1.5 MB, and forgets the least
recently seen key beyond that. The store keeps every leaked key, so the cap
only limits what this process can answer during an outage. The set starts
empty after a restart and fills as leaked keys are used.

## What each event records

| event | records |
|---|---|
| `send` | account: sends, sends from the IP, recipients, recipient domains, IP and API key; key: sends and IP; ip: sends, account and API key; domain: sends and account; the IP as known to the account and to the key (`new_ip`) |
| `feedback` | account: bounces, hard bounces, complaints or deliveries; domain: complaints |
| `account` | ip: a signup, when `account.action` is `signup`; account: its creation time, when `account.created_at` is set |
| `key_leak` | key: leaked |
| every event | the first time its account and API key were seen |

Feedback counts toward the account and sender domain the feedback event names,
which should be those of the original send. Only send events record IPs: a
login from a new IP leaves `account.new_ip` true for the first send from that
IP, and `account.recent_ip` true for the sends after it, so a hijacked account
still shows a new IP when it starts sending.

An event sent again with the `id` it was first sent with, same type and
account, records nothing more for `engine.dedupe_ttl` after it first counted
([retries](api.md#retries)): counters do not count it twice. Its signals are
read as for any event, so they include the first sending: a retried send
sees `sends_1m` as it was with the send counted once, and `new_ip` false,
since the first sending recorded the IP.

Values are matched as follows: account and key ids exactly as sent; domains in
lowercase; IPs in canonical form, so `2001:DB8::1` and `2001:db8::1` are the
same address, and so are `::ffff:203.0.113.7` and `203.0.113.7`.

## `event`

Computed from the event alone.

| signal | type | meaning |
|---|---|---|
| `type` | string | `send`, `feedback`, `account` or `key_leak` |
| `account_id` | string | as sent |
| `api_key_id` | string | as sent, `""` when there is none |
| `ip` | string | as sent, `""` when there is none |
| `from_domain` | string | domain of `from`, lowercase, `""` when it has none |
| `recipients` | int | number of `to` addresses |
| `to_domains` | list(string) | distinct domains of `to`, lowercase, sorted |
| `link_domains` | list(string) | distinct hostnames of `links`, lowercase, sorted; a link without a scheme, such as `example.com/offer`, is read as http |
| `links` | int | number of `links` |
| `subject_length` | int | characters (Unicode code points) in `subject` |
| `feedback_kind` | string | `bounce`, `complaint` or `delivery` for feedback events, `""` otherwise |
| `bounce_type` | string | as sent for bounces (`permanent`, `transient`), `""` otherwise |
| `account_action` | string | `account.action` for account events, such as `signup`; `""` otherwise |
| `attributes` | map(string, string) | the platform's attributes, empty when there are none |

## `account`

The account that sent the event.

| signal | type | window | meaning |
|---|---|---|---|
| `sends_1m` | int | 1 min | send events |
| `sends_1h` | int | 1 h | send events |
| `sends_24h` | int | 24 h | send events |
| `sends_7d` | int | 7 d | send events |
| `recipients_1h` | int | 1 h | `to` addresses over all send events |
| `recipients_24h` | int | 24 h | `to` addresses over all send events |
| `recipients_7d` | int | 7 d | `to` addresses over all send events |
| `distinct_recipient_domains_1h` | int | 1 h | distinct `to` domains of send events |
| `distinct_recipient_domains_24h` | int | 24 h | distinct `to` domains of send events |
| `distinct_ips_24h` | int | 24 h | distinct IPs of send events |
| `distinct_keys_24h` | int | 24 h | distinct API keys of send events |
| `bounces_24h` | int | 24 h | bounce feedback events |
| `hard_bounces_24h` | int | 24 h | bounce feedback events with bounce type `permanent` (in any case) |
| `complaints_24h` | int | 24 h | complaint feedback events |
| `deliveries_24h` | int | 24 h | delivery feedback events |
| `bounce_rate_24h` | double | 24 h | `bounces_24h / max(recipients_24h, sends_24h, 1)`, at most 1 |
| `hard_bounce_rate_24h` | double | 24 h | `hard_bounces_24h / max(recipients_24h, sends_24h, 1)`, at most 1 |
| `complaint_rate_24h` | double | 24 h | `complaints_24h / max(recipients_24h, sends_24h, 1)`, at most 1 |
| `bounces_7d` | int | 7 d | bounce feedback events |
| `hard_bounces_7d` | int | 7 d | bounce feedback events with bounce type `permanent` (in any case) |
| `complaints_7d` | int | 7 d | complaint feedback events |
| `bounce_rate_7d` | double | 7 d | `bounces_7d / max(recipients_7d, sends_7d, 1)`, at most 1 |
| `hard_bounce_rate_7d` | double | 7 d | `hard_bounces_7d / max(recipients_7d, sends_7d, 1)`, at most 1 |
| `complaint_rate_7d` | double | 7 d | `complaints_7d / max(recipients_7d, sends_7d, 1)`, at most 1 |
| `age_hours` | double | | hours since the account was created, or since it was first seen when the creation time is unknown |
| `hourly_baseline_7d` | double | 7 d | `sends_7d / 168`: the average sends per hour over the week |
| `volume_ratio_1h` | double | 1 h | `sends_1h / max(hourly_baseline_7d, 1)`: how this hour compares to the weekly average |
| `new_ip` | bool | 30 d | true when no send event of the account came from this IP in the last 30 days |
| `ip_sends_24h` | int | 24 h | send events of the account from this IP |
| `ip_sends_7d` | int | 7 d | send events of the account from this IP |
| `recent_ip` | bool | 24 h, 7 d | true when no send event of the account came from this IP between 24 hours and 7 days ago: `ip_sends_7d == ip_sends_24h` |

### Feedback rates

Rates are per recipient. Feedback providers report a bounce or a complaint
for each recipient it is about, and the feedback endpoints turn each into one
feedback event, so a send to 50 addresses that all bounce counts 50 bounces.
Dividing by send events would read that as 5,000%; dividing by recipients
reads it as 100%. Per recipient is also how the thresholds rules compare
against are defined: Amazon SES counts each recipient as one email when it
computes an account's bounce and complaint rates, and the 0.3% spam rate
ceiling of Gmail and Yahoo is over messages delivered to their users'
inboxes, one per recipient.

A send event without `to` counts no recipients but reached at least one, so
the denominator is the larger of recipients and send events. A platform that
always sends `to` gets rates per recipient; one that never does gets rates
per send event, the best it can tell. One that sends `to` on some events
only gets the larger of the two counts, which undercounts recipients and so
errs toward a higher rate. Gate rate rules on the same denominator, so that
batch senders reach the minimum volume as soon as their recipients do:
`(account.recipients_24h >= 1000 || account.sends_24h >= 1000)`.

Rates are capped at 1 because feedback about sends older than the window can
outnumber the recipients in it. When sends carry `to`, use
`ratio(account.bounces_24h, account.recipients_24h)` for the uncapped value.

The 7 day rates smooth out a bad day and catch an account that stays just
under a 24 hour threshold; the 24 hour rates react sooner.

The creation time comes from `account.created_at` on any event; the latest one
sent wins. The first-seen time is the earliest event time seen for the
account, whatever the order events arrived in; since older events are
rejected, it is at most `engine.max_event_age` before the account's first
event reached Catraca. Both are kept for a year after
the account's last event (configurable), so an account idle for longer looks
new again. Ages are never negative: a creation time in the future gives 0.

### `new_ip` and `recent_ip`

`new_ip` is true for the first send from an IP only, since that send makes
the IP known to the account. A rule that also needs a count built up over
many sends, such as an hour of volume far above the account's baseline, sees
`new_ip` true on at most one of them. `recent_ip` stays true through the
account's first day on the IP: until then every send from the IP is in both
`ip_sends_24h` and `ip_sends_7d`, and the two only differ once one of those
sends has left the 24 hour window but not the 7 day one.

The edges follow the buckets of the two windows (see Windows above):

- `recent_ip` turns false between 23 h 36 min and 24 h after the account's
  first send from the IP, depending on where that send fell in its 24 minute
  bucket.
- It turns true again once the account has not sent from the IP for between
  6 d 21 h 12 min and 7 d. An IP last used 7 to 30 days ago is therefore
  recent but not new, and a sender that uses an IP once a week and never in
  between, such as a weekly newsletter from a host that sends nothing else,
  looks recent every week.
- A login or other non-send event reads the counts without adding to them,
  so an IP the account has never sent from reads 0, 0 and recent.

## `key`

The API key the event names.

| signal | type | window | meaning |
|---|---|---|---|
| `sends_1m` | int | 1 min | send events with the key |
| `sends_1h` | int | 1 h | send events with the key |
| `distinct_ips_1h` | int | 1 h | distinct IPs of send events with the key |
| `distinct_ips_24h` | int | 24 h | distinct IPs of send events with the key |
| `new_ip` | bool | 30 d | true when no send event with the key came from this IP in the last 30 days |
| `age_hours` | double | | hours since the key was first seen in any event, for example an `account` event with action `api_key_created` |
| `leaked` | bool | | true once the key was reported leaked, by a `key_leak` event or by the engine; it never resets. While the store is down it is the only `key` signal, present for keys known to be leaked (see above) |

## `ip`

The IP the event came from.

| signal | type | window | meaning |
|---|---|---|---|
| `sends_1m` | int | 1 min | send events from the IP |
| `sends_1h` | int | 1 h | send events from the IP |
| `distinct_accounts_24h` | int | 24 h | distinct accounts of send events from the IP |
| `distinct_keys_24h` | int | 24 h | distinct API keys of send events from the IP |
| `signups_24h` | int | 24 h | account events with action `signup` from the IP |

## `domain`

The sender domain: the domain of `from`.

| signal | type | window | meaning |
|---|---|---|---|
| `sends_1h` | int | 1 h | send events from the domain |
| `distinct_accounts_24h` | int | 24 h | distinct accounts of send events from the domain |
| `complaints_24h` | int | 24 h | complaint feedback events whose `from` has the domain |

## Examples

```yaml
rules:
  - id: leaked-key-send
    when: event.type == "send" && key.leaked
    action: block
    reason: API key was found in public and must be rotated

  - id: new-account-burst
    when: event.type == "send" && account.age_hours < 24.0 && account.sends_1m > 100
    action: throttle
    retry_after: 60s
    reason: New account sending at burst volume

  - id: dormant-account-new-ip-spike
    when: >
      event.type == "send" && account.recent_ip &&
      account.age_hours > 720.0 && account.volume_ratio_1h > 10.0
    action: hold
    reason: Established account sending far above its baseline from a new IP

  - id: complaint-rate
    when: >
      (account.recipients_24h >= 1000 || account.sends_24h >= 1000) &&
      account.complaint_rate_24h > 0.003
    action: flag
    reason: Complaint rate above 0.3% over the last day

  - id: signup-farm
    when: event.type == "account" && event.account_action == "signup" && ip.signups_24h > 5
    action: flag
    reason: Many signups from one IP

  - id: shortened-links
    when: event.type == "send" && any_in_list("url_shorteners", event.link_domains)
    action: flag
    reason: Links through a URL shortener
```
