# Synthetic replay dataset

`events.jsonl` is ten days of made-up traffic from an imaginary sending
platform, labeled, in the format `catraca replay` reads: one JSON object per
line, `{"event": {...}, "label": "abusive" | "legit"}`, in time order. It is
here to show how a backtest works, and to give the default ruleset something
to run on.

> **Caveat.** The data is synthetic and the rules were not tuned on it. The
> scenarios were written knowing what the default rules look for, so which
> rule fires on which scenario is by construction, and abuse is about a third
> of the labeled events, far more than on any real platform, which flatters
> precision. The numbers below show the mechanics of a backtest (matches,
> misses, false positives, per rule and combined), not how precise the rules
> are on real traffic. Run `catraca replay` on your own labeled events for
> that.

## Run it

Once the CLI is built:

```sh
catraca replay rules/default.yaml examples/replay/events.jsonl
```

Until then, or in CI, the same backtest runs as a Go test, which prints the
report with `-v`:

```sh
go test ./examples/replay -run TestDefaultRuleset -v
```

The test checks that every line parses, that every rule is scored on every
labeled event without evaluation errors, and that the dataset still has true
positives, false positives and misses. It does not pin the numbers, so
changing a threshold in `rules/default.yaml` does not break it; update the
table below when the numbers change.

## Regenerate it

```sh
go run ./examples/replay/gen
```

The generator is deterministic: it uses its own seeded random number
generator, so the same source writes the same bytes on every platform and Go
release. `go test ./examples/replay/gen` fails when the committed file and the
generator disagree.

All names are invented: sender and company domains use the reserved
`.example` and `.test` TLDs, IP addresses come from the documentation ranges,
and recipients are random names at real mailbox providers, since recipient
domain signals look at those.

## What is in it

13,557 events: 12,807 labeled (4,426 abusive, 8,381 legit) and 750 unlabeled
bounces, complaints and one leak report. Feedback is not labeled because no
one reviews a bounce, and scoring it would only pad the true negatives.

Legitimate traffic, including cases that look like abuse:

| scenario | what it looks like |
|---|---|
| ten transactional products | steady password resets, receipts and reports from a couple of server IPs each, quieter on weekends |
| weekly newsletter | 1,050 sends in an hour from an established account: a huge spike over its baseline, but from its usual IP and with few complaints |
| product launch | an established product mails 320 users in 40 minutes from its usual IPs |
| bad campaign | a real newsletter mails a segment that did not want it; complaints pass 0.3% |
| stale list | an old customer re-engages users from years ago; hard bounces pass 5% |
| serverless launch | a product moves its mailer to a serverless platform on launch day: new IP on every send while volume spikes |
| serverless sender | a product that always sends from a serverless platform, so its key is used from dozens of IPs an hour |
| waitlist launch | a startup signs up and, two hours later, mails a waitlist of 220 in a minute and a half |
| shortener marketing | a new shop links its first campaigns through bit.ly |
| event invitations | a new events company invites 360 people at about 300 companies in under an hour |
| ordinary signups | 22 new customers who start sending a little, or never send |
| classroom | seven students sign up from one campus address within two hours |

Abuse:

| scenario | what it looks like |
|---|---|
| leaked key | a customer's key leaks; abusers send through 45 proxy IPs for over an hour, GitHub reports the leak, and the owner rotates the key |
| burst accounts | three throwaway accounts that sign up and blast 220 to 320 emails within minutes |
| complaint spammer | warms up for days, then mails a purchased list with 2% complaints |
| bought list | mails a list where 14% of addresses do not exist |
| domain spray | two new accounts mailing addresses scraped from company websites, hundreds of domains an hour |
| phishing | four new accounts sending credential phishing, three through URL shorteners and one through a lookalike domain |
| takeover through proxies | an old account taken over at night, a new key, 500 sends in 45 minutes from a new residential proxy IP on nearly every send |
| takeover from one IP | the same attack, 350 sends from a single server |
| signup farms | two addresses creating 12 and 9 accounts in a few hours, each sending a handful of shortened links |

## Results with the default ruleset

Ruleset version `adf1d0464c14`. A match in either mode counts as predicting
"abusive"; precision is TP / (TP + FP), recall TP / (TP + FN).

| rule | mode | action | TP | FP | FN | TN | precision | recall |
|---|---|---|---:|---:|---:|---:|---:|---:|
| leaked-key-send | enforce | block | 60 | 0 | 4,366 | 8,381 | 1.000 | 0.014 |
| new-account-burst | shadow | throttle | 523 | 120 | 3,903 | 8,261 | 0.813 | 0.118 |
| complaint-rate-high | shadow | hold | 257 | 105 | 4,169 | 8,276 | 0.710 | 0.058 |
| hard-bounce-rate-high | shadow | hold | 225 | 147 | 4,201 | 8,234 | 0.605 | 0.051 |
| key-many-ips | shadow | hold | 507 | 485 | 3,919 | 7,896 | 0.511 | 0.115 |
| account-takeover-volume | shadow | hold | 561 | 104 | 3,865 | 8,277 | 0.844 | 0.127 |
| shortener-links-new-account | shadow | flag | 259 | 45 | 4,167 | 8,336 | 0.852 | 0.059 |
| signup-farm-ip | shadow | flag | 13 | 3 | 4,413 | 8,378 | 0.812 | 0.003 |
| recipient-domain-spray | shadow | hold | 56 | 28 | 4,370 | 8,353 | 0.667 | 0.013 |
| **enforced rules (effective action)** | | | 60 | 0 | 4,366 | 8,381 | 1.000 | 0.014 |
| **shadow rules** | | | 2,074 | 933 | 2,352 | 7,448 | 0.690 | 0.469 |
| **all rules, as if enforced** | | | 2,087 | 933 | 2,339 | 7,448 | 0.691 | 0.472 |

Per-rule recall is low by design: each rule targets one pattern, so every
other abusive event is a miss for it, and rules that need volume (1,000 sends
in a day, 200 in an hour, 100 in a minute) let the start of each blast
through. The combined rows are the ones to read for coverage.

What the run shows:

- **leaked-key-send** blocks the 60 sends after the leak report and nothing
  else. The 260 abusive sends before the report are up to the other rules;
  key-many-ips catches 26 of them and account-takeover-volume 61, since the
  abusers send through the owner's established account from proxies it never
  used.
- **key-many-ips** has the lowest precision: both serverless senders use their
  keys from dozens of IPs an hour, which is what a leaked key looks like. The
  rule's description warns about this; here it costs 485 false positives.
- **account-takeover-volume** holds 302 of the 500 proxy takeover sends and
  151 of the 350 sends of the takeover from one IP: each one once the hour
  passes 200 sends. It reads `account.recent_ip`, which stays true for every
  send of the account's first day on an address. With `account.new_ip`,
  true only for the first send from an address, it missed every send of the
  takeover from one IP. Its false positives are still the serverless launch.
- **hard-bounce-rate-high** also holds 28 of the taken-over account owner's
  own sends after the attack: account-level rates cannot tell who sent the
  mail that bounced.
- **complaint-rate-high**, **hard-bounce-rate-high**, **new-account-burst**,
  **shortener-links-new-account**, **recipient-domain-spray** and
  **signup-farm-ip** each catch their abuse scenario and each hold or flag
  one legitimate look-alike: the bad campaign, the stale list, the waitlist,
  the shop using bit.ly, the event invitations and the classroom.

These are the trade-offs shadow mode exists to measure on real traffic before
a rule is enforced.
