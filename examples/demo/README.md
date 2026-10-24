# Demo scenario

A scripted run against a real `catraca serve`, recorded for the launch
video and the README animation in [`media/`](../../media). Everything the
video shows as product output (requests, answers, the webhook, the command
line) comes from [`out/scenario.json`](out), which this program writes.

```sh
go run ./examples/demo          # from the repository root
```

It takes about ten seconds and needs nothing but Go: the program builds
`./cmd/catraca` into a temporary directory (or runs the binary given with
`-catraca`), writes a configuration there, starts the server, plays the
scenario, labels decisions, runs `catraca report`, stops the server and
deletes the directory. `-keep` keeps it, with the server log and the audit
database; `-out` changes where the recording goes.

## What it sets up

- **`catraca serve`** on a free port of `127.0.0.1`, with the memory store
  and a SQLite audit log in the temporary directory, an API token, a
  `revoke_key` hook and the generic feedback endpoint. Secrets are random
  per run and reach the server through the environment, as in production.
  The signal deadline is raised from 10 ms to 250 ms: a laptop playing the
  scenario while it writes the audit log can miss 10 ms now and then, and
  the demo refuses to record a degraded decision.
- **A webhook receiver** standing in for the platform: it checks every
  `Catraca-Signature` with the public [`signature`](../../signature)
  package and records what arrived.
- **[`rules.yaml`](rules.yaml)**, a copy of the starter ruleset with three
  rules switched to `enforce` so each action can be seen, each marked
  `DEMO:`. The starter ruleset keeps them in shadow mode, and the
  configuration sets `gate.on_load: off`: a server would otherwise hold
  them in shadow mode until their labels clear the precision gate.

  | rule | here | in `rules/default.yaml` |
  |---|---|---|
  | `new-account-burst` | enforce (throttle) | shadow |
  | `complaint-rate-high` | enforce (hold) | shadow |
  | `shortener-links-new-account` | enforce (flag) | shadow |

## The scenario

1. **History**, the 24 hours before the run, sent with explicit event times:
   four established accounts sending as usual (1,850 sends), a signup farm
   creating 61 accounts from one IP (`signup-farm-ip` matches in shadow from
   the fifth), and nine new accounts linking through `bit.ly`
   (`shortener-links-new-account` flags them).
2. **Live**, at the wall clock, recorded in order as the lane:
   - normal traffic from the established accounts: `allow`, and a tenth new
     account's shortener link: `flag`;
   - `acct_x7q2` signs up and sends 140 emails at once: the first 100 are
     allowed, the rest get `throttle` with `Retry-After: 60`;
   - four complaints about the newsletter account through `POST /v1/feedback`,
     signed with `signature.Sign`, each followed by one of its sends: after
     the fourth its complaint rate passes 0.3% in 24 hours and the send is
     `hold`; the account then stops sending;
   - a `key_leak` event for `acct_tidal`'s key through `POST /v1/events`; the
     next send with the key, from another IP, is `block` with the
     `revoke_key` effect; the receiver gets the signed webhook, and the
     account carries on with a new key;
   - the farm's last three signups, `allow` with `signup-farm-ip` in shadow.
3. **Labels**: the 40 throttles, the hold and the block as true positives;
   59 of the farm's 60 shadow matches as true positives and one as a false
   positive (the two newest verdicts with `catraca label`, the rest through
   the API); the ten shortener flags as 4 true and 6 false positives (appeals
   reversing them). Then `catraca report`.

The report it prints ends like this:

```
Promote candidates (shadow rules that pass the gate):
  signup-farm-ip: precision 0.983 [0.911, 0.997] on 60 labeled matches

Retire candidates (enforced rules below the gate):
  shortener-links-new-account: precision 0.400 [0.168, 0.687] on 10 labeled matches
```

The accounts, IPs (documentation ranges) and domains (`.example`) are made
up; the decisions are Catraca's.

## Output

| file | |
|---|---|
| `out/scenario.json` | every exchange the video shows (`steps`), the live decisions in order (`lane`), the webhook as received (`hook`), the command lines and their output (`cli`), and counts |
| `out/report.txt` | `catraca report` |
| `out/report.json` | `catraca report --json` |

Ids, times and latencies change on every run; the story does not. Decision
times carry the server's UTC offset (a server in UTC prints `Z`), and on
Windows `latency_us` is often `0` or about `500`, because the clock behind
it ticks every half millisecond there.

On Windows the server is stopped with a kill, since there is no SIGINT for
another process; elsewhere it gets SIGINT and shuts down gracefully. The
report is read before either.
