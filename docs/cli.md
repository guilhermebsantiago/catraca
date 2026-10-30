# Command line

`catraca` runs the server and the tools around rules: checking and testing a
ruleset, the precision gate for CI, backtests and precision reports,
labeling decisions, listing and redriving webhook deliveries, and the queue
of leaked-key reports. `catraca help` lists the commands and
`catraca <command> -h` the flags of one. Flags may come before or after
positional arguments, with one dash or two.

```sh
go build -ldflags "-X main.version=v0.1.0" -o catraca ./cmd/catraca
```

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | a check failed: an invalid configuration or ruleset, failing fixtures, rules below the gate, lint warnings with `--strict`, a label the server refused, deliveries `outbox retry` left alone, or reports to requeue that are not dead |
| 2 | the command line is wrong: an unknown command or flag, a missing argument |
| 3 | the command could not run: a file, the audit database or the server was unavailable, or the server failed to start |

## serve

```sh
catraca serve [-config catraca.yaml]
```

Runs the server until SIGINT or SIGTERM. It then drains for
`server.drain_delay` (5s by default): `/readyz` reports not ready while
requests are still served, so load balancers stop sending them. Then it
shuts down gracefully within `server.shutdown_timeout`. A second SIGINT or
SIGTERM skips the rest of the drain. The ruleset is reloaded when its file
changes ([`rules.watch_interval`](config.md#rules)) and, on Unix, on
SIGHUP. Logs go to stderr. See [configuration](config.md#server) and the
[API](api.md).

## config check

```sh
catraca config check [-config catraca.yaml]
```

Validates the configuration and loads the ruleset it names, then prints a
summary without secrets. Ruleset lint findings, effects without a hook and
API tokens without [scopes](api.md#conventions) are printed as warnings.

```
catraca.yaml is valid (1 warning(s))
  listen      :8080
  api tokens  send-path (decide), ops (decide, read, label, admin)
  ruleset     rules/default.yaml (version 098086f42c27, 9 rules: 1 enforced, 8 shadow)
  reload      when the file changes (read every 5s), on SIGHUP and on POST /v1/rules/reload
  store       memory (one instance; counters are lost on restart)
  audit       sqlite:catraca.db, minimal events
  ...
```

## rules check

```sh
catraca rules check <ruleset> [--strict]
```

Parses and compiles a ruleset and prints its lint warnings as
`file:line: warning: ...`. Errors exit 1; warnings exit 1 only with
`--strict`.

## rules test

```sh
catraca rules test <ruleset> <fixtures>...
```

Runs [fixture files](rules.md#fixtures) against a ruleset, one line per case
and the differences of the cases that fail. Exits 1 when a case fails.

```sh
catraca rules test rules/default.yaml rules/default.test.yaml
```

## rules gate

```sh
catraca rules gate <ruleset> --audit <dsn> [--since 720h] [--min-labeled 30] [--min-precision 0.9]
```

Checks every enforced rule of the ruleset against the
[precision gate](audit.md#the-precision-gate) with the labels in the audit
database, and exits 1 when one does not pass and has no `override`. Run it
in CI on every change to the ruleset. `--since` limits the matches counted
(default: all time); `--audit` defaults to `$CATRACA_AUDIT_DSN`. A SQLite
database that does not exist is an error (exit 3), never an empty new one.

```
RULE             LABELED  TP  FP  PRECISION  95% CI          STATUS
leaked-key-send  61       61  0   1.000      [0.941, 1.000]  passes (override)

ok: 1 enforced rule(s) pass the gate or have an override
```

## replay

```sh
catraca replay <ruleset> <events.jsonl> [--json]
```

[Backtests](rules.md#backtesting) a ruleset on labeled events, one JSON
object per line in time order, through a fresh in-memory catalog and the
production engine. Prints precision, recall and F1 per rule. Event times are
used as written: the server's bounds on how far a time may be from its clock
(`engine.max_future_skew`, `engine.max_event_age`) do not apply to a replay.
The [limits](api.md#limits) on an event's size do.

## report

```sh
catraca report --rules <ruleset> --audit <dsn> [--since 720h] [--json]
```

Prints the precision of every rule over the window (`--since`, default
`720h`; `all` for all time), with promote candidates (shadow rules that pass
the gate) and retire candidates (enforced rules below it). `--json` prints
the same document as `GET /v1/stats/rules`.

## label

```sh
catraca label <decision-id> --verdict true_positive|false_positive --by <who> \
  [--reason <why>] [--rule <id>] [--server http://localhost:8080] [--token <token>]
```

Labels a decision on a running server. The token comes from `--token` or
`$CATRACA_TOKEN`, the server from `--server` or `$CATRACA_SERVER`. A label
the server refuses (an unknown decision, a rule that did not match) exits 1;
a server that cannot be reached or fails exits 3.

```sh
CATRACA_TOKEN=... catraca label 01M50QGQP8YVGSY487W3YJ8J24 \
  --verdict false_positive --by support@platform.example --reason "appeal #4411"
```

## outbox list

```sh
catraca outbox list --audit <dsn> [--status pending|dead|delivered] [--hook <name>] \
  [--since 24h] [--limit 50] [--json]
```

Lists the [webhook deliveries](hooks.md) in the outbox of the audit
database: pending ones in the order they are due, the others most recently
updated first. `--since` keeps those last updated since then, which for a
dead delivery is when it was given up. `--audit` defaults to
`$CATRACA_AUDIT_DSN`, and a SQLite database that does not exist is an error
(exit 3). `--json` prints the deliveries as a JSON array, without their
bodies.

```
ID  DECISION                    HOOK        STATUS   ATTEMPTS  CREATED               REQUEUED  UPDATED               NEXT  LAST
42  01M50QGQP8YVGSY487W3YJ8J24  revoke_key  dead     15        2026-10-22T09:12:03Z  -         2026-10-22T10:31:44Z  -     HTTP 503: maintenance
```

The outbox commands open the database the server uses, while it runs: on
SQLite, run them on the same host, on the file `audit.dsn` names.

## outbox retry

```sh
catraca outbox retry --audit <dsn> <id>...
catraca outbox retry --audit <dsn> --dead [--hook <name>] [--since 24h]
```

Requeues dead deliveries once their receiver is fixed: the ones named by
id, as `outbox list` prints them, or with `--dead` every dead delivery, or
those of one hook, or those that died since a time. A requeued delivery is
due at once, with the same body and idempotency key; its attempts and its
`max_age` start over ([redriving](hooks.md#redriving-dead-deliveries)). A
running server sends it within its poll interval, 2 seconds. Deliveries
that are not dead are left alone: with ids, each one left alone is
reported and the command exits 1.

```sh
catraca outbox retry --audit "$CATRACA_AUDIT_DSN" --dead --hook revoke_key --since 6h
```

## outbox stats

```sh
catraca outbox stats --audit <dsn> [--json]
```

Counts the deliveries of each hook: pending, due now (waiting for a worker
rather than a backoff), how long the oldest pending one has waited, dead
and delivered. It reads the whole outbox, which without
[retention](audit.md#retention) holds every delivery ever made.

```
HOOK        PENDING  DUE  OLDEST PENDING  DEAD  DELIVERED
notify      0        0    -               1     2210
revoke_key  3        1    4m12s           2     1187
```

## secretscan

```sh
catraca secretscan list --audit <dsn> [--status pending|dead|done|all] [--limit 50] [--json]
catraca secretscan retry --audit <dsn> (<report-id>... | --dead)
```

Reads and requeues the [leaked-key reports](secret-scanning.md#retries-and-dead-reports)
GitHub secret scanning sent, in the audit database; `--audit` defaults to
`$CATRACA_AUDIT_DSN`, and a SQLite database that does not exist is an
error (exit 3), as for `rules gate`.

`list` prints how many reports are pending and dead, then the latest ones,
newest first, with their outcome, attempts, the API key a token resolved
to, when the next attempt is due, where GitHub found the token and the last
error. Raw tokens are never printed. `--json` prints the same as one JSON
document.

```
1 pending (the oldest arrived 4m12s ago), 1 dead

ID  STATUS   OUTCOME         ATTEMPTS  TYPE          SOURCE  API KEY  RECEIVED              NEXT ATTEMPT          URL                                          LAST ERROR
3   done     leaked          1         acme_api_key  commit  key_123  2026-10-23T12:00:00Z  -                     https://github.com/octo/repo/blob/main/.env  -
2   dead     resolve_failed  412       acme_api_key  commit  -        2026-10-22T09:30:00Z  -                     https://github.com/octo/repo/blob/main/.env  Post "https://platform.internal/resolve": dial tcp: connection refused
1   pending  -               3         acme_api_key  commit  -        2026-10-23T12:04:00Z  2026-10-23T12:08:30Z  https://github.com/octo/app/blob/main/.env   secretscan: resolver returned 503 Service Unavailable
```

`retry` requeues dead reports, by id or all of them with `--dead`: each is
due at once, with its attempts and age counted afresh, and a running server
picks it up within seconds. Fix what its last error says first. Reports
that are not dead are left alone, since a pending one may be in the middle
of an attempt; naming one exits 1.

## version

```sh
catraca version
```

Prints the version, commit and commit date set at build time (release builds
set all three; other builds fall back to the VCS stamp when there is one),
and the Go version and platform:

```text
catraca v0.1.0 (0123456789ab, 2026-10-23T12:00:00Z) go1.26.10 linux/amd64
```
