# Command line

`catraca` runs the server and the tools around rules: checking and testing a
ruleset, the precision gate for CI, backtests and precision reports, and
labeling decisions. `catraca help` lists the commands and
`catraca <command> -h` the flags of one. Flags may come before or after
positional arguments, with one dash or two.

```sh
go build -ldflags "-X main.version=v0.1.0" -o catraca ./cmd/catraca
```

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | a check failed: an invalid configuration or ruleset, failing fixtures, rules below the gate, lint warnings with `--strict`, or a label the server refused |
| 2 | the command line is wrong: an unknown command or flag, a missing argument |
| 3 | the command could not run: a file, the audit database or the server was unavailable, or the server failed to start |

## serve

```sh
catraca serve [-config catraca.yaml]
```

Runs the server until SIGINT or SIGTERM, then shuts down gracefully within
`server.shutdown_timeout`. On Unix, SIGHUP reloads the ruleset. Logs go to
stderr. See [configuration](config.md) and the [API](api.md).

## config check

```sh
catraca config check [-config catraca.yaml]
```

Validates the configuration and loads the ruleset it names, then prints a
summary without secrets. Ruleset lint findings and effects without a hook
are printed as warnings.

```
catraca.yaml is valid (1 warning(s))
  listen      :8080
  api tokens  platform
  ruleset     rules/default.yaml (version 098086f42c27, 9 rules: 1 enforced, 8 shadow)
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
production engine. Prints precision, recall and F1 per rule.

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

## version

```sh
catraca version
```

Prints the version set at build time, the VCS revision when known, and the
Go version and platform.
