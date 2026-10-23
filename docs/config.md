# Configuration

The server reads one YAML file, `catraca.yaml` by default:

```sh
catraca serve -config /etc/catraca/catraca.yaml
catraca config check -config /etc/catraca/catraca.yaml
```

`-config` defaults to `$CATRACA_CONFIG`, then to `catraca.yaml` in the
working directory. [`catraca.example.yaml`](../catraca.example.yaml) is a
commented starting point. `catraca config check` validates a file, and loads
the ruleset it names, without starting anything.

The smallest useful file is one API token; everything else has a default:

```yaml
auth:
  tokens:
    - name: platform
      token: ${CATRACA_API_TOKEN}
```

## How the file is read

**Strict.** An unknown or repeated field is an error, reported with its line
and, when it looks like a typo, the field it probably meant:

```
catraca.yaml:2: server.listn: unknown field (did you mean listen?)
catraca.yaml:9: store.backend: want memory or redis, got "reddis"
```

Every problem in the file is reported in one run, and the server does not
start until there are none.

**Environment variables.** Values may read the environment, so secrets stay
out of the file:

| syntax | value |
|---|---|
| `${NAME}` | the value of `NAME`; an error when `NAME` is not set |
| `${NAME:-default}` | the value of `NAME`, or `default` when it is unset or empty |
| `${NAME:-}` | the value of `NAME`, or empty: an optional variable |
| `$${` | a literal `${` |

Any other `$` is kept as is. Variables are expanded inside values only,
after the YAML is parsed, so a secret full of `:`, `#` or quotes stays one
plain string. Variables work in any value, including numbers and booleans
(`max_body_bytes: ${MAX_BODY:-1048576}`). In flow style (`{a: b}` and
`[a, b]`) quote a value that holds `${...}`, since braces are YAML syntax
there.

**Defaults.** A field left out takes its default; a section left out takes
the defaults of all its fields. Writing `0` for a number or duration that has
a default is an error, not a request for the default.

**Relative paths.** `rules.path` and a SQLite path in `audit.dsn` are
resolved against the directory of the configuration file, so the server
finds them whatever its working directory.

**Durations** are Go durations with a unit: `10ms`, `30s`, `2h`. A plain
number such as `30` is an error.

**Secrets** (tokens, hook secrets, provider secrets, `store.redis.url`,
`audit.dsn`, hook headers) print as `[redacted]` wherever the configuration
is logged or dumped. `config check` shows URLs without their passwords.

## Reference

### server

| field | default | |
|---|---|---|
| `listen` | `:8080` | `host:port` to listen on. `:8080` listens on every interface; use `127.0.0.1:8080` to listen locally only |
| `max_body_bytes` | `1048576` | largest JSON body on the `/v1` routes, at least 1024. Feedback and secret scanning routes have their own limits (1 MiB and 10 MiB) |
| `shutdown_timeout` | `30s` | how long a graceful shutdown may take: draining requests, finishing accepted leaked-key batches, writing queued decisions. Decisions still queued when it runs out are not written to the audit log ([details](audit.md#how-decisions-are-written)) |

Catraca serves plain HTTP. Put it behind TLS (a load balancer, an ingress or
a reverse proxy) when traffic leaves the host or a private network.

### auth

| field | default | |
|---|---|---|
| `tokens` | required | the bearer tokens the `/v1` routes accept, at least one |
| `tokens[].name` | required | identifies the client in access logs (`client`); letters, digits, `.`, `_`, `-` |
| `tokens[].token` | required | at least 16 characters; generate one with `openssl rand -hex 32` |

Give each client its own token. To rotate one, add the new token, move the
client to it, then remove the old one. Tokens are compared in constant time.
Feedback and secret scanning routes take no token; they verify signatures.

### rules

| field | default | |
|---|---|---|
| `path` | `rules/default.yaml` | the ruleset file; see [rules](rules.md) |

The ruleset is reloaded from this path by `POST /v1/rules/reload` and, on
Unix, by `SIGHUP`. If it does not load when the server starts, the server
runs anyway, reports not ready and answers decisions with `503` until a
reload succeeds.

### store

Where signal counters live.

| field | default | |
|---|---|---|
| `backend` | `memory` | `memory` or `redis` |
| `redis.url` | required for redis | `redis://[:password@]host:6379/0`, `rediss://` for TLS, or `unix://` |
| `redis.prefix` | `catraca:` | prepended to every key, so deployments can share a database |

`memory` keeps counters in the process: right for one instance, and they
start over on restart. Use `redis` (6.2 or later) when several instances
decide, so they share counters.

The Redis store runs each decision's reads and writes as one Lua script
call, so the server must allow scripting (`EVAL` and `EVALSHA`), as Redis,
Valkey and the managed services do by default. With ACLs, give Catraca's
user `+@scripting` and the commands the script calls (`+@read +@write`
cover them) on keys under the prefix. A script that Redis lost after a
restart or failover is loaded again on first use. [Benchmarks](benchmark.md)
has what a decision costs.

### audit

The decision log, labels and the webhook outbox. See [audit](audit.md).

| field | default | |
|---|---|---|
| `dsn` | `sqlite:catraca.db` | `sqlite:<path>` or a plain path for SQLite, `postgres://user:pass@host:5432/db?sslmode=require` for Postgres |
| `event_detail` | `minimal` | `minimal` keeps no message content; `full` also keeps the whole event as sent |
| `retention` | unset: keep everything | delete decisions without a label this long after they were decided, and webhook deliveries this long after they were delivered or died; at least `24h` |
| `labeled_retention` | unset: keep forever | delete labeled decisions, with their labels, this long after they were decided; needs `retention` and must be at least as long |
| `max_open_conns` | `10` | most connections to the database from this process |
| `max_idle_conns` | `max_open_conns` | most idle connections kept open for reuse; at most `max_open_conns` |
| `conn_max_lifetime` | `30m` | close connections this long after they opened, so they follow a failover or a DNS change |
| `conn_max_idle_time` | `5m` | close connections idle this long |

Use SQLite for one instance and Postgres for several. Opening the database
applies migrations. A database that cannot be opened stops the server from
starting.

[Retention](audit.md#retention) is off by default. Durations have no day
unit, so 90 days is `2160h`. Labeled decisions are kept forever unless
`labeled_retention` says otherwise, because the precision gate counts labels
over all time.

The connection settings bound what one process opens: with a slow database,
callers wait for a free connection instead of opening more until the server
refuses them. On Postgres keep `max_open_conns` times the number of
instances under `max_connections`. An in-memory SQLite database ignores
them and keeps its one connection.

### engine

| field | default | |
|---|---|---|
| `deadline` | `10ms` | time budget for the signal lookup of one decision. When it runs out, the decision is made without the missing signals and marked `degraded`; each rule's `on_error` decides what that means |

### gate

The [precision gate](audit.md#the-precision-gate) that `GET /v1/stats/rules`
evaluates rules against.

| field | default | |
|---|---|---|
| `min_labeled` | `30` | labeled matches a rule needs, at least 1 |
| `min_precision` | `0.9` | required Wilson 95% lower bound on precision, in (0, 1] |

`catraca rules gate` and `catraca report` take the same values as
`--min-labeled` and `--min-precision`, so CI does not need this file.

### hooks

The webhooks that carry out the effects of enforced rules, one per effect.
See [hooks](hooks.md) for the request and how to verify it.

| field | default | |
|---|---|---|
| `[].name` | required | the effect, as rules list it under `effects`: lowercase letters, digits and `_` |
| `[].url` | required | an absolute `http` or `https` URL |
| `[].secret` | required | signs each request; at least 16 characters |
| `[].timeout` | `10s` | bound on one attempt |
| `[].headers` | | extra headers, for example `Authorization`; `Catraca-*` headers cannot be set |

```yaml
hooks:
  - name: revoke_key
    url: https://platform.internal/hooks/catraca/revoke-key
    secret: ${CATRACA_HOOK_SECRET}
    headers:
      Authorization: Bearer ${PLATFORM_HOOK_TOKEN}
```

An effect that an enforced rule lists and no hook carries out is skipped;
`config check` and the server's log warn about it.

### feedback

Delivery feedback routes. A provider is enabled when its section is present;
see [feedback](feedback.md) for each provider's setup.

| field | default | |
|---|---|---|
| `ses.topic_arns` | required | the SNS topic ARNs accepted on `/v1/feedback/ses` |
| `ses.account_tag` | | the SES message tag holding the account id |
| `ses.account_header` | | the email header holding the account id, the fallback; one of the two is required |
| `usesend.secret` | required | the webhook signing secret shown by useSend, for `/v1/feedback/usesend` |
| `usesend.account_metadata_key` | | read the account id from the email's metadata instead of the team id |
| `generic.secret` | required | the shared secret `/v1/feedback` requests are signed with; at least 16 characters |

```yaml
feedback:
  ses:
    topic_arns: [arn:aws:sns:us-east-1:111122223333:catraca-ses-feedback]
    account_tag: catraca-account
  generic:
    secret: ${CATRACA_FEEDBACK_SECRET}
```

### secret_scanning

GitHub's secret scanning partner endpoint, `/v1/secret-scanning/github`. See
[secret scanning](secret-scanning.md).

| field | default | |
|---|---|---|
| `github.enabled` | `false` | turn the endpoint on; the fields below are checked only when it is |
| `github.resolver.url` | required | the platform endpoint that says which API key a token is |
| `github.resolver.secret` | required | signs resolver requests; at least 16 characters |
| `github.resolver.send_raw_token` | `false` | send the raw token, not only its SHA-256; requires an `https` URL |
| `github.feedback` | `false` | answer GitHub with true and false positive labels, once GitHub enables feedback for the partnership |
| `github.github_token` | | a GitHub token without scopes, to raise the rate limit on GitHub's public keys endpoint |
| `github.keys_url` | GitHub's | where GitHub's signing keys are fetched; change it only for tests |

### logging

| field | default | |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn` or `error`. Health, readiness and metrics requests are logged at `debug` |
| `format` | `json` | `json` or `text` |

Logs go to stderr. Tokens, secrets and message content are never logged.

## Environment variables the CLI reads

| variable | used by | |
|---|---|---|
| `CATRACA_CONFIG` | `serve`, `config check` | default for `-config` |
| `CATRACA_AUDIT_DSN` | `rules gate`, `report` | default for `--audit` |
| `CATRACA_TOKEN` | `label` | the API token, when `--token` is not given |
| `CATRACA_SERVER` | `label` | default for `--server` (`http://localhost:8080`) |

Any other variable is read only where catraca.yaml references it.
