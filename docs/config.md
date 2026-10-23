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
| `shutdown_timeout` | `30s` | how long a graceful shutdown may take: finishing requests in flight and accepted leaked-key batches, writing queued decisions |
| `drain_delay` | `5s` | how long the server keeps serving after SIGTERM or SIGINT, reporting not ready on `/readyz`, before the shutdown starts. `0s` turns it off |

Catraca serves plain HTTP. Put it behind TLS (a load balancer, an ingress or
a reverse proxy) when traffic leaves the host or a private network.

**Stopping.** On SIGTERM or SIGINT the server first drains: `/readyz`
answers `503` (`"shutdown": "draining"`), every response closes its
connection, and requests are still served, for `drain_delay`. Then it stops
accepting connections and shuts down within `shutdown_timeout`. A second
signal skips the rest of the drain.

The drain is for load balancers. When Kubernetes stops a pod, it sends
SIGTERM and removes the pod from the Service at the same time, and kube-proxy,
ingresses and cloud load balancers take a few seconds to notice; a server
that stopped accepting at once would refuse the decisions sent to it
meanwhile. Closing connections moves clients that keep connections open to
other instances. The image has no shell, so a `preStop` hook that sleeps is
not an option, and `drain_delay` takes its place.

The default, 5 seconds, covers the usual propagation in Kubernetes and adds
5 seconds to every stop elsewhere, which is the cheaper mistake: a stop
that is too slow delays a restart, while a drain that is too short makes
the platform send without a decision. Set `0s` for one instance with no
load balancer in front, or for local runs, and raise it when a load
balancer is slower to deregister (some cloud load balancers need 10 to 15
seconds). Give the orchestrator time for both phases: in Kubernetes,
`terminationGracePeriodSeconds` at least `drain_delay` plus
`shutdown_timeout` (35 seconds with the defaults; Kubernetes defaults to
30), or the pod is killed before it has written its queued decisions.

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
| `redis.url` | required for redis | where Redis is, read according to `redis.mode`; see below |
| `redis.mode` | `standalone` | `standalone` for one server, `sentinel` for a primary found through Redis Sentinel, `cluster` for a Redis Cluster |
| `redis.prefix` | `catraca:` | prepended to every key, so deployments can share a database |

`memory` keeps counters in the process: right for one instance, and they
start over on restart. Use `redis` (6.2 or later) when several instances
decide, so they share counters.

The URL for each mode:

| mode | `redis.url` |
|---|---|
| `standalone` | `redis://[user:password@]host:6379/0`, `rediss://` for TLS, or `unix:///path/to/redis.sock` |
| `sentinel` | `redis://sentinel-1:26379/0?master_name=mymaster&addr=sentinel-2:26379&addr=sentinel-3:26379&password=...`: the sentinels, the name of the primary they watch (required), and the primary's password as `password`; a user and password before the host authenticate to the sentinels |
| `cluster` | `redis://[user:password@]node-1:6379?addr=node-2:6379&addr=node-3:6379`: some of the cluster's nodes |

Query parameters set the client's connection options. The ones worth
knowing:

| parameter | default | |
|---|---|---|
| `pool_size` | 10 per CPU | connections per Redis node. It also bounds how many round trips can be outstanding at once: a decision gives up at `engine.deadline`, but its round trip finishes in the background on its connection, so its writes still count. When Redis stalls, decisions beyond the pool wait for a connection until their deadline and are decided degraded |
| `read_timeout` | `5s` | how long a connection waits for a reply before it is closed. It frees connections held by an unresponsive Redis; lower it (to `1s`, say) for a faster recovery, but keep it well above Redis's normal latency, since every timeout costs a new connection |
| `dial_timeout` | `5s` | how long opening a connection may take |

Other parameters of go-redis's
[`ParseURL`](https://pkg.go.dev/github.com/redis/go-redis/v9#ParseURL)
(and `ParseFailoverURL`, `ParseClusterURL`) work too, such as
`write_timeout`, `pool_timeout` and `client_name`; an unknown one is an
error. `max_retries` is refused: Catraca never retries a Redis call,
because a script call whose reply was lost may already have run, and
running it again would count the event twice. The engine's deadline is the
budget of a decision; the next decision is the retry.

The Redis store runs each decision's reads and writes as one Lua script
call (one per hash slot on a cluster), so the server must allow scripting
(`EVAL` and `EVALSHA`), as Redis, Valkey and the managed services do by
default. With ACLs, give Catraca's user `+@scripting` and the commands the
script calls (`+@read +@write` cover them) on keys under the prefix. A
script that Redis lost after a restart or failover is loaded again on first
use. [Benchmarks](benchmark.md) has what a decision costs.

**Memory.** Every key Catraca writes expires on its own, except the marks
of keys reported leaked, which are kept until deleted. If Redis has a
`maxmemory` limit, set `maxmemory-policy volatile-ttl`:

- with `noeviction`, the default, a full Redis refuses writes, and the
  script fails at its first write, so every decision comes back `degraded`
  until memory frees up;
- the `allkeys-*` policies may evict the leaked-key marks, and a leaked key
  would then send again;
- the `volatile-*` policies evict only keys that expire anyway, so the
  leaked-key marks stay; `volatile-ttl` evicts first the keys closest to
  expiring, mostly short-window counters of senders that went quiet, which
  costs detection the least.

### audit

The decision log, labels and the webhook outbox. See [audit](audit.md).

| field | default | |
|---|---|---|
| `dsn` | `sqlite:catraca.db` | `sqlite:<path>` or a plain path for SQLite, `postgres://user:pass@host:5432/db?sslmode=require` for Postgres |
| `event_detail` | `minimal` | `minimal` keeps no message content; `full` also keeps the whole event as sent |

Use SQLite for one instance and Postgres for several. Opening the database
applies migrations.

**When the database cannot be opened.** SQLite is a local file, so a
failure to open it (a missing directory, a permission) is a configuration
problem, and the server does not start.

A Postgres database that cannot be reached when the server starts (the
connection is refused or times out, Postgres is starting up or out of
connections) does not stop it. Exiting would only hand the problem to the
orchestrator: Kubernetes restarts a crashing container with a backoff of
up to five minutes and keeps it down that long after the database is back.
Instead the server opens the database in the background, retrying with
backoff from 1 to 30 seconds, and serves decisions meanwhile, ready like
any other instance: decisions do not depend on the audit log, and this is
what happens anyway when Postgres fails after the server started. Until the
database opens:

- the decisions made meanwhile wait in the engine's queue (4096 of them)
  and are written once it opens; those beyond it are dropped and counted
  in `catraca_records_dropped_total`;
- the effects of enforced rules are written to the outbox if it opens
  within 5 seconds, and are otherwise logged and counted in
  `catraca_hooks_enqueue_errors_total`;
- `GET /v1/decisions/{id}`, labels, the review queue and the rule stats
  answer `503 audit_unavailable`.

Each failed attempt is logged at error level with the reason,
`/readyz?verbose` shows `audit` as `not_open`, and
`catraca_dependency_up{dependency="audit"}` is 0, which is the alert to
set. An error that waiting cannot fix (a malformed DSN, a wrong password, a
database that does not exist, a schema newer than this build) still stops
the server, right after it starts. A host name that does not resolve counts
as unreachable, since DNS is often what comes up last. Against a host that
drops packets, each attempt waits for the operating system to give up on
the connection; add `connect_timeout=5` to the DSN to bound it.

### engine

| field | default | |
|---|---|---|
| `deadline` | `10ms` | time budget for the signal lookup of one decision. When it runs out, the decision is made without the missing signals and marked `degraded`; each rule's `on_error` decides what that means. A `key_leak` event's write of the leak gets the same budget first, and the event answers `503` when it runs out, so the platform sends it again |

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
