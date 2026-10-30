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

**Secrets** (tokens, hook secrets, provider secrets, current and previous,
`store.redis.url`, `audit.dsn`, hook headers) print as `[redacted]`
wherever the configuration is logged or dumped. `config check` shows URLs
without their passwords. Each token and shared secret can be rotated
without refusing valid requests; see [rotating secrets](rotation.md).

## Reference

### server

| field | default | |
|---|---|---|
| `listen` | `:8080` | `host:port` to listen on. `:8080` listens on every interface; use `127.0.0.1:8080` to listen locally only |
| `admin_addr` | | a second `host:port` that serves `/healthz`, `/readyz` and `/metrics` in place of `listen`, such as `:9090`. Unset, `listen` serves them |
| `max_body_bytes` | `1048576` | largest JSON body on the `/v1` routes, at least 1024. Feedback and secret scanning routes have their own limits (1 MiB and 10 MiB) |
| `shutdown_timeout` | `30s` | how long a graceful shutdown may take: finishing requests in flight and accepted leaked-key batches, writing queued decisions. Decisions still queued when it runs out are not written to the audit log ([details](audit.md#how-decisions-are-written)) |
| `drain_delay` | `5s` | how long the server keeps serving after SIGTERM or SIGINT, reporting not ready on `/readyz`, before the shutdown starts. `0s` turns it off |
| `max_inflight` | `256` | most decisions in flight at once on `/v1/decide` and `/v1/events` together, and apart, most requests on the feedback routes; see [admission](#admission) |
| `inflight_wait` | `2ms` | how long a request over the limit waits for a slot before it is shed. `0s` sheds at once |
| `inflight_limit` | `adaptive` | `adaptive`: the decision limit drops while decisions take half of `engine.deadline` or more and climbs back as they speed up, never above `max_inflight`. `static` keeps it at `max_inflight` |

Catraca serves plain HTTP. Put it behind TLS (a load balancer, an ingress or
a reverse proxy) when traffic leaves the host or a private network.

**Health and metrics.** `/healthz`, `/readyz` and `/metrics` take no token,
so only probes and Prometheus should reach them, not the API's clients.
Without
`admin_addr` they share the API's listener, and keeping them private is up
to whatever is in front (expose only `/v1` through the load balancer). With
`admin_addr` they move to a listener of their own and the API listener
answers `404` for them: point probes and Prometheus at that port and leave
it out of the Service or load balancer that carries the API. Every other
route stays on `listen`. Both listeners drain and stop together.

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

#### Admission

When Redis slows down or saturates, more decisions wait on it at once, and
past its capacity every one of them waits out `engine.deadline` and is
degraded anyway. So the server bounds the decisions in flight on
`/v1/decide` and `/v1/events` together. A request over the limit, its body
read, waits up to `inflight_wait` for a slot, first come first served, and
is then shed: decided at once without the store. That is the decision a
deadline miss gives, `degraded: true`, with each rule's `on_error` applied
and the keys this server knows leaked still blocked, so the platform acts on
it as usual; a `5xx` before a send would stop good senders or come back as
retries that add to the load. Two kinds of event are not decided when shed,
since a decision without the store would not record them: a `feedback`
event is answered `503 overloaded` and a `key_leak` too, both with
`Retry-After`, to be sent again.

With `inflight_limit: adaptive`, the default, the limit starts at
`max_inflight`, so nothing is shed while decisions are fast. When a
decision takes half the deadline or more, Redis (or the server) is falling
behind, and the limit drops by a fifth, at most once per round of decisions
so that one stall does not collapse it. Half the deadline, not all of it,
leaves room for the spread of a loaded Redis's latency, so the decisions let
in rarely miss the deadline. While at least half the slots are busy, each
decision that finishes in time with its signals raises the limit by about
one per limit's worth of decisions. Past Redis's capacity, the decisions let
in keep getting their signals in time and the rest are shed without a round
trip, where without a limit nearly all of them would wait out the deadline
and degrade; [benchmarks](benchmark.md#overload-and-outages) has the
numbers. Each instance finds its own limit, so instances sharing a Redis
share it out between them. A `static` limit sheds only once `max_inflight`
decisions are in flight: it bounds memory and goroutines, but the number
that protects Redis depends on how fast it is and how many instances share
it.

The feedback routes have `max_inflight` slots of their own, never adaptive,
so a burst of sends never sheds feedback. Beyond them a request is answered
`503` with `Retry-After`, which providers retry. The first MiB of a
feedback body is read before the request takes a slot, so a sender that
trickles its body holds a connection, not a slot. Secret scanning, labels
and the read routes are not limited: they are rare, and none waits on Redis
in the request. `catraca_admission_inflight`, `catraca_admission_shed_total`
and `catraca_admission_limit` ([metrics](api.md#get-metrics)) show the
limits at work, and each shed request's access log line has `"shed": true`.

### auth

| field | default | |
|---|---|---|
| `tokens` | required | the bearer tokens the `/v1` routes accept, at least one |
| `tokens[].name` | required | identifies the client in access logs (`client`); letters, digits, `.`, `_`, `-` |
| `tokens[].token` | required | at least 16 characters; generate one with `openssl rand -hex 32` |
| `tokens[].previous_tokens` | | tokens of the same client being rotated out, accepted like `token` under the same name and with the same scopes; requests with one are logged with `"previous_token": true` |
| `tokens[].scopes` | every scope | what the token may call: `decide`, `read`, `label`, `admin`; see [scopes](api.md#conventions). Without the key the token has every scope; an empty list is an error |

Give each client its own token, with the scopes it needs and no more. The
send path, whose token sits on every app server, needs `decide` alone; the
tools that read the audit log, review and label decisions, and reload the
rules get their own token:

```yaml
auth:
  tokens:
    - name: send-path
      token: ${CATRACA_API_TOKEN}
      scopes: [decide]
    - name: ops
      token: ${CATRACA_OPS_TOKEN}
      scopes: [decide, read, label, admin]
```

A token without `scopes` has every scope, so a file written before scopes
keeps working, and `catraca config check` warns about it. A label records
the name of the token that gave it as `client`, next to the `by` the caller
sends.

To rotate a token, make the new token `token` and the old one a previous
token, move the client to the new one, then remove the old one; see
[rotating secrets](rotation.md#api-tokens). A token, current or previous,
may appear once in the whole list. Tokens are compared in constant time.
Feedback and secret scanning routes take no token; they verify signatures.

### rules

| field | default | |
|---|---|---|
| `path` | `rules/default.yaml` | the ruleset file; see [rules](rules.md) |
| `watch_interval` | `5s` | how often the server reads the file, to reload it when its content changed; at least `1s`. `0s` turns the watch off |

The ruleset is reloaded from this path when its content changes, by
`POST /v1/rules/reload` and, on Unix, by `SIGHUP`. A load reads the file,
parses and compiles it as [`catraca rules check`](cli.md) does, puts the
rules it would newly enforce through the [precision gate](#gate), and swaps
the result in at once; decisions in flight finish on the ruleset they
started with. A file that does not load leaves the current ruleset
serving: the error is logged once and counted in
`catraca_ruleset_loads_total{result="error"}`. If the file does not load
when the server starts, the server runs anyway, reports not ready and
answers decisions with `503` until a reload succeeds.

**The watch.** Every `watch_interval` the server reads the file and
compares its SHA-256 with what it last loaded. A change is loaded once the
file has kept the same content for two seconds, so a file still being
written, or a burst of saves, loads once and whole; a change undone in the
meantime loads nothing. Any change of the bytes counts, a comment
included, which is a way to make every instance run the gate again.
Reading the content, rather than waiting for file system events, follows
every way a file is replaced: in place, by renaming another file over it,
or as a Kubernetes ConfigMap does. Each instance watches its own file, so
a ConfigMap update reaches every pod by itself, without a signal to each.

In Kubernetes, mount the ConfigMap as a directory and point `path` into it:

```yaml
volumes:
  - name: rules
    configMap: {name: catraca-rules}
containers:
  - name: catraca
    env:
      - {name: CATRACA_RULES, value: /etc/catraca/rules/default.yaml}
    volumeMounts:
      - {name: rules, mountPath: /etc/catraca/rules, readOnly: true}
```

The kubelet updates the files of such a mount within a minute or two of a
`kubectl apply`, by swapping a symlink, and the watch loads the new
ruleset a few seconds later; `/readyz?verbose` on each pod shows the
version it runs. A ConfigMap mounted with `subPath` is never updated:
pods keep the file they started with until they restart.

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
| `retention` | unset: keep everything | delete decisions without a label this long after they were decided, and webhook deliveries this long after they were delivered or died; at least `24h` |
| `labeled_retention` | unset: keep forever | delete labeled decisions, with their labels, this long after they were decided; needs `retention` and must be at least as long |
| `max_open_conns` | `10` | most connections to the database from this process |
| `max_idle_conns` | `max_open_conns` | most idle connections kept open for reuse; at most `max_open_conns` |
| `conn_max_lifetime` | `30m` | close connections this long after they opened, so they follow a failover or a DNS change |
| `conn_max_idle_time` | `5m` | close connections idle this long |

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
  `catraca_hooks_enqueue_errors_total`; their decisions do not wait for
  that, only for `engine.dispatch_timeout`;
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
the connection; add `connect_timeout=5` to the DSN to bound it, and every
connection opened later, such as during a network partition.

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
| `deadline` | `10ms` | time budget for the signal lookup of one decision. When it runs out, the decision is made without the missing signals and marked `degraded`; each rule's `on_error` decides what that means. A `key_leak` event's write of the leak gets the same budget first, and the event answers `503` when it runs out, so the platform sends it again |
| `dispatch_timeout` | `deadline` | time budget for writing a decision's [effects](hooks.md#when-a-webhook-is-called) to the outbox. When it runs out, the decision is answered and the write goes on in the background for up to 5 seconds, so the effects are delayed, not lost; one that still fails is logged and counted. A decision with effects takes at most this much longer than one without |
| `max_future_skew` | `5s` | how far ahead of Catraca's clock an event's `time` may be. A later time is replaced by the clock's, since an event cannot come from the future and, counted there, would empty the windows it touches until the clock caught up. Keep it well under a minute, the shortest window |
| `max_event_age` | `168h` | how far behind Catraca's clock an event's `time` may be. An older event is answered `400 invalid_event`, and the feedback endpoints acknowledge it so the provider does not retry; a `key_leak` takes the clock's time instead. The default is the longest counter window, so nothing a counter could still use is refused. A lower value also stops late feedback from counting; a higher one lets an event move an account's first-seen time further back |
| `dedupe_ttl` | `10m` | how long the `id` of an event that counted is remembered, so that the event sent again meanwhile, a retry after a timeout or a provider's redelivery, does not count twice ([retries](api.md#retries)). `0s` turns it off: every sending counts |
| `recipient_memory` | `720h` | how long an address that hard-bounced or complained is remembered, for every account, so that a send to it counts in [`event.suppressed_recipients`](signals.md#the-recipient-memory). At least `1h`; `0s` turns it off, and the two `suppressed_` signals are then absent |
| `recipient_hash_key` | none | secret that keys the digest the store keeps instead of each remembered address. Without it the digest is a plain hash, and anyone who can read the store can test an address they already know against it. Use 32 random bytes or more; changing it forgets every address remembered |
| `breaker.failure_threshold` | `20` | the fewest store calls in a row that must fail or miss `deadline` for the store breaker to open |
| `breaker.failure_window` | `500ms` | how long they must keep failing, with none succeeding, for it to open |
| `breaker.cooldown` | `2s` | how long the breaker stays open, deciding without the store, before it probes the store |
| `breaker.probes` | `5` | decisions the half-open breaker lets reach the store: when they all succeed it closes, and when one fails it opens for another `cooldown` |

Both bounds apply to every route that brings events in. `catraca replay`
ignores them, since it decides historical events. See
[limits](api.md#limits) for why and for the other limits on an event.

**Deduplication.** Each event with an `id` that increments a counter costs
one entry for `dedupe_ttl`: a Redis key of about 135 bytes; on a Redis
Cluster one key of about 160 bytes per hash slot the event's counters live
in, six for a send with an API key, an IP and a sender domain; about 80
bytes in the memory store. Events without an `id` cost nothing, since
generated ids never repeat. At 1,000 sends a second, all with ids, the
default keeps 600,000 entries: about 80 MB on a single Redis, about 580 MB
over a cluster's nodes. The window has to
outlast the retries it guards against: a platform retrying a request that
timed out does so within seconds, Amazon SNS's default delivery policy
gives up after about a minute and useSend's after about three, but an SNS
[delivery policy](feedback.md#amazon-ses) of your own may retry for up to
an hour, and a useSend call retried by hand from its dashboard may come
later still. An event sent again after the window counts again. Raise
`dedupe_ttl` to the longest retry schedule you use, if the memory is there;
with `maxmemory-policy volatile-ttl` (see [redis](#store)), the entries are
among the first keys evicted under memory pressure, which costs retries
their protection before it costs counters.

**The recipient memory.** Each address remembered costs one member of a
sorted set: about 110 bytes on Redis, split over 16 keys (16 hash slots on a
cluster), and about 50 bytes in the memory store. It is kept for
`recipient_memory` after its latest hard bounce or complaint, so the memory
holds the distinct addresses that bounced or complained in that window: at
10,000 a day, about 33 MB on Redis with the default. A send checks at most
100 of its addresses, in the same round trip as its other signals; see
[benchmarks](benchmark.md#the-recipient-memory) for the cost.

**The store breaker.** With Redis down or stalled, every decision would
still wait out its deadline before degrading, and send another round trip
to a Redis that is struggling. Once store calls have failed or missed the
deadline for `breaker.failure_window`, none succeeding, and at least
`breaker.failure_threshold` of them, the breaker opens: for
`breaker.cooldown`, decisions skip Redis and are degraded at once, the same
decision a deadline miss gives, and `key_leak` events answer `503` with
`Retry-After` at once (the server still blocks the key from memory). Then
`breaker.probes` decisions go to Redis; when they all succeed the breaker
closes, and otherwise it opens for another cooldown.

The window is what tells an outage from an overload. An overload makes
decisions miss the deadline in bursts too, and a count alone would open
the breaker within milliseconds of one, cutting every decision off from
Redis for the cooldown; but the [adaptive limit](#admission) brings an
overload under control within a few rounds of the deadline, and calls
succeed again, while in an outage none does. During the window an outage
holds the decisions let in for the deadline at most, and the adaptive limit
sheds most of the others. The threshold keeps a few failures spread over a
quiet period from opening it. The cooldown is short because a probe costs a
few decisions a deadline each, while a degraded second costs detection; it
is also how long the breaker may keep deciding without Redis after Redis is
back. The breaker logs each change of state (`store breaker opened`,
`half-open`, `closed`, with how long it was open) and reports it in
`catraca_store_breaker_state`, `catraca_store_breaker_transitions_total`
and `catraca_short_circuited_decisions_total`. The memory store does not
fail, so its breaker stays closed.

### gate

The [precision gate](audit.md#the-precision-gate) that `GET /v1/stats/rules`
evaluates rules against, and that a rule must pass before a ruleset load
lets it enforce.

| field | default | |
|---|---|---|
| `min_labeled` | `30` | labeled matches a rule needs, at least 1 |
| `min_precision` | `0.9` | required Wilson 95% lower bound on precision, in (0, 1] |
| `on_load` | `enforce` | what loading a ruleset does with a rule it would newly enforce that has not passed the gate: `enforce` holds it in shadow mode, `warn` lets it enforce and logs a warning, `off` does not check |

`catraca rules gate` and `catraca report` take the same values as
`--min-labeled` and `--min-precision`, so CI does not need this file.

**The gate on load.** `catraca rules gate` keeps unproven rules out of a
ruleset in CI; `on_load` keeps them out of a running server too, whatever
way the file got there. When a ruleset loads, at start or on a reload, each
rule it would make enforce that this server does not enforce now (a new
rule in enforce mode, or one switched from shadow) and that has no
`override` is checked against the labels in the audit database, counted
over all time as `catraca rules gate` counts them. With `enforce`, a rule
that does not pass is held in shadow mode and the rest of the file loads:

- held rules are evaluated and recorded as shadow rules, so they keep
  collecting the labels that will let them pass;
- decisions carry the version of the ruleset as it is applied, which is
  the version the file would have with those rules written in shadow mode,
  so every decision says which rules could act;
- each held rule is logged with its labels and what it lacks, listed under
  `held` in `/readyz?verbose` and in the answer of `POST /v1/rules/reload`,
  and counted in `catraca_ruleset_gate_failures{status}`;
- the gate runs again on the next load: once its matches are labeled,
  reload, or change the file, and the rule enforces.

The whole file is not refused, because that would also hold back every
other change in it, such as a fix to a rule that blocks good senders, and
an instance starting with it would have no ruleset at all. Shadow mode is
where every rule starts anyway: holding one there costs detection, never a
false positive.

A rule this server already enforces is not checked again when the file
changes elsewhere, nor when its condition changes: a promotion is a change
of mode, as in CI. At start the server enforces nothing yet, so every
enforced rule without an override is checked; a rule whose precision fell
below the gate after it was promoted is held by instances that start after
that, while the others keep enforcing it until it is retired.
`catraca report` lists such rules.

**When the audit database cannot answer** (a Postgres database still being
opened at start, or down), the gate cannot run. With `enforce`, the rules
it would check stay in shadow mode, listed with the status `unavailable`,
and the gate is tried again every few seconds, without reading the file
again; once the database answers, the rules that pass enforce. A rule
with an `override` never waits for the gate, so give one to a rule that
must enforce from the first second whatever happens to the database. With
`warn` the rules enforce, and the log says the gate could not run.

`warn` suits a deployment that gates promotions in CI and wants the server
only to point out what slipped through; `off` skips the labels query.

### hooks

The webhooks that carry out the effects of enforced rules, one per effect.
See [hooks](hooks.md) for the request and how to verify it.

| field | default | |
|---|---|---|
| `[].name` | required | the effect, as rules list it under `effects`: lowercase letters, digits and `_` |
| `[].url` | required | an absolute `http` or `https` URL |
| `[].secret` | required | signs each request; at least 16 characters |
| `[].previous_secrets` | | secrets being rotated out: each request is also signed with each of them, so a receiver that has not switched yet accepts it; see [rotating secrets](rotation.md#webhook-secrets) |
| `[].timeout` | `10s` | bound on one attempt |
| `[].headers` | | extra headers, for example `Authorization`; `Catraca-*` headers cannot be set |
| `[].concurrency` | `4`, or `outbox.workers` if fewer | deliveries to this hook attempted at once, at most `outbox.workers` |
| `[].max_attempts` | `15` | attempts before a delivery is given up (marked dead) |
| `[].max_age` | `24h` | how long a delivery is tried for, from when it was queued; longer than `timeout`. A delivery not delivered by then is given up |

```yaml
hooks:
  - name: revoke_key
    url: https://platform.internal/hooks/catraca/revoke-key
    secret: ${CATRACA_HOOK_SECRET}
    headers:
      Authorization: Bearer ${PLATFORM_HOOK_TOKEN}
    max_age: 6h
```

An effect that an enforced rule lists and no hook carries out is skipped;
`config check` and the server's log warn about it.

A delivery ends at whichever limit comes first. With the default backoff,
15 attempts take 45 to 90 minutes, so `max_attempts` ends a delivery to a
receiver that keeps failing, and `max_age` ends one that waited too long to
be tried at all, after an outage of Catraca or behind a backlog: an effect
such as suspending an account may be unwanted a day late. To keep retrying
through a longer outage of the receiver, raise `max_attempts` too: each
retry after the tenth comes 7.5 to 15 minutes after the one before. See
[retries](hooks.md#retries).

### outbox

How the hooks' deliveries are sent. See [hooks](hooks.md#delivery).

| field | default | |
|---|---|---|
| `workers` | `16` | deliveries attempted at once across every hook. Each hook takes at most its own `concurrency`, so a hook whose endpoint hangs holds that many and the others keep the rest |

Each attempt holds a worker for up to its hook's `timeout`. Give the pool
room for every hook that may be slow at once: with the defaults, three
hooks hanging until their timeout still leave four workers for the rest.

### feedback

Delivery feedback routes. A provider is enabled when its section is present;
see [feedback](feedback.md) for each provider's setup.

| field | default | |
|---|---|---|
| `ses.topic_arns` | required | the SNS topic ARNs accepted on `/v1/feedback/ses` |
| `ses.account_tag` | | the SES message tag holding the account id |
| `ses.account_header` | | the email header holding the account id, the fallback; one of the two is required |
| `usesend.secret` | required | the webhook signing secret shown by useSend, for `/v1/feedback/usesend` |
| `usesend.previous_secrets` | | secrets the webhook had before; calls signed with them are still accepted |
| `usesend.account_metadata_key` | | read the account id from the email's metadata instead of the team id |
| `generic.secret` | required | the shared secret `/v1/feedback` requests are signed with; at least 16 characters |
| `generic.previous_secrets` | | secrets being rotated out; requests signed with them are still accepted |

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
| `github.resolver.previous_secrets` | | secrets being rotated out: requests are also signed with them, and raw tokens sealed with them still open; see [rotating secrets](rotation.md#resolver-secret) |
| `github.resolver.send_raw_token` | `false` | send the raw token, not only its SHA-256; requires an `https` URL |
| `github.feedback` | `false` | answer GitHub with true and false positive labels, once GitHub enables feedback for the partnership |
| `github.github_token` | | a GitHub token without scopes, to raise the rate limit on GitHub's public keys endpoint |
| `github.keys_url` | GitHub's | where GitHub's signing keys are fetched; change it only for tests |
| `github.max_attempts` | `1000` | attempts at a leaked-key report before it is given up as dead; at least 1 |
| `github.max_age` | `24h` | how long a report is retried, from when it arrived or was requeued, before it is given up as dead. With the default backoff (1s doubling to 5m) this ends a report before `max_attempts` does |

Reports are stored in the audit database before GitHub's request is
answered, and processed from there; with `send_raw_token`, the raw token is
stored encrypted until it resolves. See
[retries and dead reports](secret-scanning.md#retries-and-dead-reports) and
[privacy of tokens](secret-scanning.md#privacy-of-tokens).

### logging

| field | default | |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn` or `error`. Health, readiness and metrics requests are logged at `debug` |
| `format` | `json` | `json` or `text` |

Logs go to stderr. Tokens, secrets and message content are never logged.

### tracing

OpenTelemetry tracing, off by default; see [tracing](tracing.md). A field
left out is read from the standard `OTEL_*` variable named below, and takes
its default when that is unset too.

| field | default | |
|---|---|---|
| `enabled` | `false` | trace requests, decisions, store calls, audit writes, webhooks and leaked-key reports. `OTEL_SDK_DISABLED=true` turns it off again |
| `endpoint` | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, or `http://localhost:4318` | the OTLP/HTTP collector spans are sent to, an `http` or `https` URL; one without a path gets `/v1/traces` |
| `sample_ratio` | `OTEL_TRACES_SAMPLER`, or `0.1` | the share of traces kept among those that start at Catraca, from 0 to 1. A request whose `traceparent` says its caller kept the trace is always traced |
| `service_name` | `OTEL_SERVICE_NAME`, or `catraca` | the `service.name` of the spans |

Headers (such as a backend's API key), TLS, compression and the export
timeout come from the `OTEL_EXPORTER_OTLP_*` variables
([list](tracing.md#environment-variables)). With tracing on, the access log
names each request's trace and `/metrics` serves exemplars.

## Environment variables the CLI reads

| variable | used by | |
|---|---|---|
| `CATRACA_CONFIG` | `serve`, `config check` | default for `-config` |
| `CATRACA_AUDIT_DSN` | `rules gate`, `report`, `secretscan` | default for `--audit` |
| `CATRACA_TOKEN` | `label` | the API token, when `--token` is not given |
| `CATRACA_SERVER` | `label` | default for `--server` (`http://localhost:8080`) |

Any other variable is read only where catraca.yaml references it, except
the `OTEL_*` variables [tracing](tracing.md#environment-variables) reads.
