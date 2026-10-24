# Faults

What Catraca does when a dependency misbehaves, and the test that checks
each promise. The [design](design.md) states the principle: a broken store
degrades detection, it never blocks everyone, and a broken audit database
degrades traceability, not decisions. The scenarios below break Redis,
Postgres, webhook receivers and the secret scanning resolver in the middle
of a run and hold the server to it.

## How the scenarios run

Each scenario starts the server as it is deployed (`app.New`, its HTTP
server, a real Redis and, in CI, a real Postgres) with the dependency behind
[`internal/faultproxy`](../internal/faultproxy), a TCP proxy that injects
the fault while the server runs:

| fault | what the client sees |
|---|---|
| latency, with jitter | each reply arrives late, in order |
| slow bandwidth | each connection carries so many bytes a second |
| blackhole | connections are accepted and never answered; bytes sent either way are lost, and a connection that lost some stays dead, as after a long partition |
| reset | open connections, and each new one while it is on, get a TCP reset |
| refuse | nothing listens: dials fail with "connection refused" |
| lost reply | the next request matching a pattern reaches the server, which acts on it; the connection closes before its reply |

The proxy is in the repository rather than Toxiproxy run in process: it is
a few hundred lines with no dependencies, where Toxiproxy brings its HTTP
API, logger and metrics into `go.mod`, and it can lose the reply to one
particular request, which is how a retry after an applied Lua script is
tested. The store, engine and app tests that used fakes of their own for a
dead Redis use it too.

Besides what each scenario checks, every one of them checks, throughout:

- **Decisions keep coming.** A load of 16 concurrent clients gets every
  decision answered `200`, each within the deadline (plus the dispatch
  budget for decisions with effects) and a one second margin for the HTTP
  round trip on a busy machine. Every fault holds a call up for longer than
  that, so a decision that waited for one fails the test. The log of each
  phase gives the latency percentiles, seen from the client and as the
  engine measured them.
- **Readiness and metrics tell the truth.** `/readyz` stays ready, since a
  shared dependency must not take every instance out of the load balancer,
  while `/readyz?verbose` and `catraca_dependency_up` report the dependency
  down, timing out or slow, and back.
- **Nothing panics, nothing leaks.** No panic is logged. Once the fault is
  over, the goroutines it held up return: the count, leaving out the
  proxy's own, which stand for the network, comes back to within 10 of what
  it was before the fault. Once the test has closed the server and its
  fakes, it comes back to what it was before the test.
- **Recovery is full.** Redis scenarios end with a second of decisions none
  of which is degraded; Postgres scenarios with the work that waited in the
  database done and a new decision written and read back.

## The matrix

### Redis (the store)

| fault | expected | test |
|---|---|---|
| Replies 2.4 s late: past the deadline and the 2 s dependency check, within go-redis's 3 s read timeout | Decisions are degraded at the deadline; those Redis applied late are not marked uncounted. The adaptive limit drops, and the breaker opens once calls have missed the deadline for its window. `?verbose` reports the store `timeout`. Once Redis is fast again the breaker closes through its probes, the limit climbs back and decisions are whole again. | `TestFaultRedisLatency` |
| Blackhole | Decisions are degraded at the deadline until the breaker opens, about the deadline plus its 500 ms window into the fault, then at once. A key leak is answered `503 unavailable` with `Retry-After: 1` at once while it is open, not at the deadline. Once Redis is back, the breaker closes after its cooldown, and the calls the blackhole held return at the read timeout. | `TestFaultRedisBlackhole` |
| Every connection reset | The breaker opens after a run of failed decisions; later decisions skip the store; a key leak answers `503`. | `TestStoreBreakerWithRedisDown` |
| A Lua script's reply lost after Redis ran it | The decision is degraded and uncounted, so feedback is answered `503` with `Retry-After` and the provider sends it again. The retry, with the same event id, is a duplicate: the event counts once, and a send sent again counts once toward `burst`. One failure leaves the breaker closed. | `TestFaultRedisLostReply`; at the store, `TestRedisRetryAfterALostReplyCountsOnce` and `TestOpenRedisDoesNotResendScripts` |
| A restart without persistence: connections reset, refused for 1.5 s, keys and loaded scripts gone | Decisions go on, degraded, while it is down. Afterwards the script is loaded again on the `NOSCRIPT` that follows, without a failed decision, and counters start again from zero. | `TestFaultRedisRestart` |
| Unreachable, a key leak | `Decide` answers at the deadline, not after the client's read timeout. | `TestDecideKeyLeakWithRedisUnreachable` |

### Postgres (the audit database)

| fault | expected | test |
|---|---|---|
| Down mid-run, as in a crash or a restart: connections reset and refused | Decisions are unaffected. Writes that fail are counted in `catraca_audit_failed_total`, and once the 8192-decision queue is full, decisions are dropped and counted in `catraca_audit_dropped_total`. `?verbose` reports the audit database `unavailable`. An effect whose outbox write fails is lost: counted in `catraca_hooks_enqueue_errors_total` and logged with what to carry out by hand. A secret scanning batch is answered `503` with `Retry-After`. Once Postgres is back, the deliveries and leaked-key reports waiting in it resume, decisions are written again and the queue drains. | `TestFaultPostgresDown` |
| Partitioned: packets dropped, so queries hang and their connections die | The same, with every call to the database bounded: batch writes at 10 s, outbox writes at 5 s (the decision is answered at its dispatch budget, and the delivery counted as deferred), batch stores at 10 s, claims of deliveries and reports at 10 s, dependency checks at 2 s, `?verbose` reporting `timeout`. New connections are bounded by the DSN's `connect_timeout`, which [the configuration](config.md#audit) advises setting. Once the network is back, work resumes on new connections. | `TestFaultPostgresPartition`; for the claims, `TestHungOutboxQueriesAreGivenUp` and `TestHungClaimIsGivenUp` |
| Replies 300 ms late | Decisions are unaffected. The audit writer falls behind the load, so its queue fills and drops decisions, counted. `?verbose` shows the checks taking that long. A decision with effects is answered within its dispatch budget while the outbox write finishes in the background, and the effect is delivered. Once Postgres is fast again the queue drains. | `TestFaultPostgresSlow` |
| Unreachable when the server starts | The server starts and is ready; decisions are made and queued for the audit log; reads answer `503 audit_unavailable` and secret scanning batches `503` until it opens. | `TestServesWhileTheAuditDatabaseIsUnreachable`, `TestSecretScanningAnswers503UntilTheAuditDatabaseOpens` |

### Webhook receivers and the secret scanning resolver

| fault | expected | test |
|---|---|---|
| One hook's receiver hangs, then answers `500` | Its attempts time out or fail and back off, a second or more apart, holding at most its own concurrency of the workers; the other hook, on the same two workers, delivers every effect at once. Once the receiver is back it gets every delivery, once, and none is dead. | `TestFaultWebhookReceiverDown`; at the hooks, `TestSlowHookDoesNotHoldUpOthers` |
| The resolver refuses connections | A batch is stored and answered `202`; its reports stay pending, not dead, through failed attempts that back off. Decisions are unaffected. Once the resolver is back the reports are acted on: the key is blocked and `revoke_key` called once. | `TestFaultSecretScanningResolverDown`; across a restart, `TestSecretScanningSurvivesARestart` |

## Running them

The scenarios take a few minutes, so `go test ./...` skips them unless
`CATRACA_TEST_FAULTS` is set. The Redis ones need `CATRACA_TEST_REDIS_URL`
and the Postgres ones `CATRACA_TEST_POSTGRES_URL`; each skips without its
server. They run one at a time, since each counts the process's
goroutines.

```sh
CATRACA_TEST_FAULTS=1 \
CATRACA_TEST_REDIS_URL=redis://localhost:6379/0 \
CATRACA_TEST_POSTGRES_URL='postgres://catraca:catraca@localhost:5432/catraca_test?sslmode=disable' \
  go test -count=1 -run '^TestFault' -v ./internal/app/
```

Each scenario keeps its Redis keys under a prefix of its own and its
Postgres tables in a schema of its own, both deleted when it ends. The
Redis restart flushes the server's loaded scripts, which only makes other
clients load theirs again.

CI's `faults` job runs every scenario, with the race detector, against the
same Redis and Postgres services as the Linux test job.
