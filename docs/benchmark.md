# Benchmarks

What a decision costs, measured on one developer machine: the Go benchmarks
for each piece, then `POST /v1/decide` under load with the memory and the
Redis store, and what happens when Redis saturates, stalls or slows down. The Redis numbers come before and after the change that runs
each decision's store work as one Lua script (see
[the Redis store](#the-redis-store)). The caveats at the end say what these
numbers do not show.

## Machine

| | |
|---|---|
| CPU | AMD Ryzen 5 7600X, 6 cores, 12 threads |
| OS | Windows 11 Pro (build 26200) |
| Go | 1.27.2 |
| Redis | 7.4.11, the msys2 build from [redis-windows](https://github.com/redis-windows/redis-windows), on 127.0.0.1, no persistence |
| Redis Cluster | three 7.4.11 primaries on the same machine, no replicas |

The load generator, Catraca and Redis all run on this machine.

## Method

**Go benchmarks** use `testing.B.Loop`. `BenchmarkObserve` records one send
event (an API key, an IP, a sender domain, three recipients) for 1000
accounts in turn, so most counters hold a bucket or two.
`BenchmarkObserveBusy` first sends, for each of 20 accounts, one event in
every bucket of every window, so every read covers 60 live buckets, as for
an account that sends all the time. Each runs against the memory store,
miniredis over loopback (client overhead only), a real Redis
(`CATRACA_TEST_REDIS_URL`) and a real Redis Cluster
(`CATRACA_TEST_REDIS_CLUSTER`).

**Redis CPU per event** (`redis-us/op`) is the growth of `used_cpu_user +
used_cpu_sys` in `INFO cpu` during the benchmark loop, divided by its
iterations, summed over the primaries of a cluster. It says how many events
one Redis core can carry, which latency at low load does not.

**HTTP load** uses [`bench/load`](../bench/load), an open-loop generator:
requests start on schedule whether or not earlier ones have finished, so a
slow server shows up as latency instead of a lower rate. It sends in
batches every 5 ms, warms up for 3 s and measures for 20 s. Events are
sends from 5000 accounts, skewed so a few accounts send most of them, with
one recipient and one link each. Catraca runs the default ruleset (one rule
enforced, eight in shadow) with the SQLite audit log, and each run starts a
fresh server on an empty Redis database.

**Clocks.** Go's monotonic clock ticks about every 0.5 ms on Windows, so the
generator times requests with the performance counter
(`QueryPerformanceCounter`) instead. The engine's own time, `latency_us` in
each decision, is taken by the server with Go's clock and is quantized to
about 0.5 ms here, so the tables give the round trip.

"Before" is commit 9ed56d5, the store as it was; "after" is this branch.
Before and after runs were interleaved, so both saw the same machine.

## Go benchmarks

Medians of three to five interleaved runs on a quiet machine.

### Engine and rules

| benchmark | time | allocations |
|---|---|---|
| `BenchmarkDecide`: the engine with a canned signal set and the default ruleset | 3.1 µs | 38 |
| `BenchmarkDecideParallel`: the same from 12 goroutines, per decision | 0.82 µs | 38 |
| `BenchmarkServeDecide`: `POST /v1/decide` through the HTTP layer, around a decider that answers at once | 8.0 µs | 53 |
| `BenchmarkEvaluateDefault`: the default ruleset alone | 2.2 µs | 31 |

```sh
go test ./internal/engine ./internal/rules ./internal/api -run '^$' -bench 'Decide|EvaluateDefault'
```

### Observe

Recording one event and reading all its signals back, per event.

| store | accounts | before | after | Redis CPU before | Redis CPU after | allocations |
|---|---|---|---|---|---|---|
| memory | 1000 sparse | 12 µs | 12 µs | | | 129 → 129 |
| memory | 20 busy | 42 µs | 42 µs | | | 141 → 141 |
| miniredis | 1000 sparse | 1.48 ms | 0.74 ms | | | 10,315 → 7,212 |
| miniredis | 20 busy | 2.47 ms | 0.89 ms | | | 14,718 → 7,759 |
| Redis | 1000 sparse | 1.36 ms | 0.63 ms | 1,344 µs | 628 µs | 2,355 → 583 |
| Redis | 20 busy | 1.95 ms | 0.69 ms | 1,901 µs | 667 µs | 3,887 → 594 |
| Redis Cluster | 1000 sparse | 0.94 ms | 0.55 ms | 1,865 µs | 1,172 µs | 2,398 → 1,019 |
| Redis Cluster | 20 busy | 1.19 ms | 0.56 ms | 2,437 µs | 1,344 µs | 3,928 → 1,030 |

The memory store did not change. miniredis runs in the test process, so its
own allocations count too; the Lua interpreter it embeds accounts for most
of the "after" ones. Client memory per event on a real Redis went from
305 KB to 86 KB.

```sh
CATRACA_TEST_REDIS_URL=redis://localhost:6379/0 \
CATRACA_TEST_REDIS_CLUSTER=localhost:7001,localhost:7002,localhost:7003 \
  go test ./internal/signal -run '^$' -bench Observe -benchtime 3000x
```

### A send to many domains

The cost of an event grows with its distinct recipient domains: each one is
added to two distinct sets, four Redis calls apiece, inside the script that
holds Redis while it runs. `BenchmarkObserveWideSend` sends to the most
recipients an event may have ([`event.MaxRecipients`](api.md#limits),
1,000), each at a domain of its own. It was measured while other programs
loaded the machine, so it is given next to `BenchmarkObserve` on the same
server in the same run:

| benchmark | Redis CPU per event |
|---|---|
| `BenchmarkObserve` (three recipients) | 770 to 940 µs |
| `BenchmarkObserveWideSend` (1,000 domains) | 25.6 to 26.3 ms |

About 25 µs per distinct domain, so the 1,000 limit bounds one event to
about 26 ms of Redis time. Before the limit, a 1 MiB body could carry some
40,000 addresses: about a second during which no other decision got its
signals.

```sh
CATRACA_TEST_REDIS_URL=redis://localhost:6379/0 \
  go test ./internal/signal -run '^$' -bench '^(BenchmarkObserve|BenchmarkObserveWideSend)$/^redis-server$' -benchtime 100x -count 3
```

### Events with ids

An event with an `id` counts once per id ([retries](api.md#retries)): the
script that applies its increments first sets a key for the id with
`SET NX PX`, and skips them when the key exists. `BenchmarkObserveWithID` is
`BenchmarkObserve` with a new id on every event; `BenchmarkObserveRetry`
sends each event once before the loop, then again on every iteration, so
each is a duplicate. They were measured while other programs loaded the
machine, so whole-call times varied twofold between runs and are not
given; Redis's own accounting (`INFO commandstats`, reset before each run,
four interleaved runs of 3,000 events) is steadier:

| benchmark | script time per event | `SET NX PX` per event |
|---|---|---|
| `BenchmarkObserve` (no id) | 424 to 460 µs | |
| `BenchmarkObserveWithID` | 411 to 484 µs | 3.4 to 3.7 µs |
| `BenchmarkObserveRetry` | 371 to 397 µs | 2.4 to 2.6 µs |

The id's key costs one write in the script, about 1% of its time, which the
runs cannot tell from noise; a duplicate skips its 13 increments and costs
less than the first sending. In Go, naming the event (SHA-256 over its
type, account and id) takes 0.1 µs and one allocation, and the memory store
takes about 0.4 µs and two allocations more per event with an id, against
15 to 20 µs for the whole `Observe`. `BenchmarkDecide` did not change: the
engine only reads the result. Each id's key takes about 135 bytes of Redis
memory (`used_memory` over 100,000 keys), 160 bytes for a cluster's longer
keys, of which a send has six, and about 80 bytes in the memory store; see
[`engine.dedupe_ttl`](config.md#engine) for what that comes to.

```sh
CATRACA_TEST_REDIS_URL=redis://localhost:6379/0 \
  go test ./internal/signal -run '^$' -bench '^BenchmarkObserve(WithID|Retry)?$/^redis-server$' -benchtime 3000x
```

### The recipient memory

A send looks up at most 100 of its addresses in the
[recipient memory](signals.md#the-recipient-memory), one `ZSCORE` each in
the script it already runs, after hashing every address to pick them.
`BenchmarkObserveRecipientMemory` sends the same event with the memory on
and off, to 3, 100 and 1,000 recipients, half of them among 2,000
remembered addresses. Medians of three runs of one second per case; Redis's
time per event varied by a quarter between runs, as in the sections above:

| recipients | memory store, off | memory store, on | Redis CPU, off | Redis CPU, on |
|---|---|---|---|---|
| 3 | 17 µs | 24 µs | 734 µs | 640 µs |
| 100 | 36 µs | 66 µs | 677 µs | 1,034 µs |
| 1,000 (100 checked) | 254 µs | 418 µs | 654 µs | 806 µs |

With three recipients, the common case, the difference is within noise.
A lookup costs about 1.5 to 3.5 µs of Redis time on this Redis build, about
as much as the `SET NX` of an id, so the 100-address cap bounds a send to
some 150 to 360 µs of it, against the 26 ms 1,000 domains may cost. On a
three-node cluster the lookups go out as up to 16 more script calls, one per
set of the memory, in the same pipeline: in two runs a send to 100
addresses took 0.67 ms instead of 0.50 ms, and about 420 µs more Redis time
over the primaries, and one to 1,000 took 1.05 ms instead of 0.70 ms. In Go
the cost past 100 addresses is hashing: an HMAC-SHA-256 per address, about
0.2 µs, to pick the 100 checked without letting the sender choose them.

```sh
CATRACA_TEST_REDIS_URL=redis://localhost:6379/0 \
  go test ./internal/signal -run '^$' -bench '^BenchmarkObserveRecipientMemory$' -benchtime 1s -count 3
```

### The audit log

`BenchmarkRecordSQLite` records 20,000 decisions, a tenth of them matched
by a rule, into a SQLite file in the temp directory and waits until they
are written. `BenchmarkPruneSQLite` has retention delete 50,000 expired
ones, pauses included, with the SQLite default of 500 rows a statement and
with the Postgres default of 5,000. Three runs each:

| | decisions a second |
|---|---|
| written, batches of 256 | 126,000 |
| deleted, 500 a statement, pause as long as each took | 35,000 |
| deleted, 5,000 a statement | 74,000 |

The writer has sixty times the headroom 2,000 decisions a second need.
Retention is held back by its pause: a 500-row statement takes a few
milliseconds and then waits at least 10 ms. Both tables fit in memory
here; on a database much larger than RAM, deletes read from disk and slow
down most. Encoding a decision for the buffer takes about 3 µs, and
deciding whether to keep a plain allow under `audit.sample_allowed` about
5 ns. What these numbers mean for a deployment is in
[sizing at 10× volume](audit.md#sizing-at-10-volume).

```sh
go test ./internal/audit -run '^$' -bench 'SQLite$' -benchtime 3x
```

### Entities

Each [entity](signals.md#entity) a send names adds two increments, two
distinct-set adds and four reads to the script it already runs.
`BenchmarkObserveEntities` sends the event of `BenchmarkObserve` with 0, 1
and 4 entities declared, every send naming each one, with 200 values per
entity shared by 1,000 accounts. Medians of three runs of 5,000 sends:

| entities | memory store | Redis, per send | Redis CPU |
|---|---|---|---|
| 0 | 16 µs | 631 µs | 603 µs |
| 1 | 16 µs | 726 µs | 672 µs |
| 4 | 26 µs | 1,043 µs | 981 µs |

An entity costs a send some 90 to 100 µs of Redis time on this Redis build,
about a seventh of the send's own, and 3 µs on the memory store. On a
cluster its two keys are two more script calls in the same pipeline, as for
the other counters. Declare the attributes rules read, not every one a
platform sends.

```sh
CATRACA_TEST_REDIS_URL=redis://localhost:6379/0 \
  go test ./internal/signal -run '^$' -bench 'BenchmarkObserveEntities/./^(memory|redis-server)$' -benchtime 5000x -count 3
```

## The Redis store

Before, a send event's batch was about 90 pipelined commands, and every
count and distinct count named its 60 bucket keys: some 1,700 keys and
1,900 arguments per event. Commandstats accounted for only a third of the
1.3 ms of Redis CPU per event; parsing arguments and reading about 100 KB of
request was most of the rest. One Redis core saturated near 800 events a
second.

What was measured on sparse accounts against a real Redis:

| variant | Observe | Redis CPU per event | why not |
|---|---|---|---|
| pipeline, 60 bucket keys per read (before) | 1.25 ms | 1.28 ms | |
| a Lua script per count, summing its 60 declared bucket keys | 1.95 ms | | slower: 41 µs per call against 15 µs for MGET, and the 60 keys are still sent |
| one hash per counter, HGETALL, summed in Go | 0.58 ms | 0.57 ms | old buckets cannot be dropped without a script, so hashes grow; a busy counter's 60-field HGETALL costs 14.5 µs, and the busy benchmark only fell from 1.86 to 1.34 ms |
| the same, summed in Lua | 0.69 ms | 0.71 ms | slower than summing in Go, and busy counters stay O(60) |
| pipeline over 6-bucket block keys, at most 15 keys per read | | about half of before | Redis CPU as low as the script's, but four times its client allocations (2,169), O(15) reads and twice the writes |
| one script per batch over rolling counters (after) | 0.63 ms | 0.63 ms | |

The first four rows were measured at the start of this work with Redis CPU
taken over the whole test process; the block-key pipeline was only measured
while another program loaded the machine, so only its ratio to the others
measured alongside it is given. The chosen design, in
[`internal/store/redis.go`](../internal/store/redis.go) and
[`redis_script.go`](../internal/store/redis_script.go):

- **One script call per batch** on a single server: one command, one reply
  with only the results, and an atomic batch. Inside the script each
  `redis.call` costs about 0.7 µs (reads) to 1.3 µs (writes) on this build.
- **A counter is one hash** with a field per bucket, its newest bucket and
  the sum of the buckets it holds. Buckets that leave the newest window are
  dropped when a newer bucket is written, so a count ending in the newest
  bucket reads the sum: O(1). The script caches each counter it touches, so
  the count that follows an increment costs no call.
- **A distinct set** keeps its HyperLogLog per bucket plus one per block of
  6 aligned buckets. A count merges the whole blocks and the buckets at
  either end, 10 or 15 keys instead of 60, and the estimate is identical,
  since a HyperLogLog union is a register-wise maximum.
- **NOSCRIPT** after a restart, a failover or `SCRIPT FLUSH`: a call that
  fails with it ran nothing, so it is sent again with `EVAL`, which also
  loads the script.

Counts are the same as before. The contract suite passes on the memory
store, miniredis, miniredis through a Cluster client, a real Redis and a
real three-node cluster, and replaying 400 random events gives the same
signals on the memory store and on both real servers. The one difference is
in expiry: a counter or block expires w + w/60 after its last write, as each
bucket did, so only when the wall clock runs ahead of event time (a replay
slower than real time) can a count keep a bucket whose own TTL would have
run out.

### Redis Cluster

A script may only touch keys of one hash slot. The store already puts every
bucket of a counter or distinct set under one hash tag, but a batch spans
the account, the API key, the IP and the sender domain: about 25 tags for a
send event. On a Cluster (or Ring) client the batch is split into one script
call per tag, in batch order within each call, and the calls go out as one
pipeline that go-redis splits by node and sends concurrently. Each call is
atomic and holds every operation on its keys, so order within a key holds
and a NOSCRIPT retry stays exactly-once; a call redirected with MOVED or ASK
did not run and is resent by go-redis. On three local primaries an event
costs 0.55 ms against 0.94 ms before. The configuration's `store.redis.url`
connects to one node; a cluster is used through `store.NewRedis` with a
Cluster client.

### The deadline

The engine gives the signal lookup 10 ms, but go-redis only honors a context
while it waits for a free connection, not on the connection itself, unless
the client sets `ContextTimeoutEnabled`. Under load, decisions therefore
waited for Redis for 100 ms and more instead of degrading at the deadline.
Setting `ContextTimeoutEnabled` was worse: a deadline then closes the
connection mid-reply, and once latency neared the deadline every request
redialed, which exhausted ephemeral ports here and degraded every decision
while Redis sat idle. The store now returns at the deadline and lets the
round trip finish on its own connection, which goes back to the pool.

## HTTP load

`POST /v1/decide` on a quiet machine, before and after interleaved per rate.
Round trip as the platform sees it (connection, JSON, rules, store, audit),
in ms. Redis CPU is the share of one core over the run. Degraded is the
share of decisions made without signals because the store missed the 10 ms
deadline.

### Redis

| req/s | | p50 | p90 | p99 | p99.9 | Redis CPU | degraded |
|---|---|---|---|---|---|---|---|
| 250 | before | 1.68 | 2.49 | 2.90 | 3.73 | 30% | 0 |
| | after | 0.95 | 1.39 | 1.69 | 2.70 | 15% | 0 |
| 500 | before | 2.88 | 3.32 | 3.77 | 5.28 | 51% | 0 |
| | after | 1.41 | 1.80 | 2.09 | 2.74 | 27% | 0 |
| 1000 | before | 5.07 | 6.95 | 15.0 | 20.0 | 99% | 0 |
| | after | 2.21 | 2.62 | 2.97 | 3.37 | 45% | 0 |
| 2000 | before | 102 | 123 | 135 | 159 | 100% | 39% |
| | after | 4.26 | 4.74 | 10.2 | 10.7 | 84% | 1.2% |
| 4000 | before | 10.7 | 124 | 144 | 159 | 100% | 72% |
| | after | 10.5 | 10.8 | 11.3 | 11.8 | 100% | 100% |

Redis CPU per decision went from 1.2 ms to 0.6 ms at 250 req/s (0.45 ms at
1000), so one core of this Redis build carries about 2,000 decisions a
second instead of about 800. Near saturation the old store varies a lot
between runs: an earlier run at 1000 req/s, also at 99% Redis CPU, had a
p50 of 29 ms.

Past capacity (4000 req/s here) every decision still answers within the
deadline, but nearly all of them degrade: the round trips that reach Redis
queue behind each other and miss the deadline too. A smaller pool
(`?pool_size=8` in the URL) let 19% through instead of none; part of that
is the Windows build of Redis, which slows down with more than 63
connections (see [overload and outages](#overload-and-outages)). The
deadline fix alone, on the old pipeline, kept decisions under 12 ms at 1000
req/s (p50 6.7, p99 10.4, 7% degraded) but added no capacity. Admission
control now sheds what Redis cannot take in time; the next section has the
numbers.

### Memory

| req/s | p50 | p90 | p99 | p99.9 | degraded |
|---|---|---|---|---|---|
| 1000 | 0.24 | 0.27 | 0.56 | 1.41 | 0 |
| 2000 | 0.26 | 0.48 | 0.73 | 1.93 | 0 |
| 4000 | 0.31 | 0.43 | 0.88 | 2.09 | 0 |
| 8000 | 0.49 | 0.65 | 1.27 | 2.82 | 0 |

No decision was dropped from the SQLite audit queue in any run.

```sh
go run ./bench/load -url http://localhost:8080 -token $CATRACA_API_TOKEN -rps 1000 -duration 20s
```

## Overload and outages

What happens when Redis saturates, stalls or slows down: before and after
[admission control](config.md#admission) and the
[store breaker](config.md#engine), with their defaults (a 10 ms deadline,
`max_inflight` 256 with an adaptive limit and a 2 ms wait; the breaker opens
after 500 ms of failures, at least 20, and probes every 2 s). "Before" is
commit 7871246, "after" this branch, run one after the other on the same
Redis, each on an empty database.

**Method.** The load is `bench/load` as above, sends only, with `-timeline`
and `-metrics` to print each second's latency, degraded share, decision
limit, breaker state and what was shed. Redis was slowed down with
`DEBUG SLEEP` (`--enable-debug-command local`). Two things differ from the
tables above. This machine was shared with other work, so a few seconds of
some runs show hiccups unrelated to Catraca; each comparison was run more
than once, and the tables give runs whose hiccups did not fall in the
interesting seconds. And the Redis URL sets `?pool_size=32`, because the
Windows build of Redis slows down sharply once more than 63 connections are
open, which go-redis's default pool (10 per CPU, 120 here) reaches under
load:

| other connections open | PING p50 | p90 | p99 |
|---|---|---|---|
| none | 0 ms | 0.5 ms | 1.0 ms |
| 60 | 0.5 ms | 0.5 ms | 1.0 ms |
| 64 | 0.5 ms | 42.6 ms | 46.1 ms |
| 120 | 0.5 ms | 17.0 ms | 53.1 ms |

With 120 connections idle in the pool after an overload, a lone call to an
idle Redis missed the 10 ms deadline more often than not, so the breaker's
probes kept failing: that measured the build's `select` loop (Cygwin's,
which waits on at most 64 handles at once), not Catraca. Redis on Linux
uses epoll and has no such limit.

### Load past capacity

Round trip in ms. Degraded is the share of decisions made without signals;
shed is the part of it admission control answered without the store, the
rest being decisions that missed the deadline.

| req/s | | p50 | p90 | p99 | max | degraded | shed |
|---|---|---|---|---|---|---|---|
| 1000 | before | 2.42 | 2.84 | 3.96 | 26.8 | 0.2% | |
| | after | 2.31 | 2.78 | 3.38 | 5.17 | 0 | 0 |
| 2000 | before | 4.53 | 10.9 | 34.7 | 101 | 16.6% | |
| | after | 3.99 | 5.45 | 12.1 | 131 | 4.7% | 4.6% |
| 4000 | before | 10.6 | 11.2 | 14.0 | 58.9 | 99.9% | |
| | after | 3.21 | 5.37 | 7.68 | 12.7 | 45.9% | 45.9% |
| 1000 after 4000 | before | 2.44 | 3.02 | 5.18 | 14.6 | 0.1% | |
| | after | 2.29 | 2.62 | 3.06 | 3.95 | 0 | 0 |

At 4000 req/s Redis here serves a little over 2000 decisions a second.
Before, every decision went to it, the round trips queued behind each
other, and 99.9% missed the deadline: about 4 decisions a second got their
signals. After, the adaptive limit settles between 7 and 14 decisions at
once, those get their signals in a few milliseconds, and the rest are
answered at once without the store: 2,160 decisions a second with their
signals, none of the admitted ones missing the deadline, and the breaker
stays closed. At 2000 req/s, near capacity, shedding 4.6% kept the rest
from tipping into deadline misses. Back at 1000 req/s, nothing is shed.
Another 1000 req/s pair had the hiccup in the other run (0.3% degraded
after, 0 before): at that rate the two are the same. The server held 133 to
197 goroutines at 4000 req/s before and 74 to 107 after.

```sh
go run ./bench/load -url http://localhost:8080 -token $CATRACA_API_TOKEN \
  -metrics http://localhost:8080/metrics -timeline -phases 4000x20s,1000x10s
```

### Redis stalls for five seconds

`DEBUG SLEEP 5` at 1000 req/s, from about second 10 to second 15 (the two
runs' seconds are a few tenths apart):

| second | | p50 | p99 | degraded | breaker | decision limit | short-circuited | goroutines |
|---|---|---|---|---|---|---|---|---|
| 9 | before | 2.55 | 10.7 | 24% | | | | 76 |
| | after | 2.37 | 3.30 | 0 | closed | 11 | 0 | 38 |
| 10 | before | 10.3 | 10.7 | 100% | | | | 82 |
| | after | 2.39 | 11.8 | 96% | open | 1 | 440 | 67 |
| 11 to 14 | before | 10.2 | 10.9 | 77 to 100% | | | | 35 to 83 |
| | after | 0.31 | 2.61 | 100% | open | 1 | 1000 a second | 65 to 71 |
| 15 | before | 2.54 | 3.31 | 0 | | | | 35 |
| | after | 0.32 | 1.46 | 100% | open | 1 | 999 | 31 |
| 16 | before | 2.53 | 2.98 | 0 | | | | 31 |
| | after | 0.40 | 3.10 | 59% | closed | 10 | 589 | 34 |
| 17 | after | 2.49 | 3.07 | 0 | closed | 10 | 0 | 35 |

Before, every decision of the stall waited out the 10 ms deadline. After,
the adaptive limit dropped to 1 within about a tenth of a second, so the
rest were shed, and the breaker opened 0.55 s in, after 84 calls had
failed over 507 ms; from then on decisions were answered in a third of a
millisecond without touching Redis. The probes at 2 and 4 seconds failed
against the sleeping Redis and the one at 6 succeeded, so the breaker closed
1.5 s after Redis was back, the cost of probing every 2 s: before recovered
at once. Either way the decisions of the stall were degraded, as they must
be with Redis asleep; the difference is how long the platform waited for
them. The goroutines left during the stall are the round trips that reached
Redis before the breaker opened, one per pooled connection, waiting for it
to wake.

### Redis slows down

A Redis that keeps answering, slowly: `DEBUG SLEEP 0.008` four hundred
times, 2 ms apart, about twelve seconds of a Redis that is asleep most of
the time, at 1000 req/s. Per second, during the slowdown:

| | p50 | p99 | degraded | shed | breaker |
|---|---|---|---|---|---|
| before | 8.1 to 10.2 | 10.8 to 23.4 | 39 to 51% | | |
| after | 2.64 to 2.69 | 10.6 to 11.1 | 44 to 48% | 23 to 31% | closed |

Shedding adds no capacity, so about as many decisions degraded; what
changed is that the shed ones were answered at once instead of waiting
for a Redis that would not answer in time, which brought the median from
about 9 ms to 2.7 ms. The adaptive limit sat between 3 and 6, and the
breaker stayed closed, since Redis kept answering: slow is not down. Both
were back to no degraded decisions the second the slowdown ended.

## Tracing

[Tracing](tracing.md) is off by default, and off it must cost a decision
nothing: every place that would make a span checks for a tracer first. With
it on, the spans cost what they cost. "Before" is commit 3f2967e with
`BenchmarkServeDecide` added; "after" is this branch with tracing off, and
"on" is this branch tracing every request into no exporter, which is the
cost of the spans, the trace in the access log and the exemplars, apart
from sending them. Medians of 8 to 12 interleaved runs of half a second
each, on a quiet machine.

| benchmark | before | after, tracing off | on, every trace sampled |
|---|---|---|---|
| `BenchmarkDecide` | 3.0 µs, 42 allocations | 3.1 µs, 38 | 5.5 µs, 68 |
| `BenchmarkDecideParallel` | 0.79 µs | 0.82 µs | |
| `BenchmarkServeDecide`: the HTTP layer around a decider that answers at once | 8.0 µs, 53 allocations, 10.76 KB | 8.0 µs, 53, 10.77 KB | 10.4 µs, 89, 13.9 KB |
| `BenchmarkServeDecideParallel` | 6.0 µs | 5.8 µs | |

Off, the differences are within the spread between runs, about 3%, and a
build with tracing's checks but without the new
`catraca_store_call_duration_seconds` measured the same as both. That
histogram, which a decision pays for whether tracing is on or not, reads
the clock twice more per decision. On Windows a reading is the performance
counter, about 80 ns through a system call; each reading also allocated
twice, a cost the decision had paid since `monotime` was added, and the
branch reads it without allocating, which is why a decision makes 38
allocations again instead of 42. On Linux the clock is read without a
system call. The HTTP layer keeps one more pointer per request, the 16
bytes above.

Tracing adds 0.9 MB to the Linux binary (`-trimpath -ldflags="-s -w"`,
25.7 to 26.6 MB), with an OTLP exporter of Catraca's own; OpenTelemetry's
own exporter added 12.6 MB, for the gRPC stack it links
([why](tracing.md#otlp-over-http)).

```sh
go test ./internal/engine ./internal/api -run '^$' -bench 'Decide' -benchmem
```

## Caveats

- **One machine.** The load generator, Catraca and Redis share six cores,
  and the round trip includes the generator's own scheduling. On separate
  machines the network adds its round trip, and Catraca and Redis each get
  their own cores.
- **A Windows Redis build.** The msys2 build from redis-windows is not the
  official Linux Redis: it multiplexes with `select` and spends far more per
  argument and per call than Redis on Linux, which makes the argument count
  weigh more here, and it slows down past 63 open connections. Read
  absolute numbers as indicative, and the before and after ratios as the
  result. A three-node cluster on one machine shows the split into calls,
  not a cluster's capacity.
- **Synthetic traffic.** Sends only, one recipient each, from skewed but
  made-up accounts, and every HTTP run starts on an empty database, so most
  counters hold a bucket or two, as in `BenchmarkObserve`.
  `BenchmarkObserveBusy` covers counters with every bucket live, where the
  new layout gains most. Real traffic adds feedback and account events.
- **SQLite audit.** Decisions are written to SQLite in the background. With
  heavier load or Postgres the recorder may cost more, or drop records,
  which `catraca_records_dropped_total` counts.
- **Interference.** Part of this work ran while another program used about
  five of the twelve threads. Those runs served only for comparisons made
  alongside each other and are not in these tables, except the block-key
  pipeline row.
