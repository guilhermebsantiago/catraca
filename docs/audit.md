# Audit log, labels and the precision gate

Every decision Catraca makes is written to the audit log with the rules
behind it. People label decisions as right or wrong, the log counts those
labels per rule, and the precision gate uses the counts to decide which rules
may enforce. This page covers what is stored, how labels work, the review
queue, the gate and its report, and how to pick a database.

The code is in `internal/audit` (the log, the outbox and the queue of
leaked-key reports) and `internal/precision` (the statistics and the
gate).

## Choosing a database

The audit log runs on SQLite or Postgres. Both use the same schema and the
same queries, and both are tested against the same contract suite.

| | SQLite | Postgres |
|---|---|---|
| DSN | `sqlite:/var/lib/catraca/audit.db` or a plain path | `postgres://user:pass@host:5432/catraca?sslmode=require` |
| Setup | none: the file is created on first start | a database and a user that can create tables |
| Instances | one Catraca process | any number of processes on the same database |
| Good for | a single server, evaluation, small and medium volume | several instances, high volume, querying the log from other tools |

SQLite is the default. It runs in WAL mode, so reads (the API, reports) do not
wait for the writer, and with a busy timeout, so concurrent writes queue
instead of failing. The driver is pure Go, so Catraca still builds without
cgo.

Use Postgres when you run more than one Catraca process. Each process writes
its decisions to the same tables, and the webhook outbox and the leaked-key
reports let several processes work at once without taking the same row
twice (`FOR UPDATE SKIP LOCKED`).

Each process keeps a bounded pool of connections, at most
`audit.max_open_conns` (10 by default; see [configuration](config.md#audit)).
When the database is slow, everything that uses it (the decision writer,
the outbox, the API, health checks) waits for a free connection, each up to
its own deadline, instead of opening more until Postgres refuses
connections for everyone. Keep `max_open_conns` times the number of
processes under Postgres's `max_connections`, with room for other clients.
The pool is exported as the
`go_sql_*{db_name="audit"}` metrics: `go_sql_in_use_connections` at the
maximum and `go_sql_wait_count_total` rising mean callers are queuing for
connections. On SQLite the pool bounds open files and memory; SQLite runs
one write at a time whatever its size. An in-memory SQLite database
(`:memory:`) always has exactly one connection, since closing it would drop
the data.

Opening the database applies migrations automatically. They are embedded in
the binary, numbered (`0001_init.sql`, ...), applied in one transaction and
recorded in a `schema_migrations` table. On Postgres an advisory lock keeps two
processes from migrating at once. A binary refuses to start on a database
whose schema is newer than it knows, so rolling back to an older release
fails loudly instead of misreading the tables.

## What is stored

By default the log keeps a minimal copy of each event: enough to review a
decision and group similar ones, and no message content.

| field | example | note |
|---|---|---|
| `id`, `type`, `time` | `send` | |
| `account_id`, `api_key_id`, `ip` | | as the platform sent them |
| `from_domain` | `sender.example` | the domain of From, not the address |
| `recipients` | `3` | the number of recipients |
| `recipient_domains` | `["gmail.com", "yahoo.com"]` | distinct domains, at most 100 |
| `subject_sha256` | `6f1ed002ab5595ad` | first 16 hex digits of SHA-256 of the subject |
| `feedback_kind`, `bounce_type` | `bounce`, `permanent` | feedback events |
| `account_action` | `signup` | account events |

Not stored in the default mode: the From and recipient addresses, the subject
text, links, platform attributes, the recipient and message id of feedback
events, and the URL where a leaked key was found.

The subject hash lets a reviewer see that two hundred blocked sends shared one
subject without the log keeping it. It is not anonymization: the hash is not
salted, so anyone with the database can confirm a guessed subject. Treat the
audit database as sensitive either way, since it maps accounts, keys and IPs
to decisions.

Set the event mode to `full` to also keep the whole event as the platform sent
it, under `full`. Only do this when your privacy policy allows keeping message
metadata, and consider a shorter [retention](#retention).

The decision itself is kept whole: action, enforced matches and shadow
matches with their reasons, rules that errored, the degraded flag, the
ruleset version and the latency.

## How decisions are written

The engine calls `Record` for every decision. Record never blocks and never
fails: it puts the decision in an in-memory buffer (8192 by default) and a
background writer inserts the buffer in batches (256 decisions or every
200 ms, whichever comes first), one transaction per batch.

When the buffer is full, because the database is slow or down, new decisions
are dropped rather than slowing down every send. Drops are counted and logged
(once per ten seconds, with the count).

When the database refuses a batch because of the values in it, usually one
decision holding something it cannot store (Postgres text cannot hold a NUL
byte), the writer inserts that batch's decisions one at a time: the others
are written, and only a decision refused again is lost. Each one is counted
as rejected and logged with its decision id (`the database refused a
decision`, at most one line a second). A refusal is a Postgres error of
SQLSTATE class 22 (data exception), 23 (integrity constraint) or 54
(program limit), or a SQLite constraint, too-big or type-mismatch error.
Any other failure means the database cannot take writes, because it is
down, locked, full or read-only: the batch is tried three times in all and
then counted as failed.

`RecorderStats` reports decisions recorded, dropped, failed (queued but not
written: the database was down, the shutdown ran out of time, or the
database refused them), rejected (the refused ones, also counted as failed)
and queued; export them as metrics and alert on drops and failures.

A decision can be read and labeled as soon as Record returns: when `Get` or
`Label` does not find a decision and the buffer is not empty, it flushes the
buffer and looks again. `Flush(ctx)` writes everything queued; when ctx ends
first it returns ctx's error, and the decisions stay queued to be written
later.

`Close(ctx)` stops accepting decisions and writes everything still queued,
for as long as ctx allows, or 30 seconds when ctx has no deadline. The server
gives it what is left of `server.shutdown_timeout` after the HTTP requests
have drained. When the time runs out, Close aborts the write in flight and
gives up on every decision still queued: they are lost from the log, counted
as failed, and reported in one error line, `closed before every queued
decision was written`, with their number as `unwritten`. The platform
already has their answers; only the audit records are missing. Close then
closes the database and returns an error wrapping ctx's.

## Labels

A label is a verdict on a decision: `true_positive` (the rule was right: the
event was abuse) or `false_positive` (the rule was wrong). A label records who
gave it (`by`, required), why (`reason`) and when (`time`, defaulting to now).

```json
{ "verdict": "false_positive", "by": "support@platform", "reason": "customer appeal #4411" }
```

A label without `rule_id` is about the event itself, so it applies to every
rule that matched the decision, enforced or shadow. A label with `rule_id`
applies to that rule only, and must name a rule that matched.

**A reversal is a false positive.** When the platform undoes an enforced
decision, such as unblocking a sender after an appeal or releasing a held
email, it should send a `false_positive` label for the decision. That is the
cheapest source of labels, and the most important: every reversal counts
against the rules that caused it. `audit.Reversal(by, reason)` builds this
label.

Labels accumulate; none is ever overwritten, so the log keeps the full
history of who said what. For counting, each match takes the latest label
that applies to it, by label time. So a reviewer can correct an earlier
verdict, a rule-specific label can refine a decision-wide one, and a label
sent late with an older timestamp does not replace a newer one.

A decision that no rule matched can be labeled too, for example a reviewer
marking an allowed send as abuse. It counts for no rule, but it is kept as a
labeled example, which is what a backtest needs to measure what rules miss.

## Review queue

Reversals only label enforced decisions that someone complained about.
Shadow rules and quiet true positives need reviewers. The review queue returns
the most recent unlabeled matches of a rule, newest first, each with its
reason and the stored event:

```go
items, err := db.ReviewQueue(ctx, "new-account-burst", decision.Shadow, 50)
```

An empty rule id or mode matches any. Labeling a match removes it from the
queue. A shadow rule needs at least 30 labels (by default) before it can be
promoted, so reviewing a sample of its matches is how a new rule earns its way
to enforcement.

## Rule stats

`RuleStats(ctx, since)` counts, for each rule and mode, the matches decided
since a time:

| field | meaning |
|---|---|
| `matches` | decisions the rule matched |
| `errored` | matches that happened only because the rule failed closed |
| `labeled` | matches with a label |
| `true_positives`, `false_positives` | how the labels split |

A rule that was promoted during the window appears twice, once per mode.

## The precision gate

A rule's precision is `TP / (TP + FP)` over its labeled matches. Measured on a
few labels it means little: 5 out of 5 is "100%" with almost no evidence. So
the gate uses the lower bound of the Wilson score 95% confidence interval: a
rule passes when Catraca is 95% confident that its precision is at least the
minimum.

```
p = TP / n,  z = 1.96
lower = (p + z²/2n − z·sqrt(p(1−p)/n + z²/4n²)) / (1 + z²/n)
```

The gate has two settings:

| setting | default | |
|---|---|---|
| `min_labeled` | 30 | labeled matches required |
| `min_precision` | 0.9 | required lower bound |

With the defaults the bar is high on purpose, since a false positive is a bug:

| labeled | true positives needed | precision |
|---|---|---|
| 30 | not reachable: 30/30 has a lower bound of 0.886 | |
| 35 | 35 | 100% |
| 50 | 50 | 100% |
| 100 | 96 | 96% |
| 200 | 189 | 94.5% |

Each rule gets one of three statuses:

- `passes`: at least `min_labeled` labels and a lower bound of at least
  `min_precision`.
- `insufficient_labels`: too few labels to tell.
- `below_precision`: enough labels and a lower bound under the minimum, or,
  with fewer labels, an upper bound under the minimum. In that second case
  more labels cannot plausibly save the rule, so a bad enforced rule shows up
  as a retire candidate without waiting for 30 complaints.

The gate adds up a rule's counts across modes: precision is a property of the
rule's condition, and a rule promoted from shadow keeps the labels it earned
there. If you change what a rule means, give it a new id so its history starts
over.

### `catraca rules gate`

Checks every enforced rule of a ruleset against the audit database and fails
(exit 1) when one does not pass and has no `override`. Run it in CI so a rule
cannot be switched to `enforce` without evidence, or without a recorded,
reviewed decision to skip the gate:

```yaml
- id: leaked-key-send
  mode: enforce
  override:
    by: security-team
    reason: Leaked keys must be stopped before labels exist; GitHub confirms each leak
    at: 2026-03-01
```

In code, `precision.Gate.CheckRuleset(rules, stats)` returns the result of
each enforced rule and a `*precision.GateError` listing the failures.

### `catraca report`

Lists every rule's precision with its interval, and the rules worth acting on:

```
Gate: at least 30 labeled matches and a precision lower bound of 0.90 (Wilson 95%)

RULE               MODE     MATCHES  LABELED  TP   FP  PRECISION  95% CI          STATUS
leaked-key-send    enforce  212      61       61   0   1.000      [0.941, 1.000]  passes
new-account-burst  shadow   1840     120      117  3   0.975      [0.929, 0.991]  passes
shortener-links    enforce  950      80       66   14  0.825      [0.727, 0.893]  below_precision (override)
complaint-spike    shadow   33       9        9    0   1.000      [0.701, 1.000]  insufficient_labels

Promote candidates (shadow rules that pass the gate):
  new-account-burst: precision 0.975 [0.929, 0.991] on 120 labeled matches

Retire candidates (enforced rules below the gate):
  shortener-links: precision 0.825 [0.727, 0.893] on 80 labeled matches
```

Promote candidates are shadow rules that pass the gate. Retire candidates are
enforced rules below it, including those kept enforced by an override. The
same report is available as JSON (`precision.Report.WriteJSON`).

## Retention

By default nothing is deleted. Every send adds a decision row, with the
decision and its stored event as JSON, and a row per rule that matched, so
the log grows until the disk is full; the webhook outbox, in the same
database, keeps every delivery. Set `audit.retention` to have Catraca delete
old rows in the background:

```yaml
audit:
  retention: 2160h             # 90 days, for decisions without a label
  # labeled_retention: 17520h  # 2 years; unset keeps labeled decisions forever
```

| rows | deleted |
|---|---|
| decisions without a label, with their matches | decided more than `retention` ago |
| decisions with a label, with their matches and labels | decided more than `labeled_retention` ago; never while it is unset |
| webhook deliveries that were delivered or are dead | finished more than `retention` ago |
| webhook deliveries still pending | never: they have yet to be sent |
| [leaked-key reports](secret-scanning.md) that are done or dead | finished more than `retention` ago |
| leaked-key reports still pending | never: they have yet to be processed |

**Labeled decisions are kept longer** because they are the evidence the
precision gate counts. `catraca rules gate` and `catraca report` read labels
over all time by default, so deleting old labels would quietly change a
rule's measured precision, and drop it under the gate's minimum number of
labels. They are also the examples a backtest needs. Labels come from
reversals and reviews, so they are few next to decisions and cost little to
keep. If your privacy policy caps how long any decision may be kept, set
`labeled_retention` to that cap; it must be at least `retention`.

Once a decision is deleted, `GET /v1/decisions/{id}` and labeling it answer
`404`, and the review queue no longer lists it. Label a decision before it
ages out: a label that arrives while its decision is being deleted is
deleted with it. Rule stats over a window longer than `retention` count
fewer matches, while their labeled matches and true and false positives
stay complete as long as labeled decisions are kept. Keep `retention` at
least as long as the windows you look at (`/v1/stats/rules` defaults to
720h). It cannot be under 24h, so decisions stay long enough to be reviewed.

Each process looks for expired rows a minute after it starts and then every
ten minutes. It deletes at most 500 rows per statement, oldest first, and
after each statement waits at least as long as the statement took, so no
statement holds locks for long and working through a backlog takes at most
about half of the database's write time. That matters most on SQLite, where
the decision writer waits for each delete. On Postgres, processes deleting at
the same time skip each other's rows (`FOR UPDATE SKIP LOCKED`). Deleted rows
are counted in `catraca_audit_retention_deleted_total{table}`, with `table`
`decisions`, `outbox` or `leak_reports`, and logged once per run. A run that fails is logged,
counted in `catraca_audit_retention_errors_total` and tried again on the next
run.

Deleting rows does not shrink the files: both databases reuse the space for
new rows, so the database levels off at about one retention window of data.
To give the space back to the operating system, run `VACUUM` on SQLite (it
blocks writes while it runs) or `pg_repack` or `VACUUM FULL` on Postgres.

**Upgrading.** The release that adds retention also adds two indexes, in
migration `0002_retention.sql`, whether retention is on or not:
`decisions (decided_at_us)` and `outbox (updated_at_us)` over finished
deliveries. Building an index blocks writes to its table until it is built,
which takes a while on a large table, and the migration runs when Catraca
starts. On a large Postgres database, build them beforehand without blocking
writes; the migration then finds them and skips them:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_decided_at ON decisions (decided_at_us);
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_finished ON outbox (updated_at_us) WHERE status IN ('delivered', 'dead');
```

A concurrent build that fails leaves an invalid index behind (`\d decisions`
marks it `INVALID`); drop it and build it again before upgrading.

## Schema

| table | one row per | notes |
|---|---|---|
| `decisions` | decision | the decision and stored event as JSON (`JSONB` on Postgres), plus copies of the account, key, type and action for ad-hoc SQL |
| `matches` | rule that matched a decision | mode, action, reason, and the verdict of the latest label, so stats and the review queue need no join |
| `labels` | label | every label ever given |
| `outbox` | webhook delivery | see [hooks](hooks.md) |
| `leak_reports` | token GitHub secret scanning reported, and where | the token's SHA-256, never the raw token unless the resolver needs it, and then encrypted; see [secret scanning](secret-scanning.md#privacy-of-tokens) |
| `schema_migrations` | applied migration | |

Times are stored as unix microseconds (UTC) in `*_at_us` columns on both
databases, which keeps the queries identical. Each query has an index:
rule stats read a covering index on match time, the review queue a partial
index on unlabeled matches, the outbox and the leak reports a partial index
on pending rows (the outbox one per hook), and retention an index on
decision time and partial indexes on finished deliveries and reports.

**Upgrading to per-hook delivery.** Migration `0003_outbox_per_hook.sql`
adds the column `outbox.requeued_at_us`, set when
[`catraca outbox retry`](cli.md#outbox-retry) requeues a dead delivery, and
the partial index `outbox_effect_due` that each hook claims its deliveries
through. Adding the column does not rewrite the table on either database.
The index covers pending deliveries only, but building it reads the whole
outbox and blocks writes to it meanwhile; on a large Postgres outbox, build
it beforehand without blocking writes, and the migration skips it:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_effect_due ON outbox (effect, next_attempt_at_us, id) WHERE status = 'pending';
```

During a rolling upgrade, processes of the older release that are still
running keep delivering, but one that restarts refuses the newer schema, so
finish the rollout rather than roll back.

To delete decisions by hand instead of with [retention](#retention), delete
from `decisions`; matches and labels go with them through `ON DELETE
CASCADE`. In the `sqlite3` shell, run `PRAGMA foreign_keys = ON` first.

```sql
DELETE FROM decisions WHERE decided_at_us < 1735689600000000; -- before 2025-01-01
```
