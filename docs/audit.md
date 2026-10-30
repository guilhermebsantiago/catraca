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

### Personal data, and how long to keep it

The audit database holds personal data in both modes. Plan for it as you
would for any other store of your users' data, under the GDPR, the LGPD or
whatever law applies to you:

| data | where | mode |
|---|---|---|
| account ids and API key ids | every decision | both |
| client IP addresses | every decision | both |
| the sender's domain and recipients' domains, the number of recipients | sends | both |
| a hash of the subject, which confirms a guessed subject | sends | both |
| who labeled (`by`, often a reviewer's email), why (free text) and with which token | labels | both |
| sender and recipient addresses, subject, links, platform attributes, the recipient of feedback | sends and feedback, under `full` | `full` only |
| what each hook sends | webhook deliveries in the outbox | both |
| where a leaked key was found | [leak reports](secret-scanning.md#privacy-of-tokens) | both |

**Nothing is deleted by default**, so the database keeps all of it until
you set a [retention](#retention). Set one when you deploy. A reasonable
start is `retention: 2160h` (90 days) for decisions without a label, long
enough to review and to cover the stats windows, and a `labeled_retention`
no longer than your policy allows for evidence, such as one or two years.
With `event_detail: full`, keep `retention` shorter, such as 30 days, and
turn `full` on only for as long as you need it. To erase one person's data
on request, delete their decisions by account id (see [schema](#schema));
labels and matches go with them, webhook deliveries do not.

Exports, listings and backups carry the same data: a file written by
[`catraca audit export`](cli.md#audit-export) holds the stored events, and
[`GET /v1/decisions`](api.md#get-v1decisions) returns them to any token
with the `read` scope.

## How decisions are written

The engine calls `Record` for every decision. Record never blocks and never
fails: it puts the decision in an in-memory buffer (`audit.buffer_size`,
8192 by default) and a background writer inserts the buffer in batches
(`audit.batch_size`, 256 decisions, or every 200 ms, whichever comes
first), one transaction per batch. With
[`audit.sample_allowed`](#sampling-allowed-decisions) below 1, Record
leaves out part of the plain allows before they reach the buffer.

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
and queued; export them as metrics and alert on drops and failures. The
server does ([metrics](api.md#get-metrics)), times each attempt at a batch
(`catraca_audit_write_duration_seconds{result}`: `ok`, `refused` or
`error`), and holds the log to an [objective](slo.md#audit-completeness):
99.9% of decisions written.

A decision can be read and labeled as soon as Record returns: when `Get` or
`Label` does not find a decision and the buffer is not empty, it flushes the
buffer and looks again. `Flush(ctx)` writes everything queued; when ctx ends
first it returns ctx's error, and the decisions stay queued to be written
later. The engine calls Record from a queue of its own, after the decision
is answered, so the server's reads and labels (`GET /v1/decisions/{id}`,
labels, the review queue and the rule stats) first wait for that queue to
hand over the decisions made before them (`Engine.Sync`): a read sent right
after a decision's response finds the decision.

`Close(ctx)` stops accepting decisions and writes everything still queued,
for as long as ctx allows, or 30 seconds when ctx has no deadline. The server
gives it what is left of `server.shutdown_timeout` after the HTTP requests
have drained. When the time runs out, Close aborts the write in flight and
gives up on every decision still queued: they are lost from the log, counted
as failed, and reported in one error line, `closed before every queued
decision was written`, with their number as `unwritten`. The platform
already has their answers; only the audit records are missing. Close then
closes the database and returns an error wrapping ctx's.

## Sampling allowed decisions

Most decisions are plain allows: an `allow` that no rule matched, enforced
or in shadow. They hold nothing to review and nothing for the precision gate
to count, yet each costs a row. `audit.sample_allowed` records only that
share of them:

```yaml
audit:
  sample_allowed: 0.1   # one plain allow in ten; the default 1 records every one
```

A decision is a plain allow, and can be left out, only when all of these
hold; every other decision is always recorded:

- its action is `allow`;
- no rule matched it, enforced or in shadow, so it has no match rows and
  the [rule stats](#rule-stats), the [review queue](#review-queue) and the
  [precision gate](#the-precision-gate) see every match as before;
- no rule failed on it (`errors` is empty);
- it is not `degraded` (nor `uncounted`): every signal was there;
- it is not a `duplicate` of an event that had counted already.

Which plain allows are kept depends only on the decision id: a hash of the
id, compared with the share. Every process keeps the same ones, a lower
share keeps a subset of what a higher one keeps, and `KeepAllow` in
`internal/audit` tells whether a given id would be kept. The ones left out are
counted in `catraca_audit_sampled_out_total`, not as dropped, so they do not
burn the [audit completeness objective](slo.md#audit-completeness), which
then measures the decisions meant to be written. A decision the engine
could not hand over (`catraca_records_dropped_total`) is counted before
sampling, whatever it was.

What changes for a decision left out:

- `GET /v1/decisions/{id}` answers `404 not_found`, as for a decision
  retention deleted, and so does labeling it. A false negative found later,
  abuse that a plain allow let through, can only be labeled when its
  decision was kept; to label one, find a later decision of the same
  account that a rule matched, or lower the sampling while you investigate.
- Counts of decisions read from the log, such as allows per account or
  per day, count about `sample_allowed` times the plain allows: divide the
  plain allows counted by the share to estimate the total. Blocks,
  throttles, reviews, matched and degraded decisions are complete. The
  same goes for any listing or export of decisions with an `action=allow`
  filter.
- The events of the plain allows left out are not in the log, so events
  exported from the log to [`catraca replay`](cli.md#replay) a new rule
  against hold fewer of them, and the rule looks like it would match less
  legitimate traffic than it will. Keep `sample_allowed` at 1 while you
  collect events for a backtest, or take them from your own records.

Use it when the log's size or write rate is the problem: at 2,000
decisions a second and 90% plain allows, `0.1` writes 380 decisions a
second instead of 2,000 ([sizing](#sizing-at-10-volume)).

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

## Listing decisions

An analyst looking into an account, a leaked key or an IP needs its
decisions, not one decision by id. `ListDecisions` returns the decisions
that match a filter, newest first, a page at a time:

```go
page, err := db.ListDecisions(ctx, audit.DecisionFilter{AccountID: "acct_123", Action: decision.Block, Since: since}, 50)
// page.Next, when not empty, continues the list: set it as Cursor.
```

The filter takes an account, an API key, a client IP, an action and a time
window, `Since` inclusive and `Until` exclusive; empty fields match any.
Each item is the decision and its stored event, without labels; `Get`
returns those. The cursor is the time and id of the last decision on the
page, so the next page starts after it even while new decisions are
recorded, and a decision is never listed twice. A page holds at most 1000
decisions. [`GET /v1/decisions`](api.md#get-v1decisions) and
[`catraca decisions`](cli.md#decisions) run the same query.

Each filter reads its own index, in order (migration
`0006_decision_queries.sql`): `decisions (account_id, decided_at_us, id)`,
`(api_key_id, ...)`, `(action, ...)`, and for the IP, which is only in the
stored event, an index on the expression `event_json->>'ip'`. Combined
filters use one of them and check the rest row by row.

## Exporting labeled decisions for a backtest

The labels people give in production are the ground truth a backtest needs.
[`catraca audit export`](cli.md#audit-export) writes the decisions as a
[replay](cli.md#replay) file, oldest first, one line per decision:

```json
{"event": {"id": "evt_1", "type": "send", "time": "2026-10-01T10:00:00Z", "account_id": "acct_123", "from": "@sender.example"}, "label": "abusive"}
```

A replay label says whether the event was abuse, while audit labels say
whether a rule was right. The export reads the labels as the
[rule stats](#rule-stats) do: for each rule that matched, the latest label
that applies to it, whether it names the rule or covers the whole decision,
and for a decision no rule matched, its latest whole-decision label. Then:

| labels that apply | replay label |
|---|---|
| any `true_positive` | `abusive` |
| all `false_positive` | `legit` |
| none | no label: kept, so the replay's counters see the event, or left out with `--labeled-only` |

So a reversal after an earlier true positive makes the event `legit`, and a
decision where one rule was wrong and another right is `abusive`. A
`false_positive` on a decision no rule matched means a reviewer found it
fine: `legit`.

**With `event_detail: minimal` the replay sees less than production did.**
The log does not keep recipients, the subject, links, attributes or the
sender's address, so the export rebuilds each event from what it kept: the
ids, type, time, account, key and IP, the sender as `@` and its domain, and
the feedback kind and bounce type and the account action. Rules that read
`event.to`, `event.recipients`, recipient domains, links, the subject or
attributes, and lists or signals keyed on them, cannot match as they did,
so their recall and precision in the backtest mean little. An account's
creation time and plan are not kept either, so account age falls back to
the first event the replay sees. The export says on stderr how many events
were minimal. To backtest those rules from the log, run with
`event_detail: full` for a while, within what your privacy policy allows
(see [personal data](#personal-data-and-how-long-to-keep-it)). Rules on
accounts, keys, IPs, the sender's domain, event types and feedback kinds
replay closest to how they ran.

The replay's counters only see the exported events. With `--labeled-only`
they miss the unlabeled traffic between the labeled events, so rate and
count rules match less than they did; leave it out for those, as unlabeled
lines feed the counters without being scored. The first events of a file
run on empty counters, and decisions [retention](#retention) deleted are
gone from them too.

The replay needs events in time order and the log is in decision order. An
event whose time is before the one decided before it, as clients' clocks
differ, gets that earlier event's time, and the export counts these on
stderr.

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
ten minutes, and deletes until nothing expired is left, a statement at a
time, oldest first. How much each statement deletes and how long it waits
after it depend on the database:

| | rows per statement (`audit.retention_batch`) | wait after each (`audit.retention_pause`) |
|---|---|---|
| SQLite | 500 | as long as the statement took, at least 10 ms |
| Postgres | 5000 | 10 ms |

On SQLite every write waits for a delete, the decision writer's included,
so statements stay small and working through a backlog takes at most about
half of the database's write time. On Postgres a delete locks only the old
rows it deletes, which nothing else writes, so the writer does not wait for
it, and larger statements with short pauses keep up with a higher volume;
what they still compete for is the disk and the WAL. Processes deleting at
the same time skip each other's rows (`FOR UPDATE SKIP LOCKED`). Set
`retention_pause` higher when retention slows the decision writes
(`catraca_audit_write_duration_seconds` climbing while it runs), and
`retention_batch` lower when its statements outlast what your database
allows one to hold its locks. Deleted rows
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

### Partitioning on Postgres

Past a few hundred million decisions, deleting them row by row costs more
than it should: every deleted row goes through the WAL, and autovacuum then
has to reclaim it. Postgres can instead drop a whole month at once when
`decisions` and `matches` are partitioned by `decided_at_us`. Catraca does
not set this up. What follows is a recipe to adapt, and to rehearse on a
copy of the database first.

What partitioning changes:

- A partitioned table's primary key must include the partition key, so
  `decisions` gets `PRIMARY KEY (id, decided_at_us)` and `matches`
  `PRIMARY KEY (decision_id, rule_id, decided_at_us)`. Decision ids stay
  unique (they are ULIDs), and Catraca's insert, `ON CONFLICT DO NOTHING`,
  still skips a decision written twice: the copy has the same time, so it
  lands in the same partition.
- The foreign key from `matches` becomes `(decision_id, decided_at_us)
  REFERENCES decisions (id, decided_at_us) ON DELETE CASCADE`. `labels`
  has no decision time, so it stays a plain table without its foreign key,
  and the labels of dropped decisions are deleted by hand (below).
- Labeled decisions are kept longer than the others (`labeled_retention`,
  forever by default), so a month is not simply dropped: its labeled
  decisions are copied out first and put back.
- Leave `audit.retention` set, for the outbox and the leaked-key reports,
  and make it longer than the months you keep, so Catraca's own retention
  finds no unlabeled decision old enough to delete. `labeled_retention`
  still deletes labeled decisions row by row; they are few.
- Catraca's migrations are written for the stock schema. Read each
  release's new migrations, and apply them to the partitioned tables
  yourself when they change `decisions` or `matches`.

Create the partitioned tables with the columns and indexes of
`internal/audit/migrations/postgres`, move the rows over and swap the names
while Catraca is stopped, and create each month's partitions ahead of time,
with a cron job or `pg_partman`. Bounds are unix microseconds, UTC:

```sql
CREATE TABLE decisions_2026_07 PARTITION OF decisions
    FOR VALUES FROM (1782864000000000) TO (1785542400000000); -- July 2026
CREATE TABLE matches_2026_07 PARTITION OF matches
    FOR VALUES FROM (1782864000000000) TO (1785542400000000);
```

Then once a month, for the month that has aged out, keep its labeled
decisions and drop the rest, in one transaction:

```sql
BEGIN;
CREATE TEMP TABLE kept_decisions ON COMMIT DROP AS
    SELECT d.* FROM decisions_2026_07 d
    WHERE EXISTS (SELECT 1 FROM labels l WHERE l.decision_id = d.id);
CREATE TEMP TABLE kept_matches ON COMMIT DROP AS
    SELECT m.* FROM matches_2026_07 m
    WHERE EXISTS (SELECT 1 FROM kept_decisions k WHERE k.id = m.decision_id);
ALTER TABLE matches DETACH PARTITION matches_2026_07;
ALTER TABLE decisions DETACH PARTITION decisions_2026_07;
DROP TABLE matches_2026_07, decisions_2026_07;
CREATE TABLE decisions_2026_07 PARTITION OF decisions
    FOR VALUES FROM (1782864000000000) TO (1785542400000000);
CREATE TABLE matches_2026_07 PARTITION OF matches
    FOR VALUES FROM (1782864000000000) TO (1785542400000000);
INSERT INTO decisions SELECT * FROM kept_decisions;
INSERT INTO matches SELECT * FROM kept_matches;
COMMIT;
```

`DETACH PARTITION` locks the parent table, so the decision writer waits
until the transaction commits; copying the few labeled decisions keeps that
short, and the writer's [buffer](#how-decisions-are-written) holds the
decisions meanwhile. When `labeled_retention` deletes labeled decisions, or
you drop a month whole, delete the labels left without a decision:

```sql
DELETE FROM labels l WHERE NOT EXISTS (SELECT 1 FROM decisions d WHERE d.id = l.decision_id);
```

## Sizing at 10× volume

What the log has to absorb at 2,000 decisions a second, from the code's
defaults and the [audit benchmarks](benchmark.md#the-audit-log):

| | default | at 2,000 decisions/s | setting |
|---|---|---|---|
| rows | a decision row per decision, a match row per rule that matched | 2,000 decision rows a second, 173 million a day | `audit.sample_allowed` |
| writer | a transaction per 256 decisions, or every 200 ms | about 8 transactions a second; to keep up, each has to commit in under 128 ms, the time the next batch takes to fill | `audit.batch_size` |
| audit buffer | 8192 decisions | rides out a database stall of about 4 s; a longer one drops decisions | `audit.buffer_size` |
| engine queue | 4096 decisions | holds about 2 s of decisions while the database has not opened yet | `engine.record_queue` |
| retention | 500 rows a statement on SQLite, 5000 on Postgres | has to delete 2,000 decisions a second on average: 1.2 million a run | `audit.retention_batch`, `audit.retention_pause` |

**The buffers.** Once the database is open, a decision goes from the
engine's queue to the audit buffer in about 3 µs (it is encoded to JSON on
the way), so a slow database fills the audit buffer, not the engine's
queue. While the database stalls, the writer retries the batch in hand, up
to three attempts of up to 10 s each, and the buffer fills at the rate
decisions are recorded. Size it as

    buffer_size = decisions recorded a second × the longest stall to ride out

where the decisions recorded are all of them minus the plain allows left
out: `decisions/s × (1 − plain share × (1 − sample_allowed))`. Riding out
a 30 s failover at 2,000 recorded a second takes `buffer_size: 60000`,
about 60 MB, since each waiting decision holds about 1 KB with
`event_detail: minimal`. With `sample_allowed: 0.1` and 90% plain allows,
380 decisions a second are recorded and the default 8192 rides out about
21 s. `engine.record_queue` only matters while the database has not opened
yet, after a start with Postgres unreachable: size it the same way, with
how long the database may take to come up.

**The writer.** On the [benchmark machine](benchmark.md#machine) one writer
puts about 126,000 decisions a second into a SQLite file, sixty times what
2,000 a second needs, and the HTTP runs at 8,000 decisions a second dropped
none. Postgres was not measured; at 2,000 a second a batch of 256 has 128 ms
to commit. Watch `catraca_audit_write_duration_seconds` and
`catraca_audit_queued`: a queue that keeps climbing means the writer is
behind, and raising `batch_size` (fewer, larger transactions) helps more
than a larger buffer, which only buys time.

**Storage.** A plain allow encodes to about 430 bytes of JSON with
`event_detail: minimal` (170 for the decision, 270 for the event); a block
with one enforced and one shadow match, about 700, plus a row per match.
With the other columns, the indexes and each row's overhead, plan on
roughly 1 KB a decision on disk; this is an estimate, not a measurement.
At 2,000 decisions a second that is about 170 GB a day, 15 TB over a 90-day
`retention`. With `sample_allowed: 0.1` and 90% plain allows, 19% of the
decisions are written: about 33 GB a day, 3 TB over 90 days. At this
volume, sample, use Postgres, and consider [partitioning](#partitioning-on-postgres).

**Retention.** It has to delete, on average, as many decisions as are
written. With its defaults on SQLite it deletes about 35,000 decisions a
second, pauses included, and about 74,000 with 5,000 rows a statement, so a
run clears 10 minutes of decisions at 2,000 a second (1.2 million) in about
35 s. Those numbers come from a table that fits in memory; on a table many
times larger than RAM each statement reads from disk and is much slower.
Check that `catraca_audit_retention_deleted_total{table="decisions"}`
rises as fast as `catraca_audit_recorded_total` once the log is a
`retention` old; when it does not, give retention larger batches and
shorter pauses on Postgres, or partition.

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

**Upgrading to decision listing.** Migration `0006_decision_queries.sql`
adds the four indexes [listing decisions](#listing-decisions) reads. Each
covers the whole `decisions` table, so on a large Postgres database build
them beforehand without blocking writes, and the migration skips them:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_account ON decisions (account_id, decided_at_us, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_api_key ON decisions (api_key_id, decided_at_us, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_ip ON decisions ((event_json->>'ip'), decided_at_us, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_action ON decisions (action, decided_at_us, id);
```

They add to the cost of every decision written, about as much as the
indexes already there.

To delete decisions by hand instead of with [retention](#retention), delete
from `decisions`; matches and labels go with them through `ON DELETE
CASCADE`. In the `sqlite3` shell, run `PRAGMA foreign_keys = ON` first.

```sql
DELETE FROM decisions WHERE decided_at_us < 1735689600000000; -- before 2025-01-01
```
