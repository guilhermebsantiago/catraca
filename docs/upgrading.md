# Upgrading

How to move a running Catraca to a newer release: what happens to the audit
database, Redis and the ruleset, how to run two releases side by side while
instances roll, and what changed since the public launch on 2026-10-15
that an upgrade from it has to act on. What may change between releases is
in [compatibility.md](compatibility.md); each change is in the
[changelog](../CHANGELOG.md).

## Before you upgrade

- [ ] Read the changelog from your release to the new one, and the
      [changes since the launch](#changes-since-the-launch) below if you
      run the launch release.
- [ ] Run `catraca config check` and `catraca rules check` with the new
      binary on your configuration and ruleset. Unknown keys are errors, so
      a renamed key shows up here, not at start.
- [ ] Set every variable the new configuration names, such as
      `CATRACA_OPS_TOKEN` for the shipped image and compose file.
- [ ] Back up the audit database. A newer schema cannot be undone by
      hand; the backup is the way back.
- [ ] On a large Postgres database, build the new indexes
      `CONCURRENTLY` first ([below](#indexes-on-a-large-postgres-database)).
- [ ] Give an `override` to any enforced rule that must keep enforcing
      while the gate cannot run, or check that its labels pass
      `catraca rules gate`.
- [ ] Upgrade every Catraca instance before the platform sends a new event
      field, and before the ruleset reads a new signal.

## Migrations

The SQL migrations are embedded in the binary, numbered (`0001_init.sql`,
`0002_retention.sql`, ...) and applied when Catraca opens the audit
database at start. Nothing else runs them, and there is no separate
migrate command. SQLite opens before the server starts; Postgres opens in
the background, so the server serves decisions while it does
([audit](audit.md#choosing-a-database)).

Opening the database applies every migration it has not recorded, in
order, in **one transaction**, and records each in `schema_migrations`. If
one fails, the transaction rolls back and the schema is as it was: there
is no half-migrated state to repair. On Postgres the transaction first
takes an advisory lock (`pg_advisory_xact_lock`, held until it commits or
rolls back), so when two instances start at once:

1. The first takes the lock and applies the migrations.
2. The second waits on the lock, without a timeout of its own, until the
   first commits.
3. The second then reads `schema_migrations`, finds every migration
   recorded and applies none.

If the first fails, its transaction rolls back and releases the lock, and
the second tries the same migrations itself. SQLite needs no lock: it
supports one Catraca process, and its transaction holds the write lock.

While an instance waits on the lock or applies a long migration, its
audit database is not open yet:

- decisions are made, and queue for the audit log in `engine.record_queue`
  (4096 by default); past it they are dropped and counted in
  `catraca_records_dropped_total`;
- the routes that read or label decisions answer `503 audit_unavailable`;
- with `gate.on_load: enforce`, the enforced rules the gate would check
  stay in shadow mode, listed as `unavailable`, until the database answers
  ([gate](config.md#gate)). Rules with an `override` enforce at once.

So keep migrations short: on a large Postgres database, build the indexes
beforehand.

### Indexes on a large Postgres database

Migrations 0002, 0003 and 0006 create indexes, each with
`CREATE INDEX IF NOT EXISTS`. Inside the migration transaction a plain
`CREATE INDEX` blocks writes to its table until it is built, and it reads
the whole table. On a large `decisions` table that is minutes during which
no instance, old or new, can record a decision (they queue, then drop, as
above) and the instance migrating holds the advisory lock.

`CREATE INDEX CONCURRENTLY` builds an index without blocking writes, but
cannot run in a transaction, so the migrations cannot use it. Build the
indexes yourself, under the names the migrations use, while the old
release is still running; the migration then finds them and skips them:

```sql
-- 0002_retention
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_decided_at ON decisions (decided_at_us);
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_finished ON outbox (updated_at_us) WHERE status IN ('delivered', 'dead');
-- 0003_outbox_per_hook
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_effect_due ON outbox (effect, next_attempt_at_us, id) WHERE status = 'pending';
-- 0006_decision_queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_account ON decisions (account_id, decided_at_us, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_api_key ON decisions (api_key_id, decided_at_us, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_ip ON decisions ((event_json->>'ip'), decided_at_us, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS decisions_action ON decisions (action, decided_at_us, id);
```

Run them one at a time, outside a transaction (`psql` runs each statement
on its own). A concurrent build that fails leaves an `INVALID` index
behind (`\d decisions` shows it), and `IF NOT EXISTS` would then skip it
for good: drop it and build it again before upgrading. The other
statements of these migrations, such as the column 0003 adds, change no
rows and take moments. On SQLite, or a small table, let the migrations
build the indexes. [audit.md](audit.md#schema) says what each index is for.

## Rolling upgrades

Instances of two releases can share one Postgres and one Redis while you
replace them one by one. What to expect while both run:

- **The schema moves first.** The first new instance migrates the
  database. Old instances keep running against it, since migrations only
  add, but an old instance that restarts finds a schema newer than it
  knows and stops (on Postgres, after starting, once the background open
  fails). Finish the rollout rather than restarting old instances.
- **Redis is shared as is.** Both releases read and write the same keys;
  see [Redis keys](#redis-keys).
- **Features of the new release are partial.** A signal the old release
  does not compute is absent in its decisions, so a rule that reads it
  follows its `on_error` there. An event field the old release does not
  know is refused with `400 invalid_json` by it. An event counted by an old
  instance is not deduplicated by id.
- **Ruleset versions may differ.** The version is a hash of the file's
  canonical form, which a release may extend, so the same file can report
  two versions while both releases run ([versioning](rules.md#versioning)).

The order that keeps every decision meaningful is: build the indexes,
roll out the binary, then roll out the ruleset that uses new signals or
functions, then let the platform send new event fields.

## Downgrades

An older binary refuses a schema newer than it knows:

```
audit: database schema is at version 6, newer than this build of Catraca knows (5)
```

On SQLite it fails at start; on Postgres it starts, then stops when the
background open fails. There is no down migration. To go back:

- **Roll forward** with a fix, if the problem is one a newer build or a
  configuration change solves. This keeps the audit log.
- **Restore the backup** taken before the upgrade, and run the older
  release on it. Decisions, labels and webhook deliveries recorded since
  are lost; export what you need first (`catraca audit export`,
  `catraca decisions`).

Do not delete rows from `schema_migrations` to let an older binary start.
The migrations are not written to run twice (0003 and 0005 add columns
without `IF NOT EXISTS`), so the next upgrade would fail on the objects
they left.

Redis needs nothing on a downgrade: the older release ignores the keys it
does not know, and they expire.

## Redis keys

The store's keys are not a public interface, and a release that changes
them says so and whether counters start over. Since the launch:

- the keys of existing counters, distinct sets and first-seen times are
  unchanged, so no counter starts over;
- events with an `id` add one key per id, kept for `engine.dedupe_ttl`
  (10 minutes by default);
- new signals add keys of their own, such as account states, the recipient
  memory and the 7-day feedback counters. A new signal starts at zero when
  the first new instance counts an event, and is complete once its window
  has passed.

All keys are under `store.redis.prefix` (`catraca:` by default). An
instance pointed at another prefix, or at a new Redis, starts with empty
counters: every account looks new until the windows fill.

## Ruleset format

The ruleset format is still `version: 1`, and every `version: 1` file that
loaded at the launch loads now and means the same. Since the launch the
rule environment gained signals, among them `account.state`, the 7-day
feedback rates, `event.role_recipients`, `event.suppressed_recipients` and
the entity signals ([signals.md](signals.md)), and feedback kinds `trap` and
`blocklist`. A ruleset that reads them on an older release loads with a
lint warning and the rules follow their `on_error`, so ship the binary
first.

## Changes since the launch

Upgrading from the launch release (b326e38) changes these defaults and
requirements. The [changelog](../CHANGELOG.md) has the full list.

**API tokens have scopes.** `auth.tokens[].scopes` limits a token to
`decide`, `read`, `label` and `admin`. A token without `scopes` keeps every
scope, so your own configuration keeps working, and `catraca config check`
warns about it. The shipped configurations now split the send path's
token from an operator's: the image's `/etc/catraca/catraca.yaml`,
`deploy/compose.yaml` and the Helm chart need **`CATRACA_OPS_TOKEN`** set
as well as `CATRACA_API_TOKEN`. An unset variable is a configuration
error, so a container started from the new image without it does not
start. Give tools that read, label or reload the ops token
([config](config.md#auth)).

**The gate runs on load.** `gate.on_load` is new and defaults to
`enforce`: when a ruleset loads, each enforced rule without an `override`
that has not passed the precision gate is held in shadow mode. At start the
server enforces nothing yet, so every such rule is checked, including
rules you enforced on the launch release without enough labels. Before
upgrading, run `catraca rules gate` on your ruleset; give an `override` to
each rule that must keep enforcing, or set `gate.on_load: warn` to let
them enforce as before, each logged with a warning
([gate](config.md#gate)).

**Feedback rates are per recipient.** `bounce_rate_24h`,
`hard_bounce_rate_24h` and `complaint_rate_24h` divide by
`max(recipients_24h, sends_24h, 1)` instead of `max(sends_24h, 1)`. For a
platform that sends `to`, a send to many addresses no longer inflates the
rate, so the values drop for accounts that send to several recipients at
a time. Thresholds tuned on the launch release's rates may now be too
high: backtest them with `catraca replay`
([feedback rates](signals.md#feedback-rates)).

**Audit retention exists, and is off.** `audit.retention` and
`audit.labeled_retention` are unset by default, which keeps everything as
the launch release did. The log holds personal data, so set them
([retention](audit.md#retention)); migration 0002 adds the indexes
retention reads.

**Events are bounded.** An event more than `engine.max_event_age`
(168 hours) old is refused with `400 invalid_event` (a `key_leak` takes
Catraca's clock instead), one more than
`engine.max_future_skew` (5 seconds) ahead takes Catraca's clock, and
events over the [limits](api.md#limits), such as 1,000 recipients, are
refused. A platform that replays old events through `POST /v1/events`
needs to stay within a week.
