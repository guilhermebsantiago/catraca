# Compatibility

What a platform, an operator or a tool can rely on across Catraca releases,
and what may still change before 1.0.

Releases are numbered by [Semantic Versioning](https://semver.org). Before
1.0, a minor release (0.2.0 after 0.1.x) may break something below that
is marked as able to change; a patch release (0.1.1) never breaks anything
it lists. Every break is listed under **Changed** or **Removed** in
[CHANGELOG.md](../CHANGELOG.md), with what to do about it, and `catraca
config check` and `catraca rules check` catch the breaks that are in files.
[upgrading.md](upgrading.md) says how to move a running deployment to a
new release: migrations, rolling upgrades, downgrades and Redis keys.

## Stable

These are the contracts integrations are built on. Before 1.0 they change
only by adding to them; removing or renaming anything in them waits for 1.0
or a new version of the format, and the old one keeps working for at least
one minor release alongside it.

| surface | reference | what stays |
|---|---|---|
| Event JSON | [api.md](api.md#post-v1decide) | the fields of an event, their types and meaning, and the validation rules a valid event passes |
| Decision JSON | [api.md](api.md#post-v1decide), [audit](api.md#get-v1decisionsid) | the fields of a decision and of a stored entry, the five actions and what each asks of the platform; `retry_after` in whole seconds |
| Error codes | [api.md](api.md#conventions) | the HTTP status and `code` of each error; `message` is for people and may change |
| Ruleset format | [rules.md](rules.md) | `version: 1` files keep loading and mean the same; the signals of [signals.md](signals.md) keep their names, types and meaning |
| Hook payload | [hooks.md](hooks.md#the-request) | the JSON fields, the `Catraca-Idempotency-Key` and `Catraca-Attempt` headers, and that any `2xx` means done |
| Signature scheme | [hooks.md](hooks.md#verifying-the-signature) | `Catraca-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>` over `t + "." + body`, for hooks, the resolver and the generic feedback endpoint; the exported API of the Go package [`signature`](../signature) |
| Exit codes | [cli.md](cli.md#exit-codes) | what 0, 1, 2 and 3 mean |

Additions to watch for:

- **New fields** may appear in decisions, stored entries, hook payloads and
  `GET /v1/rules`. Ignore fields you do not know; the TypeScript client
  does.
- **Request bodies are strict.** Catraca refuses an event with a field it
  does not know (`400 invalid_json`), so a field added in a later release
  is refused by an earlier one. Upgrade Catraca before the platform starts
  sending it.
- **New signals and functions** may be added to the rule environment. On
  an earlier release, a ruleset that calls a new function does not load,
  and a rule that reads a new signal finds it absent and follows its
  `on_error`; `catraca rules check` warns about the signal there.
- **A new signature version** would be added as another value next to
  `v1`, as a rotation adds a second `v1`, so receivers that check `v1`
  keep working.

## May change before 1.0

These are listed in the changelog when they change, but may be renamed or
reshaped in a minor release.

| surface | reference | notes |
|---|---|---|
| Configuration keys | [config.md](config.md) | a key may be renamed, moved or given another default. Unknown keys are errors, so `catraca config check` names a key that no longer exists |
| Metric names and labels | [api.md](api.md#get-metrics) | a rename moves the [recording rules, alerts](../deploy/prometheus) and [dashboard](../deploy/grafana) in the same release; dashboards and alerts of your own need the same change |
| Command line | [cli.md](cli.md) | commands and flags may be renamed. The output of `config check`, `report`, `outbox` and `secretscan` is for people: do not parse it |
| Ruleset version | [rules.md](rules.md#versioning) | the hash of an unchanged file may change when the canonical form gains a field, so compare versions within one release only |
| Log fields | [api.md](api.md#logs) | field names and messages of the JSON log |
| Routes not listed above | [api.md](api.md) | query parameters and the bodies of `GET /v1/decisions` (whose cursor is opaque), `GET /v1/rules/{id}/review`, `GET /v1/stats/rules`, `POST /v1/rules/reload` and `/readyz?verbose` |

## Not a public interface

- **The audit database schema.** Catraca migrates it forward when it
  opens it, and an older binary refuses a newer schema
  ([audit](audit.md#choosing-a-database), [downgrades](upgrading.md#downgrades)). Ad-hoc SQL against it works,
  but its tables and columns may change in any minor release.
- **The store's keys** in Redis, and what they hold. A release that
  changes them says whether counters start over.
- **Go packages under `internal/`.** Only [`signature`](../signature) is
  meant to be imported.
- **The examples**, including the [TypeScript client](../examples/client-ts),
  are code to copy, not packages: a release may change them, and your copy
  keeps working against the API above.
