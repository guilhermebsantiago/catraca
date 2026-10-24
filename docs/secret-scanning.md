# Leaked keys: GitHub secret scanning

GitHub scans public repositories, gists, issues, pull requests,
discussions, wikis, Actions logs and npm packages for secrets. Through the
[secret scanning partner program][partner], a service provider registers
the format of its API keys, and GitHub posts every public match to the
provider's endpoint, usually within seconds of the push.

`POST /v1/secret-scanning/github` is that endpoint. For each reported token
Catraca asks the platform which API key it is, and emits a `key_leak` event
for every key it finds. Rules act on it: `key.leaked` becomes true for every
later event with that key, and an enforced rule can revoke the key through
an effect:

```yaml
rules:
  - id: leaked-key-reported
    description: GitHub found an API key in public
    when: event.type == "key_leak"
    action: block
    mode: enforce
    on_error: closed
    effects: [revoke_key, notify]
    reason: API key was found in public by GitHub secret scanning
  - id: leaked-key-send
    when: event.type == "send" && event.api_key_id != "" && key.leaked
    action: block
    mode: enforce
    # Known leaked keys stay blocked while the store is down; see
    # docs/signals.md.
    on_error: open
    reason: API key was found in public and must be rotated
```

## How a batch is handled

```
GitHub ──POST batch──▶ Catraca: verify signature ──▶ store reports ──▶ 202 (or 200 + feedback)
                                                          │ audit database (leak_reports)
                                        workers, per report, with retries:
                                                          │
                                        Resolver ──▶ platform: which key is this?
                                                          │ found
                                        Decider ──▶ key_leak event ──▶ rules, effects, audit
```

1. **Signature.** GitHub signs the raw body with ECDSA P-256 and SHA-256
   (`ECDSA-NIST-P256V1-SHA256`) and sends `Github-Public-Key-Identifier` and
   `Github-Public-Key-Signature` (base64 DER). Catraca verifies it with the
   key of that identifier from
   `https://api.github.com/meta/public_keys/secret_scanning`. Keys are
   cached for an hour, revalidated with `If-None-Match`, and refetched
   when a batch names an unknown key, at most once a minute, so forged key
   ids cannot make Catraca hammer GitHub's API. If GitHub's API is down,
   cached keys keep working. A batch that fails verification gets 401; a
   batch that cannot be verified because no key could ever be fetched gets
   503.
2. **Store.** The body is a JSON array of matches (`token`, `type`, `url`,
   `source`). Each match becomes a *report* in the `leak_reports` table of
   the [audit database](audit.md), keyed by a hash of the token's SHA-256,
   its type, source and URL, so a match GitHub sends again is stored once.
   Catraca answers only once every report of the batch is stored. When they
   cannot be stored, because the audit database is not open yet (a
   Postgres database that was unreachable at start opens in the
   background), is down, or takes more than 10 seconds, the answer is `503`
   with `Retry-After` and GitHub sends the batch again: a batch Catraca
   acknowledged is never only in memory. GitHub asks that endpoints handle
   large batches without timing out; storing takes one insert per 666
   matches, and nothing waits for the platform. The body limit is 10 MiB.
3. **Resolve.** Workers, 8 per process, claim due reports and ask the
   Resolver which key each token is. Each call is bounded by
   `ResolveTimeout` (10 s), and failures are [retried](#retries-and-dead-reports).
4. **Decide.** A token that resolves to a key becomes a `key_leak` event:

   ```json
   {
     "id": "ghss_6f1c0a5d2e7b4c39a8d0e1f2a3b4c5d6",
     "type": "key_leak",
     "time": "2026-10-15T12:00:00Z",
     "account_id": "acct_456",
     "api_key_id": "key_123",
     "leak": {"source": "github:commit", "url": "https://github.com/octo/repo/blob/1a2b3c/.env"},
     "attributes": {"secret_type": "acme_api_key"}
   }
   ```

   `leak.source` is `github:` followed by GitHub's `source` (`content`,
   `commit`, `npm`, `action_logs`, ...), and `time` is when the report
   arrived. The id is `ghss_` and 32 hex characters of the report's key: the
   same on every attempt, so a report decided twice is recognizable as one.
   The token itself is not part of the event. GitHub's `type` and `source`
   are cut to 256 bytes and `url` to 8 KiB, and NUL bytes are dropped, so
   no report is refused as an invalid event.

### Retries and dead reports

| what happens | the report |
|---|---|
| the Resolver answers not found | is done: a false positive |
| the Resolver fails: an error, a status other than 200 or 404, a timeout | is retried |
| the token resolves, and the `key_leak` event is decided | is done: leaked |
| the decision fails: no ruleset loaded, the store misses `MarkLeaked`'s deadline | is retried, without resolving the token again |
| the engine refuses the event as invalid, such as a key id with control characters from the resolver | is dead at once: it would be refused again |

Retries wait 1 second after the first failure, doubling up to 5 minutes,
each jittered to between half and all of it, so reports that failed
together in an outage are not retried together, and once the platform is
back, reports go through within minutes. A report is given up as *dead*
after `max_attempts` attempts (1000) or `max_age` since it arrived (24h),
whichever comes first; with the defaults the age does. Both are set under
[`secret_scanning.github`](config.md#secret_scanning).

A dead report is a leaked key that may not have been acted on. It is
logged at error level, counted in
`catraca_secret_scanning_reports{status="dead"}`, and kept with its last
error until you fix the cause and requeue it, which starts its attempts
and age afresh:

```sh
catraca secretscan list --status dead --audit "$CATRACA_AUDIT_DSN"
catraca secretscan retry --dead --audit "$CATRACA_AUDIT_DSN"
```

See [`catraca secretscan`](cli.md#secretscan). With
[`audit.retention`](audit.md#retention), done and dead reports are deleted
once they are older than the retention, like finished webhook deliveries;
pending ones never are.

### Restarts and several instances

Workers claim a report with a lease (two `ResolveTimeout`s plus 40
seconds), as webhook deliveries are claimed from the outbox: on Postgres
with `FOR UPDATE SKIP LOCKED`, so instances that share the database never
work on the same report at once. The outcome of an attempt is recorded only
if no later claim has replaced it, so a worker whose lease ran out cannot
overwrite a newer attempt.

On shutdown, Catraca stops claiming reports and waits for the attempts in
flight, within `server.shutdown_timeout`. Reports still pending stay in the
queue: the next start, or another instance, picks them up at once. An
attempt the shutdown cut short, or a crash, is retried when its lease ends.

A report can be decided twice in one narrow case: its decision went
through, recording that failed (the database went away at that moment),
and the lease ran out. Its `key_leak` event then has the same id both
times. Marking a key leaked twice changes nothing, but a `revoke_key`
receiver may be called for each decision, so revoking a key that is
already revoked should do nothing.

### Feedback to GitHub

GitHub collects true and false positive labels from partners that opt in:
the answer to the alert request is a JSON array with one entry per token:

```json
[
  {"token_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "token_type": "acme_api_key", "label": "true_positive"},
  {"token_hash": "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752", "token_type": "acme_api_key", "label": "false_positive"}
]
```

Catraca labels a token `true_positive` when the Resolver finds a key and
`false_positive` when it answers not found, and identifies it by
`token_hash` (the hex SHA-256 of the token), never by `token_raw`. Tokens
that have not resolved are left out.

GitHub's documentation describes feedback only in the answer to the alert
request, with no API to send a label later, so a label has to be known
before Catraca answers. GitHub waits 30 seconds for partners that send
feedback; with `feedback: true` Catraca stores the batch, waits up to
`FeedbackTimeout` (20 seconds) for this process's workers to resolve its
tokens, and answers `200` with the labels it has. The rest finish in the
background, unlabeled. A batch GitHub sends again is labeled from the
reports already processed, at once. Without feedback, Catraca answers `202`
with an empty array as soon as the batch is stored. Enable feedback only
after GitHub has enabled it for your partnership.

## Joining the partner program

The program is for providers whose keys grant access to their own service:
report only token formats that you issue.

1. **Make keys easy to find.** GitHub matches keys with a regular
   expression, so give them a unique prefix, a high-entropy random part and,
   ideally, a checksum, for example `acme_live_` + 32 random base62
   characters + a CRC32 of the rest. A precise format means fewer false
   positives and, with a checksum, matches the platform can reject without
   a database lookup.
2. **Store key hashes.** Keep the SHA-256 of every key so the Resolver can
   look keys up by hash and the raw token never has to leave Catraca.
3. **Deploy the endpoint** at a public HTTPS URL, such as
   `https://catraca.example.com/v1/secret-scanning/github`, and implement
   the resolver endpoint on the platform (below).
4. **Email <secret-scanning@github.com>** to start enrollment, and agree to
   GitHub's partner terms. For each secret type send a human-readable type
   name (it becomes `type` in the batches), the regular expression, a test
   account GitHub can use to generate real examples, and the endpoint URL.
   One URL can serve every type.
5. Optionally ask GitHub to enable **feedback**, then set `feedback: true`.

GitHub's public key endpoint is rate limited for unauthenticated requests.
Set `GitHubToken` to a token with no scopes to raise the limit.

## The resolver contract

Catraca does not know the platform's keys. For each token it calls the
Resolver; `NewHTTPResolver` implements one that POSTs to a platform URL:

```http
POST /internal/catraca/resolve-key HTTP/1.1
Host: platform.internal
Content-Type: application/json
Catraca-Signature: t=1760529600,v1=3c9b1e...7d

{
  "token_sha256": "6a1d5c8e0b6f4c33d2a1f7d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918",
  "type": "acme_api_key",
  "source": "commit",
  "url": "https://github.com/octo/repo/blob/1a2b3c/.env"
}
```

| platform answer | meaning |
|---|---|
| `200 {"api_key_id": "key_123", "account_id": "acct_456"}` | the token is this key; `account_id` may be omitted |
| `404` | not one of the platform's keys: a false positive |
| anything else | an error: [retried](#retries-and-dead-reports) with backoff |

Redirects are not followed. A key that was already deleted should be
answered with 404 unless the platform wants a decision recorded for it.

`token_sha256` is the lowercase hex SHA-256 of the token's UTF-8 bytes. The
raw token is added as `"token"` only when `SendRawToken` is set, for a
platform that cannot look keys up by hash; use it only over HTTPS, and read
what it means for the [queue](#privacy-of-tokens). A report can be resolved
more than once, after a retry or by another instance, so answer the same
token the same way every time.

The platform must verify `Catraca-Signature` before answering: `t` is the
Unix time in seconds and `v1` the hex HMAC-SHA256 of `<t>.<raw body>` with
the shared secret, the same scheme as Catraca's outgoing webhooks (see
[Hooks](hooks.md#verifying-the-signature) for the steps and a Node.js
version). While the secret is rotated, the header has a `v1` for the new
secret and one for each of `previous_secrets`, so check every `v1` value
([rotating secrets](rotation.md#resolver-secret)). Reject a timestamp more
than a few minutes old. A platform in Go uses the public
[`signature`](../signature) package:

```go
import "github.com/guilhermebsantiago/catraca/signature"

func resolveKey(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if err := signature.Verify(os.Getenv("CATRACA_RESOLVER_SECRET"), r.Header.Get(signature.Header), body, 0); err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	// Look the key up by token_sha256 and answer 200 or 404.
}
```

Wiring it up:

```go
resolver, err := secretscan.NewHTTPResolver(secretscan.HTTPResolverConfig{
	URL:    "https://platform.internal/internal/catraca/resolve-key",
	Secret: os.Getenv("CATRACA_RESOLVER_SECRET"),
})
h, err := secretscan.New(secretscan.Config{
	Decider:     engine,
	Resolver:    resolver,
	Reports:     auditDB, // an *audit.DB: the durable queue
	Feedback:    true,
	GitHubToken: os.Getenv("GITHUB_TOKEN"),
})
defer h.Shutdown(ctx)
```

New starts the workers, which resume the reports an earlier run left
pending. Any type with a `Resolve(ctx, secretscan.Token) (secretscan.Key,
error)` method can replace the HTTP resolver, for example one that queries
the platform's database directly. It returns `secretscan.ErrNotFound` for
tokens that are not keys, and gets `Token.Raw` only when
`Config.RawTokenSecret` is set.

## Privacy of tokens

A reported token is a live credential until the platform revokes it, so
Catraca keeps it out of every place it could linger:

- By default the raw token is never stored. The queue keeps its SHA-256,
  which is all the resolver and GitHub's feedback take, and the raw token is
  in memory only while its batch's request is handled.
- With `send_raw_token`, the resolver needs the raw token, and a report may
  wait for the resolver across a restart, so the raw token is stored with
  its report, encrypted: AES-256-GCM, with a key derived (HKDF-SHA256) from
  `secret_scanning.github.resolver.secret` and the report's key as
  additional data. The key is never stored, so the audit database, its
  replicas and backups, and the people and tools that read them, hold no
  usable token. The platform, the one other holder of the secret, receives
  the raw tokens anyway. Encrypting matters because deleting a value does
  not erase it from disk at once: old row versions, the write-ahead log,
  free pages and backups keep it for a while.
- The encrypted token is deleted as soon as the token resolves to a key or
  the report is done. A dead report whose token never resolved keeps it, so
  it can be requeued, until retention deletes the report.
- When `resolver.secret` changes, keep the old one in
  `resolver.previous_secrets`: new tokens are sealed with the new secret,
  and a token sealed with the old one still opens, so the reports waiting
  across the change still resolve. Without it, a stored token can no longer
  be decrypted, and a report that still needs it dies with an error that
  says so. [Rotating secrets](rotation.md#resolver-secret) says how long to
  keep the old one.
- The token is never logged: `secretscan.Token` leaves the raw value out of
  its `String`, `GoString` and `slog` representations, and logs carry only
  the token type, source and URL.
- It is not part of the `key_leak` event, so it never reaches the decision
  log, rules or webhooks: those see the API key id and account.
- The resolver gets the SHA-256 unless `send_raw_token` is set.
- Feedback to GitHub uses `token_hash`, never `token_raw`.

The `url` GitHub sends is public by definition and is kept in the report and
the event, so a reviewer can see where the key was exposed.

## Metrics

`catraca_secret_scanning_outcomes_total{outcome}` counts, per batch,
`accepted`, `unavailable` (the reports could not be stored, answered 503),
`invalid_signature`, `keys_unavailable`, `malformed` or `too_large`, and,
per report, `duplicate` (already stored, not processed again), `leaked`,
`not_found`, `retry` (an attempt failed and will be retried),
`resolve_failed` or `decide_failed` (the report is dead).

From the queue, read when `/metrics` is scraped and the same on every
instance:

| metric | |
|---|---|
| `catraca_secret_scanning_reports{status}` | reports `pending` and `dead` |
| `catraca_secret_scanning_oldest_pending_seconds` | how long ago the oldest pending report arrived; 0 when none is |

Alert on `catraca_secret_scanning_reports{status="dead"}` above 0: each
dead report is a leaked key that may not have been acted on. Alert on
`catraca_secret_scanning_oldest_pending_seconds` above a few minutes,
which means the resolver or the store is failing, and on `retry` and
`unavailable` rising.

## Operating the queue

```sh
export CATRACA_AUDIT_DSN=postgres://...
catraca secretscan list                    # the latest 50 reports
catraca secretscan list --status dead      # the ones given up
catraca secretscan retry 812 813           # requeue these dead reports
catraca secretscan retry --dead            # requeue every dead report
```

A running server picks requeued reports up within two seconds. See
[`catraca secretscan`](cli.md#secretscan).

[partner]: https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program
