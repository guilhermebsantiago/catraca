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
    when: event.type == "send" && key.leaked
    action: block
    mode: enforce
    on_error: closed
    reason: API key was found in public and must be rotated
```

## How a batch is handled

```
GitHub ──POST batch──▶ Catraca: verify signature ──▶ 202 (or 200 + feedback)
                                     │
                         bounded worker pool, per token:
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
2. **Accept.** The body is a JSON array of matches (`token`, `type`, `url`,
   `source`). GitHub asks that endpoints handle large batches without timing
   out, so Catraca queues the tokens and answers at once. Tokens are
   processed by `Workers` goroutines (8 by default). When more than
   `MaxPending` tokens (10000) are already waiting, a new batch gets 503 with
   `Retry-After`; a batch that arrives while nothing is pending is always
   accepted, however large, so an oversized batch is never refused forever.
   The body limit is 10 MiB by default.
3. **Resolve.** Each token goes to the Resolver. Transient errors are
   retried three times with backoff; each call is bounded by
   `ResolveTimeout` (10 s).
4. **Decide.** A token that resolves to a key becomes a `key_leak` event:

   ```json
   {
     "type": "key_leak",
     "time": "2026-10-15T12:00:00Z",
     "account_id": "acct_456",
     "api_key_id": "key_123",
     "leak": {"source": "github:commit", "url": "https://github.com/octo/repo/blob/1a2b3c/.env"},
     "attributes": {"secret_type": "acme_api_key"}
   }
   ```

   `leak.source` is `github:` followed by GitHub's `source` (`content`,
   `commit`, `npm`, `action_logs`, ...). The token itself is not part of
   the event.

On shutdown, the server stops accepting batches and waits for accepted
tokens to finish (`Handler.Shutdown`).

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
whose resolution failed are left out.

GitHub waits 30 seconds for partners that send feedback, so with
`Feedback: true` Catraca waits up to `FeedbackTimeout` (20 seconds) for the
batch's tokens, answers `200` with the labels it has, and lets the rest
finish in the background. Without feedback, Catraca answers `202` with an
empty array before resolving anything. Enable feedback only after GitHub has
enabled it for your partnership.

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
5. Optionally ask GitHub to enable **feedback**, then set `Feedback: true`.

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
| anything else | an error: retried, then logged |

Redirects are not followed. A key that was already deleted should be
answered with 404 unless the platform wants a decision recorded for it.

`token_sha256` is the lowercase hex SHA-256 of the token's UTF-8 bytes. The
raw token is added as `"token"` only when `SendRawToken` is set, for a
platform that cannot look keys up by hash; use it only over HTTPS.

The platform must verify `Catraca-Signature` before answering: `t` is the
Unix time in seconds and `v1` the hex HMAC-SHA256 of `<t>.<raw body>` with
the shared secret, the same scheme as Catraca's outgoing webhooks (see
[Hooks](hooks.md#verifying-the-signature) for the steps and a Node.js
version). Reject a timestamp more than a few minutes old. A platform in Go
uses the public [`signature`](../signature) package:

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
	Feedback:    true,
	GitHubToken: os.Getenv("GITHUB_TOKEN"),
})
defer h.Shutdown(ctx)
```

Any type with a `Resolve(ctx, secretscan.Token) (secretscan.Key, error)`
method can replace the HTTP resolver, for example one that queries the
platform's database directly. It returns `secretscan.ErrNotFound` for
tokens that are not keys.

## Privacy of tokens

A reported token is a live credential until it is revoked, so Catraca keeps
it out of every place it could linger:

- The raw token lives only in memory, while its batch is processed.
- It is never logged: `secretscan.Token` leaves the raw value out of its
  `String`, `GoString` and `slog` representations, and logs carry only the
  token type, source and URL.
- It is not part of the `key_leak` event, so it never reaches the audit
  log, rules or webhooks: those see the API key id and account.
- The resolver gets the SHA-256 unless `SendRawToken` is set.
- Feedback to GitHub uses `token_hash`, never `token_raw`.

The `url` GitHub sends is public by definition and is kept in the event,
so a reviewer can see where the key was exposed.

## Metrics

`OnOutcome` reports, per batch, `accepted`, `invalid_signature`,
`keys_unavailable`, `malformed`, `too_large` or `overloaded`, and, per
token, `leaked`, `not_found`, `resolve_failed` or `decide_failed`. Alert on
`resolve_failed` and `decide_failed`: each one is a leaked key that may not
have been acted on.

[partner]: https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program
