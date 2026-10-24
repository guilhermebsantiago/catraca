# Rotating secrets

Every token and shared secret Catraca uses can be replaced without a moment
where one side refuses the other's valid requests. Next to its current
value, each takes the values being rotated out:

| secret | configuration | who signs or sends it | who checks it | what Catraca does with the previous values |
|---|---|---|---|---|
| API tokens | `auth.tokens[].token`, `previous_tokens` | the platform's clients | Catraca | accepts them as the same client |
| webhook secrets | `hooks[].secret`, `previous_secrets` | Catraca | the platform's receivers | signs each request with every secret |
| resolver secret | `secret_scanning.github.resolver.secret`, `previous_secrets` | Catraca | the platform's resolver | signs with every secret, and opens raw tokens sealed with any |
| generic feedback secret | `feedback.generic.secret`, `previous_secrets` | the platform | Catraca | accepts a request signed with any |
| useSend secret | `feedback.usesend.secret`, `previous_secrets` | useSend | Catraca | accepts a call signed with any |

The rule behind every runbook below: **the side that can hold two secrets
moves first.** Catraca holds both while the other side switches, and when
Catraca signs, it signs with both, so the other side may switch whenever it
is ready.

## Before you start

- Generate each new secret with `openssl rand -hex 32` and keep it where
  the old one is, in a secret store or an environment variable.
- Catraca reads its configuration when it starts. Each step that changes
  it is a rollout: a restart of every instance, or a redeploy with the new
  environment. A step is done when **every** instance runs it
  (`kubectl rollout status` in Kubernetes); until then some instances still
  have the old configuration, and the runbooks account for that.
- `previous_secrets` and `previous_tokens` may not hold an empty value, a
  repeat of the current one or a duplicate; `catraca config check` reports
  them. An optional variable left unset, `${OLD_SECRET:-}`, is empty, so
  remove the line at the end of a rotation instead.
- The image's own configuration, `deploy/catraca.yaml`, has no previous
  values: to rotate without a gap, mount a configuration of your own.
- After a leak, run the steps back to back: the old secret works until the
  last step removes it.

## API tokens

Clients send a token; Catraca checks it.

1. Set the new token as `token` and move the old one to
   `previous_tokens`, then roll out:

   ```yaml
   auth:
     tokens:
       - name: platform
         token: ${CATRACA_API_TOKEN}            # new
         previous_tokens: ["${CATRACA_API_TOKEN_OLD}"]
   ```

   Both tokens authenticate the client, under the same name in the access
   logs.
2. Move the client to the new token. Requests that still use the old one
   are logged with `"previous_token": true`.
3. Once no request has been logged with `previous_token` for a while,
   remove `previous_tokens` and roll out.

Giving the client a second entry with a new name, adding it, moving the
client and removing the old entry, works too; `previous_tokens` keeps the
client's name in logs across the rotation.

## Webhook secrets

Catraca signs each [webhook](hooks.md) request; the platform's receiver
verifies the signature.

1. Set the new secret as the hook's `secret` and move the old one to
   `previous_secrets`, then roll out:

   ```yaml
   hooks:
     - name: revoke_key
       url: https://platform.internal/hooks/catraca/revoke-key
       secret: ${CATRACA_HOOK_SECRET}         # new
       previous_secrets: ["${CATRACA_HOOK_SECRET_OLD}"]
   ```

   Each request now carries a `v1` signature for each secret:
   `Catraca-Signature: t=1760529600,v1=<new>,v1=<old>`. A receiver that
   still verifies with the old secret accepts it, and so do the requests of
   instances not restarted yet, which sign with the old secret alone.
2. When the rollout is complete, switch the receiver to the new secret, or
   let it accept both. Every request carries a signature with the new
   secret now, including retries of deliveries queued before the rotation:
   a delivery is signed when it is attempted, not when it is queued.
3. Remove `previous_secrets` and roll out. Requests are signed with the new
   secret alone, so the receiver must have it by now.

**What receivers must do.** Check every `v1` value of the header, not only
the first, and accept the request when one matches; the
[steps](hooks.md#verifying-the-signature) and the Node.js example in the
hooks guide do. In Go, `signature.Verify` does. A receiver that accepts
both secrets during step 2 uses `signature.VerifyAny`:

```go
err := signature.VerifyAny([]string{os.Getenv("CATRACA_HOOK_SECRET"), os.Getenv("CATRACA_HOOK_SECRET_OLD")},
	r.Header.Get(signature.Header), body, 0)
```

A receiver that compares the whole header with a signature it computed, or
reads only the first `v1`, refuses every request from step 1 on; fix it
before rotating.

## Resolver secret

Catraca signs each request to the platform's
[resolver](secret-scanning.md#the-resolver-contract) with this secret, and,
with `send_raw_token`, also derives from it the key that seals the raw
tokens of leaked-key reports waiting in the queue.

1. Set the new secret as `resolver.secret` and move the old one to
   `resolver.previous_secrets`, then roll out. Requests carry a signature
   for each, as webhooks do, and the resolver keeps answering whichever
   secret it verifies with. New reports are sealed with the new secret;
   reports that arrived before are opened with the old one.
2. When the rollout is complete, switch the resolver to the new secret.
3. Remove `previous_secrets` and roll out, but only once no report sealed
   with the old secret can still be tried: with `send_raw_token`, wait at
   least `secret_scanning.github.max_age` (24h by default) after step 1
   finished, and look for dead reports first:

   ```sh
   catraca secretscan list --status dead --audit "$CATRACA_AUDIT_DSN"
   ```

   Requeue the ones worth retrying and let them finish before step 3. A
   report whose token was sealed with a secret Catraca no longer has dies
   with "the stored raw token cannot be decrypted"; it keeps the token's
   SHA-256 and the URL where GitHub found it, to be handled by hand.
   Without `send_raw_token` nothing is sealed, and step 3 can follow step 2
   at once.

## Generic feedback secret

The platform signs each request to `POST /v1/feedback`; Catraca checks it.

1. Set the new secret as `feedback.generic.secret` and move the old one to
   `previous_secrets`, then roll out. Catraca accepts either.
2. Switch the platform to the new secret. A platform with several
   instances may sign with both during its own rollout: in Go,
   `signature.SignAll([]string{newSecret, oldSecret}, time.Now(), body)`.
3. Once every instance of the platform signs with the new secret, remove
   `previous_secrets` and roll out. A request signed with the old secret
   alone is answered `401` from then on, so a rise of
   `catraca_feedback_outcomes_total{provider="generic",outcome="invalid_signature"}`
   means something still signs with it; put the old secret back until it
   is found.

## useSend secret

useSend signs every call to `POST /v1/feedback/usesend` with its webhook's
secret, one at a time, and makes the secret itself, so Catraca cannot hold
the new secret before useSend starts using it. There is a window from the
moment useSend changes the secret until Catraca knows it; calls in it are
answered `401` and useSend retries them, six attempts over about two and a
half minutes, keeping their id, so each counts once when it gets through.
Keep the window inside the retries:

1. Prepare the rollout first, so it can start at once.
2. Change the webhook's secret in useSend.
3. Set the new secret as `feedback.usesend.secret` and move the old one to
   `previous_secrets`, so calls that were signed before the change still
   verify, and roll out.
4. Once `catraca_feedback_outcomes_total{provider="usesend",outcome="invalid_signature"}`
   has stopped rising, remove `previous_secrets` and roll out.

useSend disables a webhook after 30 calls in a row have failed every
attempt; check it in useSend after a rotation that took longer than the
retries. Do not create a second webhook with the new secret to bridge the
window: each webhook sends its own calls, with their own ids, so every
event would count twice.
