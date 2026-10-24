# Effect webhooks

An enforced rule can list `effects`: things the platform should do beyond
the decision itself, such as revoking a leaked API key or suspending an
account. Catraca carries out an effect by calling a webhook on the platform.
This page covers when a webhook is called, how deliveries are sent, what
they carry, how to verify them, and how retries, redrives and idempotency
work.

The code is in `internal/hooks`; the outbox it uses lives in the audit
database (`internal/audit`), and the signature scheme in the public
`signature` package.

## Configuring hooks

Each hook is named after the effect it carries out. In `catraca.yaml` the
fields are `name`, `url`, `secret`, `previous_secrets`, `timeout`,
`headers`, `concurrency`, `max_attempts` and `max_age`
([configuration](config.md#hooks)); in Go, `hooks.Hook`:

| field | | |
|---|---|---|
| `Name` | required | the effect, as rules list it: `revoke_key`, `suspend_account`, `notify`, ... |
| `URL` | required | an absolute `http` or `https` URL that receives a POST |
| `Secret` | required | the key for the request signature; generate a long random value per hook |
| `PreviousSecrets` | | secrets being rotated out; each request is also signed with each of them ([rotation](rotation.md#webhook-secrets)) |
| `Timeout` | 10s | bound on one attempt |
| `Headers` | | extra request headers, for example `Authorization`; they cannot replace the `Catraca-*` headers |
| `Concurrency` | 4 | the hook's deliveries attempted at once, at most `Workers` |
| `MaxAttempts` | 15 | attempts before a delivery is marked dead |
| `MaxAge` | 24h | how long a delivery is tried for, from when it was queued |

Dispatcher-wide settings, in `hooks.Config`:

| setting | default | |
|---|---|---|
| `Workers` | 16 | deliveries attempted at once across every hook (`outbox.workers`) |
| `Concurrency`, `MaxAttempts`, `MaxAge` | 4, 15, 24h | the defaults of the hooks' own |
| `MinBackoff`, `MaxBackoff` | 2s, 15m | the retry backoff range |
| `PollInterval` | 2s | how often due retries are looked for |
| `BacklogInterval` | 15s | how often the backlog is counted and deliveries past their max age are given up |
| `EnqueueTimeout` | 5s | bound on writing a decision's deliveries to the outbox |
| `MaxWrites` | 1024 | outbox writes in flight before new effects are given up at once |

## When a webhook is called

For each decision whose enforced matches have effects, the engine hands the
decision to the dispatcher, which writes one delivery per effect. Effects of
shadow matches never fire: a shadow rule only records what it would have
done. Nor do the effects of a rule that matched only because it fails closed
(`errored` in the decision): while the store is down such a rule matches
every event it covers. An effect with no configured hook is skipped.

The delivery is written to the `outbox` table in the audit database, so it
survives a crash or a restart, and a background worker sends it, normally
within milliseconds. If the decision is dispatched again, nothing new is
written: there is at most one delivery per (decision id, effect).

The decision waits for that write, but only for its dispatch budget,
[`engine.dispatch_timeout`](config.md#engine) (by default the engine
deadline, 10 ms). The write normally takes a millisecond or two, and then
the delivery is durable before the platform has its answer. When the
outbox is slow (SQLite busy with a large write, Postgres failing over or
still opening at start), the decision is answered when the budget runs out
and the write goes on in the background for up to 5 seconds. Holding the
answer longer would turn a slow audit database into slow decisions, and
the decisions with effects are the ones that block abuse; dropping the
write would lose an effect, such as revoking a leaked key, to a hiccup.
Finishing it in the background keeps the effect unless Catraca crashes in
those few seconds or the outbox stays unavailable through them.

Deliveries whose write fails, or that find 1024 writes already in flight,
are lost. Each is counted in `catraca_hooks_enqueue_errors_total` and logged
at error level, with the decision id, the effects, the account and the API
key, so it can be carried out by hand (when writes pile up, the log is
limited to a line a second, which counts the effects lost since the one
before). `catraca_hooks_enqueue_deferred_total` counts the deliveries whose
decision was answered before they were written.

## Delivery

A pool of workers, 16 by default ([`outbox.workers`](config.md#outbox)),
attempts deliveries for every hook, and each hook takes at most its own
`concurrency` of them, 4 by default. A delivery starts as soon as a worker
is free; it never waits for other attempts to end. So a hook whose endpoint
hangs until its timeout, or one with a backlog of thousands, holds at most
its own concurrency of the workers while the others keep delivering. When
more deliveries are due than workers are free, the hook with the fewest
attempts in flight goes first, and hooks equally busy take turns.

Each hook claims its own due deliveries, oldest first. That is the only
order there is: deliveries for different hooks are independent, attempts of
one hook run concurrently and may finish in any order, and a failed attempt
goes back behind newer deliveries until its retry is due. A receiver that
needs an order must restore it, for example from the decision's `time`.

With Postgres, several Catraca processes deliver from the same outbox, each
with its own workers, and never claim the same delivery twice; each hook's
concurrency then applies per process.

A claim, and each count of the backlog, gives up after 10 seconds, and the
next poll tries again. So a query on a connection the network dropped
without a reset, which would otherwise wait until TCP gives up on it, holds
up delivery for 10 seconds rather than a quarter of an hour.

## The request

```http
POST /hooks/catraca/revoke-key HTTP/1.1
Content-Type: application/json
User-Agent: Catraca-Hooks/1
Catraca-Signature: t=1772366400,v1=5d9c1c2f0e0b7a6c3b6e8a0f1d2c4b5a6978e1f2a3b4c5d6e7f8091a2b3c4d5e
Catraca-Idempotency-Key: 01JNQX8R3T0B6M9X1W2V4Y5Z7A:revoke_key
Catraca-Attempt: 1

{
  "effect": "revoke_key",
  "decision_id": "01JNQX8R3T0B6M9X1W2V4Y5Z7A",
  "event_id": "evt_8c1f",
  "event_type": "send",
  "account_id": "acct_42",
  "api_key_id": "key_7d3e",
  "action": "block",
  "rule_ids": ["leaked-key-send"],
  "reasons": ["API key was found in public and must be rotated"],
  "time": "2026-03-01T12:00:00Z"
}
```

| field | |
|---|---|
| `effect` | the effect to carry out |
| `decision_id` | the decision behind it; `GET /v1/decisions/{id}` returns the decision and its rules |
| `event_id`, `event_type` | the event that was decided |
| `account_id`, `api_key_id` | who it is about; `api_key_id` is omitted when the event had none |
| `action` | the decision's action |
| `rule_ids`, `reasons` | the enforced rules that matched and list this effect, and their reasons, in the same order |
| `time` | when the decision was made |

The body is compact JSON (formatted above for reading). It is fixed when the
delivery is written, so every attempt sends the same bytes. Answer with any `2xx` status once the effect is done (or safely
queued on your side). Anything else is a failed attempt.

| header | |
|---|---|
| `Catraca-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256>`, with a `v1` per secret while one is rotated; see below |
| `Catraca-Idempotency-Key` | `<decision id>:<effect>`, the same on every attempt |
| `Catraca-Attempt` | the attempt number, from 1 |
| `traceparent` | with [tracing](tracing.md) on, the W3C trace context of the attempt, so your spans join its trace; each attempt starts a trace of its own |

## Verifying the signature

The signature proves that the request comes from Catraca and was not altered
or replayed. It is an HMAC-SHA256, keyed with the hook's secret, over the
timestamp, a period, and the raw body:

```
v1 = hex(HMAC_SHA256(secret, t + "." + body))
```

To verify a request:

1. Read the raw body before parsing it. Re-serialized JSON will not match.
2. Split the header on `,` into `key=value` pairs. Take `t` and every `v1`;
   ignore other keys, which leaves room for new schemes.
3. Compute the HMAC of `t + "." + body` with your secret and compare it with
   each `v1` in constant time. Accept if one matches.
4. Reject when `t` is more than a few minutes (Catraca uses 5 by default) from
   your clock, so a captured request cannot be replayed later.

While a hook's secret is rotated, Catraca signs each request with the new
secret and with each of the hook's `previous_secrets`, one `v1` value per
secret, so a receiver that knows either accepts it; step 3 is what makes
that work. See [rotating secrets](rotation.md#webhook-secrets) for the
order of the steps.

### Go

The public package
[`github.com/guilhermebsantiago/catraca/signature`](../signature) implements
the scheme, so a receiver in any module can import it:

```go
import "github.com/guilhermebsantiago/catraca/signature"

err := signature.Verify(secret, r.Header.Get(signature.Header), body, 0)
```

`Verify` returns nil, or one of `signature.ErrMalformed` (the header cannot
be parsed), `signature.ErrMismatch` (no `v1` matches: forged, altered, or
signed with another secret), `signature.ErrExpired` (authentic, but the
timestamp is outside the tolerance) and `signature.ErrEmptySecret`. A zero
tolerance means `signature.DefaultTolerance`, five minutes. A receiver that
accepts the old and the new secret during a rotation calls
`signature.VerifyAny([]string{newSecret, oldSecret}, header, body, 0)`.

In a handler:

```go
func revokeKey(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	err = signature.Verify(os.Getenv("CATRACA_HOOK_SECRET"), r.Header.Get(signature.Header), body, 0)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var p struct {
		DecisionID string `json:"decision_id"`
		APIKeyID   string `json:"api_key_id"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	// Revoking twice is harmless here; for effects that are not, check
	// Catraca-Idempotency-Key first (see below).
	if err := keys.Revoke(r.Context(), p.APIKeyID, "catraca decision "+p.DecisionID); err != nil {
		http.Error(w, "try again", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

### Node.js / TypeScript

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyCatraca(
  secret: string,
  header: string | undefined,
  rawBody: Buffer,
  toleranceSeconds = 300,
): boolean {
  if (!header) return false;
  let timestamp = "";
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [key, value] = part.trim().split("=", 2);
    if (key === "t") timestamp = value;
    else if (key === "v1" && value) signatures.push(value);
  }
  const t = Number(timestamp);
  if (!timestamp || !Number.isInteger(t) || signatures.length === 0) return false;
  if (Math.abs(Date.now() / 1000 - t) > toleranceSeconds) return false;

  const expected = createHmac("sha256", secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest();
  return signatures.some((s) => {
    const got = Buffer.from(s, "hex");
    return got.length === expected.length && timingSafeEqual(got, expected);
  });
}
```

With Express, take the raw body for this route instead of the JSON parser:

```ts
app.post("/hooks/catraca/revoke-key", express.raw({ type: "application/json" }), async (req, res) => {
  if (!verifyCatraca(process.env.CATRACA_HOOK_SECRET!, req.header("Catraca-Signature"), req.body)) {
    return res.sendStatus(401);
  }
  const key = req.header("Catraca-Idempotency-Key")!;
  if (await alreadyProcessed(key)) return res.sendStatus(200);

  const payload = JSON.parse(req.body.toString("utf8"));
  await revokeApiKey(payload.api_key_id, `catraca decision ${payload.decision_id}`);
  await markProcessed(key);
  res.sendStatus(204);
});
```

## Retries

A failed attempt is a non-`2xx` response, a network error or a timeout.
Redirects are not followed: a `3xx` is a failure, so a moved endpoint shows up
in the logs instead of silently receiving traffic elsewhere.

After a failure the delivery waits, then is tried again:

```
wait = min(MinBackoff × 2^(attempt − 1), MaxBackoff), with equal jitter: a random value in [wait/2, wait]
```

With the defaults the waits are about 1–2 s, 2–4 s, 4–8 s and so on,
doubling up to 7.5–15 minutes. The jitter keeps a receiver coming back from
an outage from getting every retry at the same moment. A `Retry-After`
header (seconds or an HTTP date) on the response is honored when it asks
for longer, up to `MaxBackoff`.

Each hook bounds its retries two ways, and a delivery is marked `dead` at
whichever limit it reaches first:

- **`max_attempts`** (15 by default): the fifteenth failure, 45 to 90
  minutes after the first with the default backoff, ends the delivery.
- **`max_age`** (24 hours by default), counted from when the delivery was
  queued: an effect that late, such as suspending an account a day after
  the abuse, may no longer be wanted. A failure whose retry would come after
  it ends the delivery at once, its error saying so. A delivery still
  waiting for an attempt when it passes `max_age`, because Catraca was down
  or behind a backlog, is not attempted again: every 15 seconds the
  dispatcher gives such deliveries up, and counts them in
  `catraca_hooks_expired_total` as well as dead.

A delivery for an effect that no configured hook carries out, because the
hook was removed or this process's configuration lacks it, is left pending:
during a rolling deploy another process may have the hook. It is given up
once it is older than 24 hours (the default `max_age`), with an error that
says no hook carries it out, and shows in the backlog metrics meanwhile.

## Redriving dead deliveries

Dead deliveries stay in the outbox with the last status code and error,
until [`audit.retention`](audit.md#retention), when set, deletes them along
with delivered ones, so redrive them before that. Once the receiver is
fixed, list them and requeue them with the [CLI](cli.md#outbox-list),
against the same audit database the server uses:

```sh
catraca outbox list --audit "$CATRACA_AUDIT_DSN" --status dead --hook revoke_key
catraca outbox retry --audit "$CATRACA_AUDIT_DSN" 42 43
catraca outbox retry --audit "$CATRACA_AUDIT_DSN" --dead --hook revoke_key --since 6h
```

A requeued delivery is due at once, so a running server sends it within its
poll interval (2 seconds), with the same body and idempotency key as before.
Its attempts start over from 1, and its `max_age` from the moment it was
requeued, so an old delivery can be redriven too; `catraca outbox list`
shows when it was requeued. The receiver gets the effect again even if an
earlier attempt did it and only the answer was lost, which the idempotency
key makes safe.

## Metrics

| metric | |
|---|---|
| `catraca_hooks_enqueued_total` | deliveries written to the outbox |
| `catraca_hooks_enqueue_errors_total` | deliveries lost because they could not be written, each logged |
| `catraca_hooks_enqueue_deferred_total` | deliveries whose decision was answered before they were written, when the write outlasted `engine.dispatch_timeout` |
| `catraca_hooks_delivered_total` | deliveries answered with a `2xx` |
| `catraca_hooks_retries_total` | failed attempts that will be retried |
| `catraca_hooks_dead_total` | deliveries given up, for any reason |
| `catraca_hooks_expired_total` | deliveries given up without another attempt, past `max_age` or with no hook; also counted as dead |
| `catraca_hooks_attempts_total{hook,outcome}` | attempts of each hook, by what became of the delivery: `delivered`, `retry` or `dead` |
| `catraca_hooks_attempt_duration_seconds{hook}` | histogram: how long each request took, until the answer or the error |
| `catraca_hooks_delivery_latency_seconds{hook}` | histogram: from when a delivery was queued, with its decision, to its `2xx`, retries and backoff included |
| `catraca_hooks_pending{hook}` | deliveries waiting: due, in flight, or waiting out a backoff |
| `catraca_hooks_pending_due{hook}` | of those, the ones already due: waiting for a worker, not for a backoff |
| `catraca_hooks_oldest_pending_age_seconds{hook}` | how long the oldest pending delivery has waited since it was queued |

The `{hook}` gauges have a series for every configured hook, and one for each
effect with pending deliveries and no hook. They are counted every 15
seconds from the outbox, which every process shares, so with several
processes aggregate them with `max`, not `sum`. The counters and histograms
are per process, with a series for every configured hook from the start.

Alert on `catraca_hooks_dead_total` and `catraca_hooks_enqueue_errors_total`
rising, and on `catraca_hooks_oldest_pending_age_seconds` past what an
effect may wait; [`deploy/prometheus/rules.yaml`](../deploy/prometheus/rules.yaml)
does, and holds effects to an [objective](slo.md#webhook-freshness): 99%
delivered within a minute. A `catraca_hooks_pending_due` that stays high
means the workers cannot keep up; a `catraca_hooks_pending` that grows
while `pending_due` stays low means the receiver is failing and deliveries
wait out their backoff, which `catraca_hooks_attempts_total{outcome="retry"}`
shows per hook. `catraca outbox stats` shows the same per hook, with the
dead and delivered counts.

## Idempotency

Deliveries are **at least once**. A request can arrive twice: when your
endpoint did the work but the response was lost, when it answered after
Catraca's timeout, or when a Catraca process stopped mid-attempt (a claimed
delivery is leased for the hook's timeout plus 30 seconds, then retried by
any process).

`Catraca-Idempotency-Key` is `<decision id>:<effect>` and is the same on
every attempt, so make the effect safe to receive twice:

- Some effects already are: revoking a revoked key or suspending a suspended
  account changes nothing.
- For the others, such as sending a notification, store the keys you have
  processed (with a unique constraint) and answer `200` without acting when a
  key comes back. Record the key in the same transaction as the effect when
  you can.

On Catraca's side, the outbox holds one delivery per (decision id, effect),
so dispatching a decision again never creates a second delivery.
