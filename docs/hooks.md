# Effect webhooks

An enforced rule can list `effects`: things the platform should do beyond
the decision itself, such as revoking a leaked API key or suspending an
account. Catraca carries out an effect by calling a webhook on the platform.
This page covers when a webhook is called, what it receives, how to verify
it, and how retries and idempotency work.

The code is in `internal/hooks`; the outbox it uses lives in the audit
database (`internal/audit`).

## Configuring hooks

Each hook is named after the effect it carries out:

| field | | |
|---|---|---|
| `Name` | required | the effect, as rules list it: `revoke_key`, `suspend_account`, `notify`, ... |
| `URL` | required | an absolute `http` or `https` URL that receives a POST |
| `Secret` | required | the key for the request signature; generate a long random value per hook |
| `Timeout` | 10s | bound on one attempt |
| `Headers` | | extra request headers, for example `Authorization`; they cannot replace the `Catraca-*` headers |

Dispatcher-wide settings:

| setting | default | |
|---|---|---|
| `MaxAttempts` | 15 | attempts before a delivery is marked dead |
| `MinBackoff`, `MaxBackoff` | 2s, 15m | the retry backoff range |
| `Concurrency` | 4 | deliveries attempted at once |
| `PollInterval` | 2s | how often due retries are looked for |

## When a webhook is called

For each decision, the engine hands the decision to the dispatcher, which
writes one delivery per effect of the **enforced** matches. Effects of shadow
matches never fire: a shadow rule only records what it would have done. An
effect with no configured hook is skipped.

The delivery is written to the `outbox` table in the audit database before
`Dispatch` returns, so it survives a crash or a restart. A background worker
then sends it, normally within milliseconds. If the decision is dispatched
again, nothing new is written: there is at most one delivery per
(decision id, effect).

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
| `Catraca-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256>`; see below |
| `Catraca-Idempotency-Key` | `<decision id>:<effect>`, the same on every attempt |
| `Catraca-Attempt` | the attempt number, from 1 |

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

To rotate a secret, accept both the old and the new secret on the receiver,
switch Catraca to the new one, then drop the old one.

### Go

Code inside the Catraca module can call `hooks.Verify(secret, header, body,
tolerance)`. A receiver in another module cannot import an `internal`
package, so here is the same check with only the standard library:

```go
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// verifyCatraca checks a Catraca-Signature header against the raw body.
func verifyCatraca(secret, header string, body []byte, tolerance time.Duration) error {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return errors.New("malformed Catraca-Signature header")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	match := false
	for _, s := range sigs {
		if got, err := hex.DecodeString(s); err == nil && hmac.Equal(got, want) {
			match = true
		}
	}
	if !match {
		return errors.New("signature does not match")
	}
	if age := time.Since(time.Unix(unix, 0)); age > tolerance || age < -tolerance {
		return errors.New("signature timestamp outside tolerance")
	}
	return nil
}
```

And a handler that uses it:

```go
func revokeKey(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	err = verifyCatraca(os.Getenv("CATRACA_HOOK_SECRET"), r.Header.Get("Catraca-Signature"), body, 5*time.Minute)
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
doubling up to 7.5–15 minutes, and the fifteenth failure, 45 to 90 minutes
after the first, marks the delivery `dead`. The jitter keeps a receiver
coming back from an outage from getting every retry at the same moment. A
`Retry-After` header (seconds or an HTTP date) on the response is honored when
it asks for longer, up to `MaxBackoff`.

Dead deliveries stay in the outbox with the last status code and error. To
list them, and to send one again after fixing the receiver:

```sql
SELECT id, decision_id, effect, attempts, last_status_code, last_error
FROM outbox WHERE status = 'dead' ORDER BY updated_at_us DESC;

UPDATE outbox SET status = 'pending', attempts = 0, next_attempt_at_us = 0 WHERE id = 42;
```

The dispatcher's `Stats` (enqueued, enqueue errors, delivered, retried, dead)
are meant to be exported as metrics; alert on dead deliveries.

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
