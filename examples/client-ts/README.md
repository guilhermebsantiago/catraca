# TypeScript client

A small client for the Catraca HTTP API, with no runtime dependencies. It
uses only web-standard APIs (`fetch`, `AbortSignal.timeout` and
`AbortSignal.any`), so it should work on any runtime that has them; it is
tested on Node 24. It is an example to copy into your project (the `src/`
directory), not a published package.

The types in [`src/types.ts`](src/types.ts) mirror the JSON of Catraca's Go
types field for field: a field that is `omitempty` in Go is optional here.
Times are RFC 3339 strings, and `retry_after` is in whole seconds;
`retryAfterSeconds` returns it (at least 1) for a `Retry-After` header.

```ts
import { Catraca, reasons, retryAfterSeconds } from "./catraca/index.ts";

const catraca = new Catraca({
  baseUrl: "http://catraca.internal:8080",
  token: process.env.CATRACA_TOKEN!,
  timeoutMs: 250,
  failOpen: true,
});

const decision = await catraca.decide({
  type: "send",
  account_id: "acct_42",
  api_key_id: "key_1",
  ip: "203.0.113.7",
  from: "hello@shop.example",
  to: ["ana@mail.example"],
  subject: "Your receipt",
  links: ["https://shop.example/r/1"],
});

switch (decision.action) {
  case "allow":
  case "flag":
    // send it; for flag, also log decision.id for review
    break;
  case "throttle":
    // answer 429 with Retry-After: retryAfterSeconds(decision)
    break;
  case "hold":
    // queue it until a person reviews it
    break;
  case "block":
    // refuse it, citing reasons(decision)
    break;
}
```

## Methods

| method | route | returns |
|---|---|---|
| `decide(event)` | `POST /v1/decide` | the decision, for a send, synchronously |
| `record(event)` | `POST /v1/events` | the decision for feedback or account activity |
| `getDecision(id)` | `GET /v1/decisions/{id}` | the decision, its stored event and its labels, or `null` |
| `label(id, label)` | `POST /v1/decisions/{id}/labels` | the decision with all its labels |

Every method takes an optional `{ signal, timeoutMs }`. The timeout defaults
to 1000 ms; on the send path, set it to what a send can afford to wait.

## Failing open

With `failOpen: true`, `decide` and `record` never throw because Catraca is
unavailable. When Catraca cannot be reached, times out, answers with a 5xx,
or answers with something that is not a decision, they return

```json
{ "id": "", "action": "allow", "ruleset_version": "", "latency_us": 0,
  "time": "...", "fail_open": { "kind": "timeout", "message": "..." } }
```

so the platform keeps sending. `fail_open` is set only by the client, never
by Catraca; log it and alert on it, because while it lasts nothing is being
checked. Errors that mean the request is wrong, such as an invalid event
(400) or a bad token (401), still throw a `CatracaError`: failing open on
those would turn detection off without anyone noticing. A request canceled
through your own `signal` throws its abort reason.

`label` and `getDecision` never fail open: they are not on the send path.

## Develop

```sh
npm ci
npm run typecheck
npm test
```

The tests run against a mock Catraca on a loopback port; they need no
network and no Catraca. Node runs the TypeScript directly, so there is no
build step.
