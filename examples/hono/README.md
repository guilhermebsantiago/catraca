# Hono example

A minimal email API in the shape of a sending platform, built with
[Hono](https://hono.dev) on Node. `POST /emails` authenticates the customer
by API key, asks Catraca about the send with the
[TypeScript client](../client-ts), and does what the decision says:

| action | answer |
|---|---|
| allow | sends, `200 {"id", "status": "sent", "decision_id"}` |
| flag | sends, `200`, and logs a line with the decision and the rules for review |
| throttle | `429` with `Retry-After` and the reasons; nothing is sent |
| hold | queues the email for a person to review, `202 {"status": "queued_for_review"}` |
| block | `403 {"error": "blocked", "reasons": [...]}` |

Sending is fake: `FakeSender` only remembers what it was given, and held
emails wait in an in-memory queue. Replace them with your mail transport and
review tooling.

The client fails open: if Catraca is unreachable, slow (250 ms by default)
or answers with a server error, the email is sent and a warning is logged,
so an outage of Catraca never stops your customers' mail. If Catraca rejects
the request itself, for example because the token is wrong, the API answers
500 and logs the error instead, so a misconfiguration does not silently turn
checks off.

## Run it

You need Node 22.18 or later, which runs TypeScript directly, and a Catraca
server.

```sh
npm ci
CATRACA_URL=http://localhost:8080 CATRACA_TOKEN=your-token npm start
```

| variable | default | |
|---|---|---|
| `CATRACA_URL` | `http://localhost:8080` | where Catraca listens |
| `CATRACA_TOKEN` | (required) | Catraca's bearer token |
| `CATRACA_TIMEOUT_MS` | `250` | how long a send waits for a decision before failing open |
| `PORT` | `3000` | where this API listens |

Then send an email with the demo API key:

```sh
curl -i localhost:3000/emails \
  -H 'Authorization: Bearer demo-key' \
  -H 'Content-Type: application/json' \
  -d '{"from": "hello@shop.example", "to": ["ana@mail.example"],
       "subject": "Your receipt", "text": "See https://shop.example/r/1"}'
```

The event sent to Catraca carries the account and API key behind the demo
key, the sender, recipients, subject, the links found in the body, and the
client's IP, taken from the connection. Behind a proxy, take it from the
header your proxy sets, and only from a proxy you trust: signals such as new
IPs and keys used from many places are only as good as this address.

## Test it

```sh
npm run typecheck
npm test
```

The tests drive the app with `app.request` against a mock Catraca on a
loopback port; they need no network and no Catraca.
