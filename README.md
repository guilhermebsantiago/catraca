# Catraca

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/lane-dark.gif">
  <img alt="The Catraca rotor deciding a stream of events from the demo: most allowed, one each flagged, throttled, held and blocked, and dashed rings for shadow matches" src="docs/media/lane.gif" width="800">
</picture>

A self-hosted anti-abuse engine for platforms that send email.

Your platform asks Catraca before each send and reports delivery feedback and
account activity. Catraca answers in milliseconds with an action (allow, flag,
throttle, hold or block) and the rules behind it.

- **Rules in CEL**, kept in git, reviewed like code, with fixtures.
- **Shadow mode first.** A rule only enforces after its measured precision
  clears a gate; every reversal is a label.
- **Fails safe.** Each rule declares what happens when it cannot be evaluated.
- **Signals** over sliding windows in Redis or memory: velocity, bounce and
  complaint rates, new IPs, keys used from many places, leaked keys.
- **Traceable.** Audit log, labels, precision per rule, Prometheus metrics,
  signed webhooks for effects such as revoking a key.
- **Integrations:** Amazon SES (via SNS), useSend, and GitHub's secret
  scanning partner program.

> Status: early development. Everything below works and is tested, but the
> API and the configuration may still change before a first release.

## Quick start

```sh
go build -o catraca ./cmd/catraca

cp catraca.example.yaml catraca.yaml
export CATRACA_API_TOKEN=$(openssl rand -hex 32)
export CATRACA_HOOK_SECRET=$(openssl rand -hex 32)
export CATRACA_FEEDBACK_SECRET=$(openssl rand -hex 32)

./catraca config check            # validate the configuration and the ruleset
./catraca serve                   # listens on :8080, audit log in catraca.db
```

Ask before a send:

```sh
curl -s -X POST localhost:8080/v1/decide \
  -H "Authorization: Bearer $CATRACA_API_TOKEN" \
  -d '{"type": "send", "account_id": "acct_42", "api_key_id": "key_1",
       "ip": "203.0.113.7", "from": "hello@shop.example", "to": ["ana@mail.example"]}'
```

```json
{"decision": {"id": "01M50QGN32570CX37SPKGJDZ7A", "action": "allow", "ruleset_version": "098086f42c27", "...": "..."}}
```

The platform acts on `action`. Every rule in the
[starter ruleset](rules/default.yaml) runs in shadow mode except
`leaked-key-send`, so out of the box Catraca records what it would do and
blocks only keys reported leaked.

## Docs

- [Design](docs/design.md)
- [HTTP API](docs/api.md)
- [Configuration](docs/config.md)
- [Command line](docs/cli.md)
- [Signals](docs/signals.md)
- [Writing rules](docs/rules.md)
- [Audit log and the precision gate](docs/audit.md)
- [Hooks](docs/hooks.md)
- [Feedback: SES, useSend](docs/feedback.md)
- [GitHub secret scanning](docs/secret-scanning.md)

## Examples

- [TypeScript client](examples/client-ts): typed, dependency-free, fails open
- [Hono email API](examples/hono) that asks Catraca before each send
- [Synthetic replay dataset](examples/replay) and the default ruleset's
  backtest on it
- [Demo scenario](examples/demo) against a real server, recorded for the
  [launch video](docs/media/catraca.mp4) ([how it is made](media))

## Development

```sh
go test ./...
```

Postgres tests run when `CATRACA_TEST_POSTGRES_URL` is set, and the store's
contract suite also runs against a real Redis when `CATRACA_TEST_REDIS_URL`
is set (for example `redis://localhost:6379/0`). CI runs both.

## License

Apache-2.0
