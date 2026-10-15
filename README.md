# Catraca

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

> Status: early development. The engine, signals, rules, audit log,
> precision gate, hooks, feedback and secret scanning packages are built and
> tested; the HTTP server and CLI that wire them together are next.

## Docs

- [Design](docs/design.md)
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

## Development

```sh
go test ./...
```

Postgres tests run when `CATRACA_TEST_POSTGRES_URL` is set, and the store's
contract suite also runs against a real Redis when `CATRACA_TEST_REDIS_URL`
is set (for example `redis://localhost:6379/0`). CI runs both.

## License

Apache-2.0
