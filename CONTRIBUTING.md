# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you start

- For a bug, open an issue with what you sent, what Catraca answered and
  what you expected. A failing test is the best report.
- For a new signal, rule or integration, open an issue first so we can agree
  on the shape. [docs/design.md](docs/design.md) explains the principles a
  change has to keep: default to trust, a false positive is a bug, fail safe,
  fast, traceable.

## Working on the code

```sh
go test ./...
gofmt -l .
go vet ./...
```

- Go 1.26 or later. No cgo: SQLite is pure Go.
- Redis and Postgres tests run when `CATRACA_TEST_REDIS_URL`,
  `CATRACA_TEST_REDIS_CLUSTER` and `CATRACA_TEST_POSTGRES_URL` are set; CI
  runs them.
- A rule change comes with fixtures in `rules/*.test.yaml`
  (`catraca rules test`), and a starter rule ships in shadow mode.
- A new signal goes in `signal.Specs()`, [docs/signals.md](docs/signals.md)
  and the contract tests of both store backends.
- Keep one store round trip per decision; the latency budget is part of the
  design. Numbers for performance changes go in
  [docs/benchmark.md](docs/benchmark.md).
- Commits explain why, in the imperative.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
