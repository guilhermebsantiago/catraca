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
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

- Go 1.26 or later. No cgo: SQLite is pure Go. The `toolchain` line in
  `go.mod` names the Go patch release that CI and releases build with, kept
  at the newest one so the standard library's security fixes ship; with the
  default `GOTOOLCHAIN=auto`, an older Go downloads it.
- Redis and Postgres tests run when `CATRACA_TEST_REDIS_URL`,
  `CATRACA_TEST_REDIS_CLUSTER` and `CATRACA_TEST_POSTGRES_URL` are set; CI
  runs them. The fault-injection scenarios of [docs/faults.md](docs/faults.md)
  take minutes and also need `CATRACA_TEST_FAULTS=1`.
- A rule change comes with fixtures in `rules/*.test.yaml`
  (`catraca rules test`), and a starter rule ships in shadow mode.
- A new signal goes in `signal.Specs()`, [docs/signals.md](docs/signals.md)
  and the contract tests of both store backends.
- Keep one store round trip per decision; the latency budget is part of the
  design. Numbers for performance changes go in
  [docs/benchmark.md](docs/benchmark.md).
- Commits explain why, in the imperative.

## CI and dependencies

- [ci.yml](.github/workflows/ci.yml) runs on every pull request, on `main`
  and weekly: gofmt, `go mod tidy`, vet and staticcheck; govulncheck, after
  checking that CI and the Dockerfile build with the `go.mod` toolchain;
  tests on Linux against real Redis and Postgres, and on Windows and macOS;
  the fault-injection scenarios against Redis and Postgres;
  the cross-compile; the Docker compose stack; a GoReleaser snapshot of the
  release, whose image must start and answer a decision; and the TypeScript
  examples.
- [codeql.yml](.github/workflows/codeql.yml) runs CodeQL on the Go code, the
  TypeScript and the workflows; [scorecard.yml](.github/workflows/scorecard.yml)
  runs the OpenSSF Scorecard.
- Actions are pinned by full commit SHA with the version in a comment, jobs
  get `contents: read` unless they need more, and checkouts use
  `persist-credentials: false`. Base images are pinned by digest, with the
  tag kept for Dependabot.
- [Dependabot](.github/dependabot.yml) proposes Go modules, actions, base
  images and npm packages weekly, minor and patch updates grouped. It does
  not move `go.mod`'s toolchain line: when it bumps the `golang` image, run
  `go mod edit -toolchain=go1.26.N` with the same version in that pull
  request (CI fails until they match). A new Go minor release moves the
  `go` directive, the toolchain line and the image together, by hand.

## Releasing

Releases are cut by pushing a tag; [release.yml](.github/workflows/release.yml)
runs [GoReleaser](.goreleaser.yaml) and nothing is built on a laptop.

1. Check that `main` is green, including the release dry run, and that
   `go.mod`'s toolchain is the newest Go patch release.
2. Tag the commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "Catraca v0.1.0"
   git push origin v0.1.0
   ```

   A tag with a suffix, such as `v0.2.0-rc.1`, becomes a pre-release and
   does not move the image's `latest` tag.
3. The workflow builds `catraca` for Linux, macOS and Windows on amd64 and
   arm64 (with CGO off, and the version, commit and date that
   `catraca version` prints set through ldflags), archives
   them with the README, license, example configuration and starter
   ruleset, writes `checksums.txt` and an SPDX SBOM per archive, pushes
   `ghcr.io/guilhermebsantiago/catraca:v0.1.0` and `:latest` for
   linux/amd64 and linux/arm64, signs the image with cosign (keyless), and
   attests the build provenance of the archives, the SBOMs and the image.
4. It leaves a draft release. Read the notes, check the assets, and publish
   it. The image is already on ghcr.io at this point.
5. The first time only: open the package's settings (Packages, catraca,
   Package settings), make it public if it is not, and check that it is
   linked to this repository.
6. Verify what was published, as in [SECURITY.md](SECURITY.md#verifying-a-release).

If the workflow fails on something transient, re-run it: the rerun replaces
its draft. If the cause needs a fix, delete the draft release, fix it on
`main` and tag the next patch version rather than moving a tag whose image
may already be public. To check a change to the release configuration
locally:

```sh
go run github.com/goreleaser/goreleaser/v2@v2.18.3 check
go run github.com/goreleaser/goreleaser/v2@v2.18.3 release --snapshot --clean --skip=docker,sign,sbom
```

GoReleaser 2.18 itself needs Go 1.27.1 or later to build, and the release
build needs Docker and syft for the parts this skips. Keep its version the
same in `.goreleaser.yaml`, `ci.yml` and `release.yml`; Dependabot does not
update it.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
