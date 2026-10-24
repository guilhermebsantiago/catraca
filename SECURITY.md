# Security

Catraca sits in the send path of email platforms and handles API tokens,
webhook secrets and leaked-key reports, so security reports are welcome and
taken seriously.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/guilhermebsantiago/catraca/security/advisories/new)
for this repository, with the version or commit, a description and, if you
can, steps to reproduce. You should get an answer within a few days.

## Scope

In scope: the server and its endpoints (decide, events, labels, feedback,
secret scanning), signature verification (SNS, useSend, GitHub, the
`Catraca-Signature` scheme), the outgoing hooks, the audit log and the
configuration handling. Deployment choices are out of scope, but the docs
say what to keep private: `/metrics`, `/healthz` and `/readyz` need no
token and belong on an internal network. Set `server.admin_addr` to serve
them on a listener of their own, off the API's port, and expose only the
API's port to clients; without it they share the API's listener and
whatever is in front must keep them private. They show no secrets: metrics
carry rule ids, counts and the build, and `/readyz?verbose` says whether
Redis and the audit database answer, without hostnames or errors, and
which ruleset version runs, from which file path, with the ids of the
rules the precision gate holds back.

Every API token and shared secret can be rotated with an overlap, so a
leaked one can be replaced without refusing valid traffic; see
[rotating secrets](docs/rotation.md).

## Leaked-key reports at rest

Reports from GitHub secret scanning are stored in the audit database before
they are acknowledged, so a restart or an outage cannot lose them. What is
stored is the token's SHA-256, its type, where GitHub found it (a public
URL), the API key and account it resolved to, and the outcome. The raw
token is stored only when `secret_scanning.github.resolver.send_raw_token`
is on, because the resolver then needs it and a report may wait for the
resolver across a restart. It is then encrypted with AES-256-GCM under a
key derived from the resolver's secret, which is never stored (while the
secret is rotated, a token sealed with a previous one still opens), and
deleted as soon as the token resolves or the report is done; a dead report keeps
it until it is requeued or retention deletes the report. A copy of the
audit database, a backup or a read-only user therefore never holds a usable
token; the platform, the other holder of the secret, receives raw tokens in
that mode anyway. Tokens never appear in logs, events, webhooks or
metrics. See [secret scanning](docs/secret-scanning.md#privacy-of-tokens).

## Supported versions

Catraca has no tagged release yet; fixes land on `main`. Once releases
start, fixes go to `main` and ship in a new release of the latest minor
version; before 1.0 older versions get no backports.

Releases build with the newest Go patch release (the `toolchain` line in
`go.mod`). CI runs govulncheck on every change and weekly, so a known
vulnerability in the toolchain or a dependency that the code can reach
fails the build.

## Verifying a release

Each release has `checksums.txt`, an SPDX SBOM per archive and GitHub
build provenance for every file in `checksums.txt`; the image on
`ghcr.io/guilhermebsantiago/catraca` carries an SBOM attestation, build
provenance and a keyless cosign signature, all tied to the release
workflow of this repository. For `v0.1.0`:

```sh
sha256sum --ignore-missing -c checksums.txt
gh attestation verify catraca_0.1.0_linux_amd64.tar.gz --repo guilhermebsantiago/catraca
gh attestation verify oci://ghcr.io/guilhermebsantiago/catraca:v0.1.0 --repo guilhermebsantiago/catraca
cosign verify ghcr.io/guilhermebsantiago/catraca:v0.1.0 \
  --certificate-identity https://github.com/guilhermebsantiago/catraca/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
