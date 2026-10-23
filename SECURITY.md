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
token and belong on an internal network.

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
