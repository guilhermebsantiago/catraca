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

Catraca has no tagged release yet; fixes land on `main`.
