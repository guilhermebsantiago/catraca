# syntax=docker/dockerfile:1

# Base images are pinned by the digest of their multi-arch index, so a build
# pulls exactly what was reviewed; the tag says which release that digest is
# and lets Dependabot propose updates. The golang image sets
# GOTOOLCHAIN=local, so the toolchain line in go.mod does not apply here:
# this tag is what compiles the binary, and should match it.
FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# SQLite is modernc.org/sqlite, pure Go, so the binary needs no cgo and runs
# on a static base image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/catraca ./cmd/catraca \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/catraca /usr/local/bin/catraca
# WORKDIR would create the data directory as root; copy an empty one owned
# by nonroot so SQLite can write there.
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/catraca
COPY --chown=nonroot:nonroot rules/default.yaml /etc/catraca/rules/default.yaml
COPY --chown=nonroot:nonroot deploy/catraca.yaml /etc/catraca/catraca.yaml
WORKDIR /var/lib/catraca
USER nonroot
EXPOSE 8080
ENV CATRACA_CONFIG=/etc/catraca/catraca.yaml
ENTRYPOINT ["catraca"]
CMD ["serve"]
