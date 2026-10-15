# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
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

FROM gcr.io/distroless/static-debian12:nonroot
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
