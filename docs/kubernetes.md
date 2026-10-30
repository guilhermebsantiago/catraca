# Kubernetes

The Helm chart in [`deploy/helm/catraca`](../deploy/helm/catraca) runs
Catraca on Kubernetes the way the rest of these docs recommend: probes on
the admin port, a drain before shutdown, a ruleset that reloads without a
restart and secrets that never pass through Helm. Its
[README](../deploy/helm/catraca/README.md) lists the values; this page says
why the chart is built the way it is, and what to decide before production.

## Before you install

**The image.** The chart deploys `ghcr.io/guilhermebsantiago/catraca`, tag
`v` plus the chart's `appVersion`, which is how GoReleaser tags a release.
No release is published yet. Until one is, build the image from the
repository's `Dockerfile`, push it to a registry the cluster can pull from,
and set `image.repository` and `image.tag` (or `image.digest`).

**The Secret.** The chart renders no Secret and reads no secret from
`values.yaml`. Create one; by default the chart looks for a Secret named
after the release, with three keys:

```sh
kubectl create secret generic catraca \
  --from-literal=api-token="$(openssl rand -hex 32)" \
  --from-literal=ops-token="$(openssl rand -hex 32)" \
  --from-literal=feedback-secret="$(openssl rand -hex 32)"
```

`api-token` is the send path's token, with the `decide` scope alone, and
`ops-token` the operators' (`decide`, `read`, `label`, `admin`); see
[scopes](api.md#conventions). With Postgres and Redis, add `audit-dsn` and
`redis-url` to the same Secret. `secret.env` and `secret.optionalEnv` map
each environment variable to its key, and the configuration reads them as
`${NAME}` ([environment variables](config.md#how-the-file-is-read)). Keep
the Secret in whatever you already use for secrets (External Secrets,
Sealed Secrets, a vault), not in Git.

**Then install:**

```sh
helm install catraca deploy/helm/catraca \
  --set image.repository=registry.example.com/catraca --set image.tag=v0.1.0
kubectl rollout status deployment/catraca
```

## One pod or several

The defaults run one pod with counters in memory and the audit log in
SQLite on an `emptyDir`: enough to try Catraca, not to depend on it. Each
pod counting on its own would let an account send a multiple of every
limit, so the chart refuses to render more than one replica, or an
autoscaler, until counters are in Redis (`config.store.backend: redis`)
and the audit log in Postgres (`config.audit.dsn`, with `sqlite.enabled:
false`). [`ci/production-values.yaml`](../deploy/helm/catraca/ci/production-values.yaml)
is a complete example: three replicas, Redis and Postgres from the
Secret, the Prometheus Operator's objects and a NetworkPolicy. Mind
`audit.max_open_conns` times the pods against Postgres's `max_connections`.

To keep a single pod's SQLite log across restarts, point
`sqlite.existingClaim` at a PersistentVolumeClaim; the Deployment then
uses the `Recreate` strategy, since a ReadWriteOnce volume attaches to one
pod at a time.

## Configuration and ruleset

`config` in the values is the configuration file, `catraca.yaml`, as a
map: the chart renders it into a ConfigMap and sets `server.listen`,
`server.admin_addr` and `rules.path` itself, so the ports and paths always
match the pod's. The server reads the file at start, so the pod template
carries its checksum and a change rolls the pods. Run
`catraca config check` on a file before you ship it; CI runs it on what the
chart renders.

The ruleset is a ConfigMap of its own, mounted as a directory, not with
`subPath`. The kubelet updates such a mount in place within a minute or two
of a change, and each pod reloads the file within
[`rules.watch_interval`](config.md#rules) of that, with no restart and no
signal. Its checksum is left out of the pod template on purpose: a rollout
for every ruleset change would restart pods for nothing. `/readyz?verbose`
on each pod shows the version it runs. The chart ships the starter ruleset,
`rules/default.yaml`; set `rules.content`, or `rules.existingConfigMap` to
manage the ruleset outside the chart, with GitOps say. A ruleset that
fails to load leaves running pods on the one they have, and new pods not
ready until a fixed one arrives.

## Ports, probes and stopping

The container listens on two ports. `http` (8080) carries the API and is
the only port on the chart's Service. `admin` (9090) carries `/healthz`,
`/readyz` and `/metrics`, which take no token, so they stay off the
Service that clients reach ([config](config.md#server)). An optional second
Service, `<release>-admin`, exposes the admin port inside the cluster for
Prometheus.

The liveness probe is `/healthz`, which answers while the process serves
HTTP. The readiness probe is `/readyz`: ready once a ruleset is loaded and
not while draining. It ignores Redis and Postgres on purpose, since an
outage of either would otherwise take every pod out of the Service at once
while Catraca can still decide ([GET /readyz](api.md#get-healthz-and-get-readyz)).

On SIGTERM the server keeps serving for `server.drain_delay` (5s), reporting
not ready, while kube-proxy and load balancers stop sending to it, then
shuts down within `server.shutdown_timeout` (30s), writing the decisions it
has queued. No `preStop` hook is needed, and the image has no shell for
one. `terminationGracePeriodSeconds` is 40, the sum plus a margin: raise
it with either setting, or the pod is killed before its queued decisions
reach the audit log. Raise `drain_delay` too behind a cloud load balancer
that is slow to deregister.

## Security

The pod runs as the image's `nonroot` user (65532), with a read-only root
filesystem, no privilege escalation, every capability dropped and the
runtime's default seccomp profile. The only writable path is
`/var/lib/catraca`, for SQLite, and only while `sqlite.enabled`; with
Postgres the pod writes nothing to disk. The ServiceAccount's token is not
mounted, since Catraca does not call the Kubernetes API.

`networkPolicy.enabled` restricts ingress: the API port from
`networkPolicy.apiFrom` (anyone when empty), the admin port from
`networkPolicy.adminFrom` (no one but the kubelet's probes when empty, on
most network plugins). Egress stays open, since Redis, Postgres, hooks,
GitHub and an OTLP collector may live anywhere. The chart has no Ingress:
put TLS in front of the API with the ingress or gateway you already run,
and route only `/v1` to it.

## Availability and scaling

With more than one replica the chart adds a PodDisruptionBudget that lets
one pod go at a time, and rolls updates one new pod at a time without
taking any down first. Spread the pods across nodes or zones with
`topologySpreadConstraints`. `autoscaling.enabled` adds a
HorizontalPodAutoscaler on CPU, which needs the requests the chart sets.
The CPU limit is left out, so a burst is not throttled into missed
decision deadlines; set one if your cluster's policy requires it.

## Monitoring

`serviceMonitor.enabled` adds a Prometheus Operator ServiceMonitor that
scrapes `/metrics` on the admin Service, and `prometheusRule.enabled` the
recording and alerting rules of
[`deploy/prometheus/rules.yaml`](../deploy/prometheus/rules.yaml) as a
PrometheusRule ([objectives and alerts](slo.md)). Every rule aggregates by
`job`, one job per Catraca deployment: `serviceMonitor.jobLabel` sets it,
and otherwise it is the admin Service's name. Set the labels your
Prometheus selects by in `serviceMonitor.labels` and
`prometheusRule.labels`. The 30-day objectives need 31 days of retention.
Import [`deploy/grafana/catraca.json`](../deploy/grafana/catraca.json) for
the dashboard.

## Rotating secrets

Rotate a token or a shared secret as [rotating secrets](rotation.md) says,
with the Secret as the place the values live. For the send path's token:
put the new token under `api-token` and the old one under a new key, say
`api-token-old`, then upgrade with

```yaml
secret:
  optionalEnv:
    CATRACA_API_TOKEN_OLD: api-token-old
config:
  auth:
    tokens:
      - name: send-path
        token: ${CATRACA_API_TOKEN}
        previous_tokens: ["${CATRACA_API_TOKEN_OLD}"]
        scopes: [decide]
      - name: ops
        token: ${CATRACA_OPS_TOKEN}
        scopes: [decide, read, label, admin]
```

The changed configuration rolls the pods by itself. Pods read the Secret
only at start, so a change to the Secret alone reaches them on the next
rollout: run `kubectl rollout restart deployment/catraca` after editing
it, and `kubectl rollout status` to see every pod take it.

## What CI checks

The `helm` job in [ci.yml](../.github/workflows/ci.yml) lints the chart and
renders it with the default values and with `ci/production-values.yaml`,
validates the manifests against the Kubernetes and Prometheus Operator
schemas with kubeconform, checks that rendering three replicas without
Redis and Postgres fails, runs `catraca config check` on the rendered
configuration, and checks that the chart's copies of the starter ruleset and
the Prometheus rules match the originals. It does not install the chart in
a cluster.
