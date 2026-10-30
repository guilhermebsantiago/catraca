# Catraca Helm chart

Runs [Catraca](https://github.com/guilhermebsantiago/catraca), the
self-hosted anti-abuse engine for platforms that send email, on Kubernetes.
[docs/kubernetes.md](../../../docs/kubernetes.md) explains the choices behind
it; [`values.yaml`](values.yaml) documents every value.

## Install

No release image is published yet. Build one from the repository's
`Dockerfile` and push it where the cluster can pull it; once releases
exist, the default `ghcr.io/guilhermebsantiago/catraca:v<appVersion>`
works as is.

```sh
# The tokens and secrets: the chart never renders them.
kubectl create secret generic catraca \
  --from-literal=api-token="$(openssl rand -hex 32)" \
  --from-literal=ops-token="$(openssl rand -hex 32)" \
  --from-literal=feedback-secret="$(openssl rand -hex 32)"

helm install catraca deploy/helm/catraca \
  --set image.repository=registry.example.com/catraca \
  --set image.tag=v0.1.0
```

That runs one pod, counters in memory and the audit log in SQLite on an
`emptyDir`. For production, with Redis, Postgres and several pods, start
from [`ci/production-values.yaml`](ci/production-values.yaml) and add
`audit-dsn` and `redis-url` to the Secret.

## What it renders

| object | when | |
|---|---|---|
| Deployment | always | `catraca serve`, nonroot, read-only root filesystem, probes on the admin port, 40s to drain and stop |
| ConfigMap `<release>` | always | `catraca.yaml`, from `config`; a change rolls the pods |
| ConfigMap `<release>-rules` | unless `rules.existingConfigMap` | the ruleset, mounted as a directory; each pod reloads it in place |
| Service `<release>` | always | the API's port only |
| Service `<release>-admin` | `adminService.enabled` or `serviceMonitor.enabled` | the admin port: `/healthz`, `/readyz`, `/metrics` |
| ServiceAccount | `serviceAccount.create` | its token is not mounted |
| PodDisruptionBudget | more than one replica | one pod down at a time |
| HorizontalPodAutoscaler | `autoscaling.enabled` | on CPU |
| ServiceMonitor | `serviceMonitor.enabled` | Prometheus Operator |
| PrometheusRule | `prometheusRule.enabled` | `deploy/prometheus/rules.yaml` |
| NetworkPolicy | `networkPolicy.enabled` | ingress to the API and admin ports |

No Secret, no Ingress and no PersistentVolumeClaim: bring your own.

## Main values

| value | default | |
|---|---|---|
| `image.repository` | `ghcr.io/guilhermebsantiago/catraca` | |
| `image.tag` | `v` + `appVersion` | |
| `image.digest` | | pins the image; wins over the tag |
| `replicaCount` | `1` | more needs Redis and Postgres, or the chart refuses to render |
| `secret.name` | the release's full name | the existing Secret |
| `secret.env` | `CATRACA_API_TOKEN`, `CATRACA_OPS_TOKEN`, `CATRACA_FEEDBACK_SECRET` | variable: key, required |
| `secret.optionalEnv` | `CATRACA_AUDIT_DSN`, `CATRACA_REDIS_URL` | variable: key, set when the key exists |
| `config` | one instance, memory, SQLite | the configuration file ([docs/config.md](../../../docs/config.md)) |
| `rules.content` | the starter ruleset | the ruleset's YAML |
| `rules.existingConfigMap` | | read the ruleset from your own ConfigMap |
| `ports.http`, `ports.admin` | `8080`, `9090` | `server.listen` and `server.admin_addr` |
| `sqlite.enabled` | `true` | a writable `/var/lib/catraca`; off with Postgres |
| `sqlite.existingClaim` | | a PVC for the SQLite log, with the `Recreate` strategy |
| `terminationGracePeriodSeconds` | `40` | at least `drain_delay` + `shutdown_timeout` |
| `resources` | 100m CPU, 128Mi requested; 256Mi limit | no CPU limit |
| `autoscaling.enabled` | `false` | CPU-based HPA |
| `serviceMonitor.enabled` | `false` | |
| `prometheusRule.enabled` | `false` | |
| `networkPolicy.enabled` | `false` | |

## Develop

```sh
helm lint --strict deploy/helm/catraca
helm lint --strict deploy/helm/catraca -f deploy/helm/catraca/ci/production-values.yaml
helm template catraca deploy/helm/catraca -f deploy/helm/catraca/ci/production-values.yaml
```

`files/rules.yaml` and `files/prometheus-rules.yaml` are copies of
`rules/default.yaml` and `deploy/prometheus/rules.yaml`, since a chart
cannot read files outside its directory: copy them again when the
originals change (CI fails until they match). Bump `version` in
`Chart.yaml` with every change to the chart, and `appVersion` with each
Catraca release.
