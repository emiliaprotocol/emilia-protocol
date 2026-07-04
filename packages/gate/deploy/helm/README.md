<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Gate — reference Helm chart (`emilia-gate`)

**Contract:** `EP-GATE-HELM-v1` · **Status: reference chart, experimental, BYOC.**

A reference Kubernetes deployment of the [EMILIA Gate](../../README.md) — the
Trusted Action Firewall. Deny-by-default enforcement for consequential machine
actions: an action runs only with a valid, in-scope, sufficiently-assured,
fresh, non-replayed EMILIA authorization receipt. *No receipt, no execution.*

This chart is meant to be **read, reviewed, and adapted** for your cluster
(bring-your-own-cloud). It is not a managed product and there is no official
public image yet — build and push your own image of the gate service.

## What the chart renders

| Template                      | Object          | Notes |
| ----------------------------- | --------------- | ----- |
| `templates/deployment.yaml`   | `Deployment`    | Single-container gate service; env-driven config; hardened pod defaults (non-root, read-only rootfs, all capabilities dropped, no SA token); liveness + readiness probes; manifest-checksum annotation rolls pods on config change. |
| `templates/service.yaml`      | `Service`       | `ClusterIP` by default, port 8080 → container `http`. |
| `templates/configmap.yaml`    | `ConfigMap`     | The `EP-ACTION-RISK-MANIFEST-v0.1` JSON (which actions are guarded, what assurance each requires). Skipped when `manifest.existingConfigMap` is set. |
| `templates/servicemonitor.yaml` | `ServiceMonitor` (stub) | Rendered only when `metrics.enabled=true`; scrapes the gate's `/metrics` endpoint; requires the Prometheus Operator CRDs. |
| `templates/NOTES.txt`         | post-install notes | Rollout/port-forward/rotation crib sheet. |

## Security invariants (fail-closed)

1. **Key material is never rendered.** Issuer public keys arrive via an
   **existing** Kubernetes Secret you create out-of-band; the chart only emits
   a `secretKeyRef`. Rendering **fails** (`required`) if
   `issuerKeys.existingSecret` is unset — a gate with no pinned issuers must
   not deploy.
2. **Strict evidence log by default** (`gate.evidenceStrict=true` →
   `EP_GATE_EVIDENCE_STRICT=true`): the gate refuses to authorize an action it
   cannot durably account for.
3. **Hardened pod defaults**: `runAsNonRoot`, `readOnlyRootFilesystem`,
   `capabilities: drop [ALL]`, `seccompProfile: RuntimeDefault`,
   `automountServiceAccountToken: false`. Loosen deliberately via values, not
   accidentally.

## Quick start

```sh
# 1. Create the pinned-issuer-keys Secret yourself (NEVER in values files).
#    issuer-keys.json = JSON array of base64url SPKI-DER Ed25519 public keys
#    (or a {kid: key} map), i.e. the keys the gate trusts to sign receipts.
kubectl -n emilia create secret generic emilia-gate-issuer-keys \
  --from-file=issuer-keys.json=./issuer-keys.json

# 2. Install the chart, pointing at YOUR image and the existing Secret.
helm install gate ./emilia-gate \
  --namespace emilia --create-namespace \
  --set image.repository=YOUR_REGISTRY/emilia-gate \
  --set image.tag=0.9.0 \
  --set issuerKeys.existingSecret=emilia-gate-issuer-keys

# 3. (Optional) expose /metrics + ServiceMonitor stub (needs Prometheus Operator).
#    --set metrics.enabled=true
```

Omitting `issuerKeys.existingSecret` makes `helm install`/`template` refuse to
render — that is intentional.

## Environment contract (what the container is expected to read)

The chart is env-driven; the gate service image consumes:

| Env var                  | Source                              | Default |
| ------------------------ | ----------------------------------- | ------- |
| `NODE_ENV`               | fixed                               | `production` |
| `EP_GATE_PORT`           | `gate.port`                         | `8080` |
| `EP_GATE_LOG_LEVEL`      | `gate.logLevel`                     | `info` |
| `EP_GATE_EVIDENCE_STRICT`| `gate.evidenceStrict`               | `true` |
| `EP_GATE_MANIFEST_PATH`  | ConfigMap mount                     | `/etc/emilia-gate/action-risk-manifest.json` |
| `EP_GATE_METRICS_ENABLED`| `metrics.enabled`                   | `false` |
| `EP_GATE_ISSUER_KEYS`    | `secretKeyRef` → your existing Secret | — (required) |

Anything else (e.g. a Redis URL for a durable consumption store) goes in
`gate.extraEnv` as verbatim `EnvVar` objects — `valueFrom` your own
Secrets/ConfigMaps there rather than inlining values.

## Key values

| Value | Default | Meaning |
| ----- | ------- | ------- |
| `replicaCount` | `2` | Gate replicas. NOTE: replay defense across replicas needs a shared consumption store (see `createDurableConsumptionStore` in `packages/gate/store.js`); configure the backend via `gate.extraEnv`. |
| `image.repository` / `image.tag` | `ghcr.io/emilia-protocol/gate` / chart `appVersion` | BYOC image. |
| `issuerKeys.existingSecret` | — **required** | Name of your pre-created Secret with pinned issuer keys. |
| `issuerKeys.secretKey` | `issuer-keys.json` | Key inside that Secret. |
| `manifest.inline` | subset of default packs | Action-risk manifest rendered to the ConfigMap. Replace with your org's manifest. |
| `manifest.existingConfigMap` | `""` | Bring your own manifest ConfigMap (chart's ConfigMap is then skipped; pods do not auto-roll on changes to it). |
| `metrics.enabled` | `false` | Sets `EP_GATE_METRICS_ENABLED=true` and renders the ServiceMonitor stub. |
| `probes.liveness.path` / `probes.readiness.path` | `/healthz` / `/readyz` | HTTP probe paths on the gate port. |
| `resources` | 100m/128Mi → 500m/256Mi | Requests/limits defaults. |

## Honest limitations

- **Experimental.** Not battle-tested; `helm lint`-clean is not a security
  review. Read the rendered output (`helm template`) before applying.
- The default in-memory consumption store and evidence sink are per-pod. For
  fleets (`replicaCount > 1`) wire a shared/durable backend or replayed
  receipts on another pod are only caught by receipt freshness, not
  consumption.
- The ServiceMonitor is a **stub**: no TLS/auth on the scrape endpoint —
  adapt it to your monitoring stack.
- No Ingress/NetworkPolicy/HPA templates on purpose: the gate is an internal
  policy-enforcement point; expose it deliberately.

## License

Apache-2.0 — see the repository root.
