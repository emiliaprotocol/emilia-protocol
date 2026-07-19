<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Gate — deprecated Terraform module (`EP-GATE-TF-v1`)

Terraform sibling of the Helm chart (`../helm`, `EP-GATE-HELM-v1`) for BYOC
(bring-your-own-cloud) installs of the Trusted Action Firewall. Same container
contract, same fail-closed invariants, expressed as three Kubernetes resources
in a cluster **you** control:

| Resource | Purpose |
| --- | --- |
| `kubernetes_config_map_v1.manifest` | The action-risk manifest (the deny-by-default policy), mounted read-only at `/etc/emilia-gate/action-risk-manifest.json` |
| `kubernetes_deployment_v1.gate` | The gate pods — non-root, read-only rootfs, no privilege escalation, all capabilities dropped, no service-account token; pinned issuer keys arrive via a non-optional `secretKeyRef` to **your** Secret |
| `kubernetes_service_v1.gate` | Cluster-internal Service (ClusterIP by default) in front of the pods |

**Deprecated:** this legacy module may run per-process in-memory consumption and
evidence state. New deployments should use `./service`, which targets
`apps/gate-service` and requires durable operator adapters.

**Honest framing:** this is a *reference module* and it is *experimental*. It
is a starting point for your platform team to review, fork, and own — not a
managed service, not a turnkey production install. The deployer's cluster, the
deployer's keys, the deployer's responsibility for network policy, ingress,
TLS, and durable storage. There is no official public gate image while this is
experimental: build and push your own.

## Key custody — read this first

Issuer public keys (the keys the gate pins and trusts to have signed receipts)
are consumed from an **existing Kubernetes Secret that you create**. The module
takes the Secret's *name* only:

- it never accepts key material inline,
- it never creates or reads a Secret, so no key bytes enter Terraform state,
- the `secretKeyRef` is `optional = false` — **no pinned issuers, no pods**. A
  gate without pinned issuer keys must never come up permissive, so it fails
  closed by not coming up at all.

Create the Secret out-of-band (or via your own secrets tooling — ESO, sealed
secrets, Vault injector):

```sh
kubectl -n emilia create secret generic emilia-gate-issuer-keys \
  --from-file=issuer-keys.json=./issuer-keys.json
```

where `issuer-keys.json` is a JSON array of pinned base64url SPKI-DER Ed25519
public keys (or a `{kid: key}` map). It reaches the container as
`EP_GATE_ISSUER_KEYS`.

## Usage

```hcl
provider "kubernetes" {
  config_path = "~/.kube/config" # your cluster, your credentials
}

module "emilia_gate" {
  source = "github.com/FutureEnterprises/emilia-protocol//packages/gate/deploy/terraform"

  namespace = "emilia"                                  # must already exist
  image     = "ghcr.io/your-org/emilia-gate@sha256:..." # pin a digest

  replicas                = 1
  issuer_keys_secret_name = "emilia-gate-issuer-keys" # NAME only, never keys
  github_token_secret_name = "emilia-gate-github"

  # The deny-by-default policy the gate enforces (EP-ACTION-RISK-MANIFEST).
  manifest_json = file("${path.module}/manifest.json")
}

output "gate_endpoint" {
  value = module.emilia_gate.service_endpoint
  # e.g. http://emilia-gate.emilia.svc.cluster.local:8080
}
```

The manifest is validated at `terraform plan` time (must be JSON with an
`actions` field), and its sha256 is annotated onto the pod template so every
policy change rolls the pods.

## Container contract (identical to the Helm chart)

| Env var | Source | Default |
| --- | --- | --- |
| `NODE_ENV` | fixed | `production` |
| `EP_GATE_PORT` | `port` | `8080` |
| `EP_GATE_LOG_LEVEL` | `log_level` | `info` |
| `EP_GATE_EVIDENCE_STRICT` | `evidence_strict` | `true` |
| `EP_GATE_MANIFEST_PATH` | ConfigMap mount | `/etc/emilia-gate/action-risk-manifest.json` |
| `EP_GATE_METRICS_ENABLED` | `metrics_enabled` | `false` |
| `EP_GATE_ISSUER_KEYS` | `secretKeyRef` → your existing Secret | — (required) |
| `GITHUB_TOKEN` | `github_token_secret_name` → existing Secret | — (optional) |

Extra plain-text env goes in `extra_env` — **never secrets** (values in that
map land in Terraform state). Use `secret_env` for generic non-optional
`secretKeyRef` entries; the module accepts Secret names/keys, never values.

## Inputs

| Name | Default | Notes |
| --- | --- | --- |
| `image` | — (required) | Pin a digest or exact tag |
| `manifest_json` | — (required) | JSON string; plan-time validated |
| `issuer_keys_secret_name` | — (required) | Existing Secret, same namespace |
| `issuer_keys_secret_key` | `issuer-keys.json` | Key inside that Secret |
| `name` | `emilia-gate` | DNS-1123 label |
| `namespace` | `default` | Must already exist |
| `replicas` | `1` | Values above one require both shared backend references |
| `shared_consumption_backend`, `shared_evidence_backend` | `null` | Secret-backed adapter environment references required above one replica |
| `github_token_secret_name` | `null` | Existing GitHub token Secret reference |
| `secret_env` | `{}` | Generic environment-to-existing-Secret references |
| `port` / `service_port` | `8080` / `8080` | |
| `service_type` | `ClusterIP` | Anything more exposed is your explicit call |
| `log_level` | `info` | `error` \| `warn` \| `info` \| `debug` |
| `evidence_strict` | `true` | Keep true — fail-closed evidence log |
| `metrics_enabled` | `false` | Scrape wiring is chart-only for now |
| `liveness_path` / `readiness_path` | `/healthz` / `/readyz` | `null` disables |
| `resources` | 100m/128Mi → 500m/256Mi | |
| `run_as_user` | `10001` | Non-root enforced |
| `read_only_root_filesystem` | `true` | `/tmp` is a writable emptyDir either way |
| `extra_env`, `extra_labels` | `{}` | Plain-text only |

Outputs: `service_name`, `namespace`, `service_endpoint`, `deployment_name`,
`manifest_config_map_name`, `module_version`.

## Operational notes

- **Replay defense across replicas:** the module refuses `replicas > 1` unless
  both `shared_consumption_backend` and `shared_evidence_backend` provide
  complete Secret-backed environment references. That proves wiring exists,
  not that a custom legacy image implements the required atomic adapters;
  prefer the service module.
- **Namespace:** not created by this module — pass one that exists.
- **Ingress/TLS/NetworkPolicy/ServiceMonitor:** intentionally out of scope.
  The default posture is cluster-internal; exposure decisions belong to the
  deployer.

## What has been validated

`packages/gate/deploy/terraform/tests/validate.sh` runs formatting, provider
schema validation, and mocked plan tests that cover the one-replica default,
multi-replica refusal, and Secret-backed environment rendering. It uses
Terraform 1.9.8 with
`hashicorp/kubernetes` 2.38. A create-only `terraform plan` renders all three
resources, and the plan-time input validations refuse unsafe scaling. The module has **not** been
applied against a live cluster as part of this repo's CI — treat it as
reviewed reference code, not a certified install path.
