# EMILIA Gate service Helm chart

This chart is a BYOC reference deployment for `apps/gate-service`. It does not
name or imply an official published image. Build `Dockerfile.gate`, push the
result to a registry you control, and pass an immutable digest where possible.

The chart intentionally refuses to render with its default values. Supply:

- `image.repository` and exactly one of `image.digest` or `image.tag`;
- `configuration.existingSecret` containing `gate.config.mjs` and
  `migrate.mjs`;
- `secrets.postgres.existingSecret` with the database URL key;
- `secrets.kms.existingSecret` with the KMS key identifier/config key;
- `secrets.issuerRoots.existingSecret` with the pinned issuer-root set.

The chart never renders a Kubernetes `Secret`. Secret names and keys are wired
with non-optional references. The migration hook receives the operator config
and Postgres reference; set `migrations.postgres.existingSecret` to give it a
separate DDL-capable role. The service receives the config and all three runtime
references. The config module must satisfy the durable store contracts in
`apps/gate-service/README.md`. The chart does not substitute an in-memory
adapter or invent a persistence schema on the operator's behalf.

## Install

```bash
helm upgrade --install emilia-gate \
  packages/gate/deploy/helm/emilia-gate-service \
  --namespace emilia-gate --create-namespace \
  --set-string image.repository=registry.example.com/security/emilia-gate-service \
  --set-string image.digest=sha256:REPLACE_WITH_IMAGE_DIGEST \
  --set-string configuration.existingSecret=emilia-gate-configuration \
  --set-string secrets.postgres.existingSecret=emilia-gate-postgres \
  --set-string secrets.kms.existingSecret=emilia-gate-kms \
  --set-string secrets.issuerRoots.existingSecret=emilia-gate-issuer-roots \
  --atomic --wait
```

The pre-install/pre-upgrade migration Job must complete before Helm rolls the
Deployment. It is bounded by an active deadline and runs non-root with a
read-only root filesystem. The Deployment defaults to two replicas,
`maxUnavailable: 0`, a one-pod PDB, resource requests/limits, startup/liveness/
readiness probes, and a writable memory/scratch volume only at `/tmp`.

## Network policy

The default NetworkPolicy permits DNS, same-namespace ingress, and Postgres on
port 5432 only to a same-namespace pod labeled
`app.kubernetes.io/name=postgresql`. Managed Postgres requires an operator to
set `networkPolicy.egress.postgres.podSelector=null` plus stable
`networkPolicy.egress.postgres.cidrs` (or provide an additional CNI policy).

Standard Kubernetes NetworkPolicy does not support DNS names. GitHub API,
cloud KMS, and SIEM endpoints commonly use changing address ranges. Do not copy
today's public IP list into a long-lived manifest and assume it remains valid.
Prefer a controlled egress proxy with stable CIDRs or a CNI FQDN policy, then
set `kmsCidrs`, `githubCidrs`, and `siemCidrs` to the stable enforcement points.
Until configured, those outbound paths remain denied.

On a first Helm install, the migration is a pre-install hook and therefore runs
before this release's regular NetworkPolicy exists. Enforce a namespace-level
baseline egress policy before installation; subsequent upgrades are covered by
the existing release policy.

## Clusterless check

```bash
packages/gate/deploy/helm/emilia-gate-service/tests/render-check.sh
```

The script runs strict Helm linting, renders with documentation-only registry
and Secret names, asserts the hardening resources and settings, and rejects any
rendered `Secret`. It does not connect to a cluster.
