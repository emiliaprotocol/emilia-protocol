# EMILIA Gate BYOC Deployment

This document deploys `apps/gate-service` as an operator-built container on
Kubernetes. The repository does not claim or configure an official published
Gate image. Build `Dockerfile.gate`, push it to a registry you control, and
deploy the resulting immutable digest.

The service performs complete mediation for `github.repo.delete`, but it is not
caller authentication or GitHub authorization. Keep it behind the operator's
identity-aware gateway and authorization controls. The supplied Kubernetes
Service is `ClusterIP`; these assets intentionally do not create a public
Ingress or cloud load balancer.

## Runtime contract

`apps/gate-service` intentionally leaves production adapters to the BYOC
operator. It refuses to start unless `EMILIA_GATE_CONFIG` points to an ESM
module that supplies:

- a GitHub connector;
- a durable, ownership-fenced, permanent consumption store;
- a durable, strict, fork-aware atomic evidence log;
- a durable action-status store;
- pinned issuer and approver roots, RP ID, and allowed origins.

There is no production in-memory fallback. The Helm chart and Terraform module
mount an operator-owned `gate.config.mjs` and an idempotent `migrate.mjs` from
an existing Kubernetes Secret. Treat both files as executable release
artifacts: review, sign, version, and restrict changes to them.

The repository does provide a canonical append-only evidence primitive:
`packages/gate/evidence-postgres.js` with
`packages/gate/deploy/sql/001-runtime.sql`. The Docker image retains that SQL so
`migrate.mjs` can apply it. Prefer this backend for the strict shared evidence
log unless a replacement independently satisfies the same atomic append,
readback, fork-detection, and least-privilege contract. Consumption and action
status still require operator-reviewed durable adapters and migrations.

The service listens on `HOST`/`PORT`; the assets set `0.0.0.0:8080`. Its health
API is `GET /v1/health`. The route returns 200 only when the operator-supplied
readiness function proves the durable consumption, evidence, and action-state
dependencies are usable; failures return a detail-free 503. It deliberately
does not call GitHub, KMS, or SIEM services on every probe. Use separate external
synthetics for connector reachability.

## Build the image

The Dockerfile uses a pinned multi-platform Node 22 base, runs as UID/GID
`10001`, and writes only to `/tmp` when the runtime supplies that mount. It
includes `pg` for operator Postgres adapters. A cloud-specific KMS SDK is not
chosen for the operator; extend the image when the config module needs one.

```bash
export REGISTRY=registry.example.com/security
export IMAGE_TAG="$(git rev-parse --short=12 HEAD)"

docker build \
  --file Dockerfile.gate \
  --tag "$REGISTRY/emilia-gate-service:$IMAGE_TAG" \
  .
```

Scan and sign the local artifact under the organization's supply-chain policy,
then push it through the organization's release process. Resolve the registry
digest and use `repository@sha256:...` in production. Do not deploy `latest`.

The Kubernetes assets also enforce non-root execution, a read-only root
filesystem, `RuntimeDefault` seccomp, no privilege escalation, all Linux
capabilities dropped, no service-account token, and a size-limited `/tmp`
`emptyDir`.

## Provision existing Secrets

Create Secrets outside Helm/Terraform. The deployment code stores only Secret
names and key names, never secret values.

| Secret | Default key | Consumer | Purpose |
| --- | --- | --- | --- |
| `emilia-gate-configuration` | `gate.config.mjs` | service | Operator production adapter and trust wiring |
| `emilia-gate-configuration` | `migrate.mjs` | migration Job | Idempotent forward schema migration |
| `emilia-gate-postgres` | `database-url` | service | Least-privilege runtime Postgres URL |
| `emilia-gate-postgres-migrate` | `database-url` | migration Job | Optional DDL-capable migration URL |
| `emilia-gate-api-token` | `api-token` | service | Bearer token required before action lookup or execution |
| `emilia-gate-kms` | `kms-key-id` | optional service extension | Only when an operator config adds a KMS-backed capability; Gate verification itself holds no signing key |
| `emilia-gate-issuer-roots` | `issuer-roots.json` | service | Pinned issuer/approver trust material |

Use a runtime database role that can read/write only the Gate tables. Give DDL
privileges to a separate migration role and set the migration-specific Secret.
Require TLS with hostname and CA verification for managed Postgres. Do not put
database passwords, private signing keys, GitHub tokens, or cloud credentials
inside `gate.config.mjs`.

The service action also needs a GitHub credential or a custom connector that
mints one. Reference a separate existing Secret through `runtime.extraEnv` in
Helm or equivalent caller-owned wiring in Terraform. A fine-grained credential
must be limited to the intended organization/repositories and the minimum
Administration permission needed by the GitHub deletion API. Never reuse a
personal broad-scope token.

Updating an existing Secret does not change the pod template. Restart the
Deployment after a reviewed rotation:

```bash
kubectl -n emilia-gate rollout restart deployment/emilia-gate-service
kubectl -n emilia-gate rollout status deployment/emilia-gate-service
```

For issuer-root rotation, deploy an overlap set first, wait beyond the maximum
accepted receipt age, then remove the retired root. For KMS rotation, keep the
old public verification material available for historical evidence while new
records use the new key identifier.

## Helm deployment

Create a private values file containing references, not values:

```yaml
image:
  repository: registry.example.com/security/emilia-gate-service
  digest: sha256:REPLACE_WITH_REGISTRY_DIGEST

configuration:
  existingSecret: emilia-gate-configuration

secrets:
  postgres:
    existingSecret: emilia-gate-postgres
    key: database-url
    envName: DATABASE_URL
  apiToken:
    existingSecret: emilia-gate-api-token
    key: api-token
    envName: EMILIA_GATE_API_TOKEN
  kms:
    existingSecret: emilia-gate-kms
    key: kms-key-id
    envName: EP_KMS_KEY_ID
  issuerRoots:
    existingSecret: emilia-gate-issuer-roots
    key: issuer-roots.json
    envName: EP_GATE_ISSUER_ROOTS

migrations:
  postgres:
    existingSecret: emilia-gate-postgres-migrate
    key: database-url

runtime:
  extraEnv:
    - name: GITHUB_TOKEN
      valueFrom:
        secretKeyRef:
          name: emilia-gate-github
          key: token
          optional: false
```

Render locally before touching a cluster:

```bash
helm lint --strict packages/gate/deploy/helm/emilia-gate-service \
  --values gate.production.values.yaml
helm template emilia-gate packages/gate/deploy/helm/emilia-gate-service \
  --namespace emilia-gate --values gate.production.values.yaml > /tmp/gate.yaml
```

Install or upgrade:

```bash
helm upgrade --install emilia-gate \
  packages/gate/deploy/helm/emilia-gate-service \
  --namespace emilia-gate --create-namespace \
  --values gate.production.values.yaml \
  --atomic --wait --timeout 15m
```

The `pre-install,pre-upgrade` hook runs `migrate.mjs` before pods roll. A failed
or timed-out migration aborts the release. On first install, that hook runs
before this release's regular NetworkPolicy exists; apply a namespace-level
default-deny baseline before installing. Existing release policies cover later
upgrades.

The default is two replicas, rolling updates with `maxUnavailable: 0`, a PDB
with `minAvailable: 1`, resource requests/limits, and host-level topology
spreading. Use multiple nodes and zones; a PDB cannot create capacity or protect
against simultaneous involuntary failures.

## Terraform deployment

Use `packages/gate/deploy/terraform/service` from a root module that configures
the Kubernetes provider. Required inputs include namespace, full BYOC image
reference, configuration Secret name, and the Postgres/KMS/issuer-root Secret
names. Set `migration_postgres_secret_name` for the DDL role.

The Terraform migration Job name hashes the image, command, and
`migration_revision`. Terraform waits for that Job before creating/updating the
Deployment. Bump `migration_revision` when schema inputs change without an image
change. The module does not create a namespace or any Secret.

Validate without a cluster:

```bash
packages/gate/deploy/terraform/service/tests/validate.sh
```

## Network policy and egress

The base policy selects both service and migration pods, denies ingress, and
permits only DNS plus Postgres egress. A second service-only policy permits:

- service ingress from the same namespace;
- optional operator-supplied KMS, GitHub, and SIEM TCP/443 CIDRs.

The migration Job never receives the service-only HTTPS allowances. DNS goes
to the configured cluster-DNS selectors; Postgres TCP/5432 goes only to the
configured same-namespace selector or managed-database CIDRs.

Standard Kubernetes NetworkPolicy cannot select an FQDN. GitHub, cloud KMS, and
SaaS SIEM address ranges can change, so a copied public-IP snapshot is not a
durable control. Prefer an egress proxy with stable private CIDRs or a
CNI-specific FQDN policy. Point `githubCidrs`, `kmsCidrs`, and `siemCidrs` (or
the Terraform equivalents) at those enforcement points. Leave a path unset to
keep it denied.

The Gate's SIEM copy is observability, not the authoritative enforcement
record. SIEM failure must not make an action executable. The durable strict
evidence log remains the enforcement record and must fail closed independently.

Cluster DNS labels vary. Confirm the actual CoreDNS labels before rollout:

```bash
kubectl -n kube-system get pods --show-labels
```

## Local E2E harness

`docker-compose.gate-e2e.yml` builds the local Dockerfile, initializes a local
Postgres schema, mounts an E2E-only Postgres adapter, and starts the service as
non-root with a read-only root filesystem. It does not use an official Gate
image. Its GitHub connector is real, so use a deliberately invalid token when
testing only health and never send `POST /v1/actions` against a production
repository.

Create five test-only files outside the repository, then point Compose at them.
The issuer-roots file contains the JSON trust object shown below; the other
four files contain one value each. File-backed Secrets preserve the read-only
container filesystem in Docker Compose.

```bash
export EMILIA_GATE_E2E_POSTGRES_OWNER_PASSWORD_FILE=/secure/tmp/gate-postgres-owner-password
export EMILIA_GATE_E2E_POSTGRES_RUNTIME_PASSWORD_FILE=/secure/tmp/gate-postgres-runtime-password
export EMILIA_GATE_E2E_API_TOKEN_FILE=/secure/tmp/gate-api-token
export EMILIA_GATE_E2E_GITHUB_TOKEN_FILE=/secure/tmp/gate-github-token
export EMILIA_GATE_E2E_ISSUER_ROOTS_FILE=/secure/tmp/gate-issuer-roots.json

docker compose -f docker-compose.gate-e2e.yml config --quiet
```

Example test-only issuer-roots content:

```json
{
  "trustedKeys": ["test"],
  "approverKeys": { "test": "test" },
  "rpId": "approve.example.test",
  "allowedOrigins": ["https://approve.example.test"]
}
```

With Docker running, use a valid test trust bundle if the constructor requires
cryptographic key parsing, then start and inspect health:

```bash
docker compose -f docker-compose.gate-e2e.yml up --build --wait
curl --fail --silent --show-error http://127.0.0.1:8787/v1/health
docker compose -f docker-compose.gate-e2e.yml down --volumes
```

Compose runs the repository's canonical Postgres evidence migration and
backend under a migration owner, then connects the service as a separate
least-privilege runtime role. Its consumption/action schema and adapter wiring
remain E2E fixtures, not a promised production schema. The operator's reviewed config/migration
modules remain authoritative.

## Backup runbook

Define and monitor an RPO/RTO before production. Replay state and the atomic
evidence head are security state, not disposable cache.

1. Enable encrypted managed Postgres snapshots and point-in-time recovery. Keep
   backup storage in a separate failure and administrative domain.
2. Take periodic logical backups with `pg_dump --format=custom --no-owner
   --no-acl` using a dedicated read-only backup role.
3. Back up every table owned by the operator adapter as one consistent database
   point: permanent consumption, evidence records/head, action status, and the
   migration ledger. Never back up only the evidence rows without their head or
   only actions without consumption state.
4. Record database engine version, migration revision, image digest, config
   artifact digest, issuer-root version, and KMS key identifier with each
   backup. Do not export private KMS key material.
5. Protect backup and restore credentials separately from runtime credentials.
   Alert on snapshot deletion, PITR disablement, restore, and backup failure.
6. Restore into an isolated environment on a schedule and verify row counts,
   constraints, migration ledger, evidence-chain continuity, and representative
   consumed receipt IDs. A backup is not proven until a restore is tested.

Use provider-native snapshots/PITR for low RPO. A logical backup is valuable for
portability and inspection but is not a substitute for continuous recovery.

## Restore runbook

A stale restore can forget that receipts were consumed and can therefore reopen
a replay window. Treat restore as a security incident, not just database work.

1. Block ingress and scale Gate to zero. Preserve logs and the failed database;
   do not overwrite the only forensic copy.
2. Restore the selected snapshot/PITR point into a new isolated database. Keep
   GitHub egress denied during validation.
3. Identify the interval between the recovery point and the last acknowledged
   production write. Reconcile consumption and evidence from surviving replicas,
   immutable exports, or transaction logs where available.
4. Before reopening, invalidate every receipt that could have been consumed in
   the lost interval, or advance an operator-pinned acceptance epoch so those
   receipts cannot authorize again. If that cannot be proven, remain closed.
5. Verify schema constraints, migration ledger, evidence head/sequence, action
   records, and permanent consumption rows with operator tooling. `/v1/health`
   alone is not a restore check.
6. Point a new Postgres Secret version at the restored database. Run the current
   forward migration Job. Do not grant the runtime role DDL privileges.
7. Start one isolated pod with GitHub mutation egress still blocked. Verify
   readiness, an expected refusal, a known consumed-receipt replay refusal, and
   evidence append/readback.
8. Restore controlled egress, scale to two replicas, and verify concurrent
   reservation and atomic evidence append behavior across both pods.
9. Reopen ingress only after the replay-gap decision and evidence are recorded.

Restore KMS configuration and public issuer roots from the secret manager, not
from the database dump. If a KMS key was destroyed, follow the key-compromise/
evidence-verification policy; a database restore cannot recreate it.

## Upgrade runbook

1. Review the exact image digest, config module, migration module, and rendered
   manifests. Run the service tests plus Helm, Terraform, and Compose checks.
2. Confirm current backups/PITR and record the evidence head and migration
   revision before change.
3. Use expand-and-contract migrations. Because the Helm migration runs before
   old pods are replaced, the migrated schema must remain compatible with the
   old application until rollout completes. Do not drop/rename columns or
   tighten constraints in the expand phase.
4. Deploy with `helm upgrade --atomic --wait` or a reviewed Terraform plan.
   Confirm the migration Job completes before the Deployment rolls.
5. Watch readiness, restart count, Postgres errors, evidence-log failures,
   reservation contention, GitHub errors, and SIEM delivery. Keep enforcement
   closed if durability is uncertain.
6. Verify a known replay refusal and a controlled non-destructive test action.
   Confirm evidence append/readback from both replicas.
7. Perform contract cleanup only in a later release after all old pods and
   rollback targets no longer need the old schema.

## Rollback runbook

Application rollback and database rollback are different decisions.

1. Stop the rollout and retain migration/pod logs. Determine whether the new
   migration is backward compatible with the previous image.
2. If compatible, Helm can roll back the application revision:

   ```bash
   helm -n emilia-gate history emilia-gate
   helm -n emilia-gate rollback emilia-gate PREVIOUS_REVISION --wait --timeout 15m
   ```

   The chart's migration hook is `pre-install,pre-upgrade`; it does not run a
   down migration during `helm rollback`.
3. For Terraform, pin the prior image digest. Disable the migration Job only for
   that controlled apply after proving the current schema is compatible; an old
   migration module must not be used as an implicit down migration.
4. Verify readiness, replay refusal, evidence append/readback, and both replicas
   before reopening normal traffic.
5. Prefer a forward fix for schema defects. Never run an automatic down
   migration over durable consumption or evidence records.

If the database itself must move to an older recovery point, use the full
restore runbook and invalidate the lost receipt interval. Do not pair an old
database snapshot with live traffic merely to make the old image start; that
can erase replay and evidence history.

## Clusterless checks

These checks require no Kubernetes cluster:

```bash
packages/gate/deploy/helm/emilia-gate-service/tests/render-check.sh
packages/gate/deploy/terraform/service/tests/validate.sh
docker compose -f docker-compose.gate-e2e.yml config --quiet
npm --prefix apps/gate-service test
```

The Docker image and full Compose startup still require a running Docker daemon.
