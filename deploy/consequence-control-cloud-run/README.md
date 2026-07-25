# Consequence-control split Cloud Run deployment

This lane renders and, only with an explicit apply gate, performs a two-service
Cloud Run deployment:

- `consequence-actuator`: internal-only, provider-credential-owning actuator.
- `consequence-control`: decision service with no GitHub App credentials.

The scripts never create secret payloads. They accept only existing Secret
Manager secret names pinned to numeric versions. Container images must be
Artifact Registry-style references pinned by `@sha256:<64 lowercase hex>`.

## Security boundary

The actuator runtime receives:

- the GitHub App ID, installation ID, and private key;
- a dedicated actuator database URL and the expected
  `consequence_actuator_executor` principal name;
- the execution-envelope public key;
- the actuator-observation private key; and
- the shared actuator application bearer token.

The decision runtime receives:

- the exact tagged actuator revision URL and the shared actuator bearer token;
- the execution-envelope private key;
- the actuator-observation public key;
- its distinct executor and recovery database URLs; and
- its own decision-plane secrets.

The decision service receives GitHub target coordinates, but no GitHub App
credential environment variable or secret binding.

The actuator uses `internal` ingress, Direct VPC egress, Cloud Run Invoker IAM,
and an application bearer token whose resource-level Secret Accessor binding is
limited to the two runtime service accounts. The decision client keeps the
application token in `Authorization`
and obtains a Google-signed ID token through Application Default Credentials
for the actuator's canonical service URL. It sends that identity token in
`X-Serverless-Authorization`. Acquisition failure is fail-closed; there is no
application-token-only fallback and no direct metadata URL handling.

The actuator is deployed with `--no-allow-unauthenticated`. At the resource
level, the deployment lane reconciles the complete `roles/run.invoker` binding
to exactly the decision runtime service account; stale, conditional, `allUsers`, and
`allAuthenticatedUsers` invoker bindings are removed and the resulting policy
is read back and checked. It similarly reconciles each referenced secret's
`roles/secretmanager.secretAccessor` binding to only the runtime identities
that consume that secret while preserving unrelated IAM roles. The exact
tagged actuator URL remains the request destination, while the canonical
service URL remains the pinned ID-token audience, including during canary
traffic.

Resource-level reconciliation is not treated as sufficient proof. After the
zero-traffic candidates exist and before every promotion step,
`verify-effective-iam.py --live` queries Cloud Asset Policy Analyzer for the
effective `run.routes.invoke` and `secretmanager.versions.access` permissions.
It expands groups and service-account impersonation and refuses partial,
conditional, public, aggregate, unexpanded, or non-allowlisted access. Before
analysis, the verifier independently queries the project ancestry. A standalone
project uses its exact project scope. If any folder or organization ancestry
exists, the deployment must supply the exact covering
`organizations/NUMBER` analyzer scope and the caller must be able to analyze
that scope; project scope is never claimed to cover ancestor policies. Missing,
partial, or mismatched ancestry evidence fails closed.

The effective-IAM manifest requires the exact project-derived Compute Engine
and Cloud Run service agents for every checked target, alongside the workload
identities. This is an accepted GCP control-plane dependency, not a
resource-level grant created by this lane. Their predefined roles include
service-account impersonation and, for the Cloud Run agent, route invocation.
User accounts, default compute accounts, arbitrary service agents, inherited
owners, and inherited admins remain forbidden. An inherited owner or admin
grant therefore blocks promotion even when the resource policy itself looks
closed.

Policy Analyzer evaluates IAM allow policies and does not apply deny policies
to its results. Deny policies may provide defense in depth, but they cannot be
used to make this proof pass. The deployment project must therefore remove
broad allow roles from human and default identities and use deployment roles
that omit `run.routes.invoke`, `secretmanager.versions.access`, and service
account token-creation permissions.

The decision service intentionally keeps its existing application-level
authentication posture and `--no-invoker-iam-check`; this change does not make
that externally addressed service IAM-only.

## Readiness

The decision service exposes unauthenticated `/v1/live` and `/v1/ready`
endpoints, so Cloud Run startup, liveness, and readiness probes use those
endpoints.

The actuator protects `/v1/live` and `/v1/ready` with its bearer token. Putting
that token in a Cloud Run probe header would disclose it in service
configuration. Instead, the actuator server performs database-principal and
GitHub App readiness before it starts listening, and Cloud Run uses a TCP
startup probe. A listening actuator therefore passed its startup readiness
contract. Its tagged revision is also checked through the decision service's
`/v1/ready` probe.

## Render without credentials

Every mutating deployment, bootstrap, provisioning, or traffic command, and
every canary, telemetry, authorization, or stable trust verification requires
`DEPLOYMENT_CONFIG_SHA256` in the process environment. It is the SHA-256 of the
exact config bytes and is deliberately forbidden inside the config. Production
automation must inject it from a protected release variable, signed policy
evaluation, or equivalent source that the caller cannot rewrite. A
caller-derived digest provides no trust separation and does not satisfy this
contract.

Each shell entry point accepts only its explicit deployment-config key
allowlist. Invocation controls, `PATH`, `ACTION`, thresholds, poll limits,
prepared requests, and artifact paths are never config keys. The loader opens
the config once with no symlink following, requires safe ownership and mode,
checks the protected digest over those exact bytes, and retains a private
read-only snapshot plus an in-memory copy. Downstream verifiers consume the
retained bytes through stdin, so replacing the original path after validation
cannot change the authorized config.

`config.example.env` is a catalog, not one accepted all-command file. Maintain
separately pinned provision, deploy, bootstrap, and traffic profiles containing
exactly the keys emitted by `provision_config_variables`,
`deploy_config_variables`, `bootstrap_config_variables`, and
`traffic_config_variables` in `lib/common.sh`. The protected GitHub deployment
workflow therefore requires separate
`CONSEQUENCE_CONTROL_DEPLOY_CONFIG`/`CONSEQUENCE_CONTROL_DEPLOY_CONFIG_SHA256`
and
`CONSEQUENCE_CONTROL_BOOTSTRAP_CONFIG`/`CONSEQUENCE_CONTROL_BOOTSTRAP_CONFIG_SHA256`
and
`CONSEQUENCE_CONTROL_TRAFFIC_CONFIG`/`CONSEQUENCE_CONTROL_TRAFFIC_CONFIG_SHA256`
secret/variable pairs.

The same protected workflow is the only production traffic-mutation entry
point. It exposes one dispatch operation for each exact transition accepted by
`traffic.sh`: decision 1%, 10%, 50%, and 100%; actuator 100%; and rollback.
Each dispatch materializes the signed stable manifest and a fresh,
one-time-consumable rollout authorization from protected environment secrets.
Promotion steps additionally require the signed canary evidence and prior-stage
telemetry. Rollback intentionally omits those two promotion-only artifacts but
still requires a new consumed authorization for each service transition. The
workflow never derives the protected config digest from the config bytes.

The protected traffic profile uses fixed, root-owned-runner paths for
verification-key material so its independently pinned config bytes never
depend on a generated runner directory:

- `/tmp/emilia-consequence-control-trust/canary-evidence-public.pem`
- `/tmp/emilia-consequence-control-trust/rollout-telemetry-public.pem`
- `/tmp/emilia-consequence-control-trust/rollout-authorization-public.pem`
- `/tmp/emilia-consequence-control-trust/stable-release-public.pem` (file trust
  only; omit the secret and this path when the profile pins Cloud KMS)

The workflow creates the previously absent directory with mode `0700`, writes
the corresponding protected environment secrets with a `077` umask, and then
the existing verifiers require the independently configured key IDs and
SHA-256 values. The stable public key is passed explicitly to `traffic.sh`;
Cloud-KMS profiles fail closed if a file key is also supplied.

The durable mutation ledger uses the checked-in
`postgres-rollout-attempt-store.sh`, whose exact SHA-256 is pinned by
`CONSEQUENCE_CONTROL_ATTEMPT_STORE_ADAPTER_SHA256`. The workflow supplies only
the dedicated executor database URL through
`CONSEQUENCE_CONTROL_ROLLOUT_ATTEMPT_DATABASE_URL`, requires `psql`, and the
traffic script single-opens and privately copies the authenticated adapter
before any Cloud Run mutation.

```sh
cp deploy/consequence-control-cloud-run/config.example.env /tmp/emilia-config-catalog.env
# Build separate operation profiles from the catalog using the exact schemas
# above, then replace non-secret coordinates and secret-name:version references.
# Fetch this value from the independently protected release policy:
export DEPLOYMENT_CONFIG_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
deploy/consequence-control-cloud-run/provision-dedicated-project.sh \
  --config /tmp/emilia-provision.env \
  --render

deploy/consequence-control-cloud-run/deploy.sh \
  --config /tmp/emilia-deploy.env \
  --render

# Required as well when the project has folder or organization ancestry:
deploy/consequence-control-cloud-run/deploy.sh \
  --config /tmp/emilia-deploy.env \
  --analyzer-scope organizations/123456789 \
  --render

deploy/consequence-control-cloud-run/traffic.sh \
  --config /tmp/emilia-traffic.env \
  --render-promote
```

Rendering is the default-safe operation. Applying requires both `--apply` and
`DEPLOYMENT_APPROVED=true`. This repository change does not grant deployment
approval.

## Dedicated-project provisioning

The runtime belongs in a dedicated project, not beside unrelated workloads.
`provision-dedicated-project.sh` creates or reconciles the project, billing
link, required APIs, exact `/26` Direct VPC subnet, Private Google Access,
router/NAT, Artifact Registry repository, custom provisioner/deployer/recovery
roles, runtime service accounts, and split recovery custody. It removes
default Editor grants and every Owner grant only after all three custom-role
bindings are read back, then proves the managed bindings are exact.

The config pins `BILLING_ACCOUNT`, optional `PROJECT_PARENT`,
`PROVISIONER_PRINCIPAL`, `DEPLOYER_PRINCIPAL`, and comma-separated
`RECOVERY_PRINCIPALS`. The active `gcloud` identity must exactly match the
configured provisioner. The provisioner and deployer must be distinct service
accounts. At least two recovery principals are required; each must be a real,
independently controlled IAM identity and must differ from both service
accounts. The provisioner and recovery roles deliberately omit runtime
`actAs`, route invocation, and secret-payload access. Applying requires
confirmations outside the config:

```sh
PROVISIONING_APPROVED=true \
PROVISIONING_CONFIRM_PROJECT=emilia-production \
deploy/consequence-control-cloud-run/provision-dedicated-project.sh \
  --config /tmp/emilia-cloud-run.env \
  --apply
```

Approval controls are rejected if stored in the config file. The provisioning
script also exposes explicit `--grant-jit-actas` and `--revoke-jit-actas`
operations. Those require `ROLLOUT_APPROVED=true`,
`ROLLOUT_CONFIRM_PROJECT` equal to `PROJECT_ID`, and a UTC
`JIT_ACTAS_EXPIRES_AT` no more than 60 minutes in the future.

## First stable release

A new dedicated project has no rollback target. Before the first candidate,
`bootstrap-stable.sh` creates a witnessed, deny-all pair that serves only
authenticated health routes. It refuses an existing service, mutable image
reference, non-allowlisted digest, drifted provenance file, reused runtime
identity, permissioned bootstrap identity, or caller-selected trust root.

The bootstrap image digest must appear in
`STABLE_BOOTSTRAP_ALLOWED_DIGESTS`; its exact provenance document is pinned by
`STABLE_BOOTSTRAP_PROVENANCE_SHA256`. The signed stable manifest uses either:

- the configured `STABLE_RELEASE_KMS_KEY_URI` and its pinned
  `STABLE_RELEASE_KEY_ID`; or
- `STABLE_RELEASE_PUBLIC_KEY_FILE` plus
  `STABLE_RELEASE_PUBLIC_KEY_SHA256`, with the matching private key supplied
  only at invocation time.

The two trust modes are mutually exclusive. Cloud KMS is the production
default:

```sh
DEPLOYMENT_CONFIG_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
DEPLOYMENT_APPROVED=true \
deploy/consequence-control-cloud-run/bootstrap-stable.sh \
  --config /tmp/emilia-bootstrap.env \
  --bootstrap-id bootstrap1 \
  --placeholder-image \
    us-central1-docker.pkg.dev/emilia-production/runtime/deny-all@sha256:3333333333333333333333333333333333333333333333333333333333333333 \
  --output /secure/emilia/stable-release.json \
  --apply
```

The output is written only after both services are proven health-only and
serve 100% as the witnessed pair. Subsequent traffic changes revalidate the
signature, key metadata, complete project ancestry, lineage, labels, ingress,
Invoker-IAM mode, generation, service account, image digest, execution
environment, VPC, CPU, memory, scaling, concurrency, timeout, port, probes,
plain environment, numeric secret bindings, enabled secret versions, exact
traffic, and live revision state.

## Apply order

`deploy.sh --apply` is deliberately ordered:

1. verify APIs, pre-existing secrets, and service accounts, then close and
   read-back-verify each secret's accessor allowlist;
2. query and validate the complete project ancestry, requiring an explicit
   organization-wide analyzer scope when any parent hierarchy exists;
3. prove absence of effective `actAs`, then create unique release-scoped
   `roles/iam.serviceAccountUser` grants on exactly the decision and actuator
   runtime service accounts; each condition expires after at most 15 minutes;
4. deploy the actuator candidate by exact digest with zero traffic and a
   revision tag;
5. close and read-back-verify actuator `roles/run.invoker` to exactly the
   decision service account;
6. resolve the actuator's canonical service URL for the token audience and the
   exact tag URL for the request destination;
7. deploy the decision candidate by exact digest with zero traffic, configured
   to call the tagged actuator revision with dual-header authentication;
8. revoke the two temporary `actAs` grants, read back both runtime
   service-account policies, and stop immediately unless the deployer is absent
   from both;
9. re-query ancestry, then run the live effective-IAM proof over the actuator
   and every referenced
   secret, refusing inherited or impersonated access outside the allowlist;
10. stop without changing production traffic.

An EXIT cleanup path retries revocation if either deployment or any intervening
step fails. A separately invokable `deploy.sh --cleanup-jit` recovers after a
hard runner termination by removing only the two condition titles derived from
the configured `RELEASE_ID`, then proving direct and effective absence. It is
not a project-wide expired-grant sweeper; invoke it with the exact original
release config. The release identity must not retain project-wide
`iam.serviceAccounts.actAs`; the live proof runs only after revocation is
read-back-verified.

The actuator must be reachable through the configured VPC path. Cloud Run calls
to an internal-ingress service must route through a VPC considered internal, so
both services use the configured network/subnet and `all-traffic` Direct VPC
egress.

## Canary contract

Before any traffic shift, the checked-in `run-canary.py` driver must execute
the exact normal, forced-timeout, replay, durable-lookup, and authenticated
reconciliation workflow and Ed25519-sign a short-lived evidence document for
the exact candidate
revision names and image digests. Promotion re-verifies the signature under the
pinned canary-driver key ID, absolute public-key path, and
`CANARY_EVIDENCE_PUBLIC_KEY_SHA256`, plus freshness, project, region, revision
names, and image digests. The verifier reads and hashes the key once, then uses
those exact bytes for signature verification. During traffic apply it consumes
the already captured service snapshots rather than fetching a new service
baseline, while still re-deriving candidate revision configuration live. The
signed document contains these closed observations:

```json
{
  "@version": "EP-CONSEQUENCE-CANARY-EVIDENCE-v1",
  "project_id": "emilia-production",
  "region": "us-central1",
  "evidence_status": "observed",
  "observed_at": "2026-07-25T08:00:00Z",
  "expires_at": "2026-07-25T08:10:00Z",
  "nonce": "canary_nonce_...",
  "actuator_revision": "SERVICE-RELEASE",
  "decision_revision": "SERVICE-RELEASE",
  "actuator_image": "REGISTRY/IMAGE@sha256:...",
  "decision_image": "REGISTRY/IMAGE@sha256:...",
  "checks": {
    "exact_execution": {
      "http_status": 200,
      "outcome": "COMMITTED",
      "action_digest": "sha256:...",
      "attempt_id": "attempt:...",
      "provider_reference": "github:issue:..."
    },
    "timeout": {
      "http_status": 202,
      "outcome": "INDETERMINATE",
      "effect_boundary_entered": true
    },
    "replay": {
      "http_status": 409,
      "reason": "envelope_replayed",
      "provider_invocations": 1
    },
    "reconciliation": {
      "http_status": 200,
      "valid": true,
      "outcome": "ESCALATED",
      "reason": "github_attempt_attribution_unavailable",
      "reexecuted": false
    }
  },
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "canary-driver-key-2026-07",
    "value": "base64url-signature"
  }
}
```

The signature input is the UTF-8 JSON serialization of every member except
`signature`, with keys sorted recursively and separators `,` and `:`. The
canary driver private key is not a deployment secret and must not be readable
by either runtime service account.

Execute the live workflow and write evidence atomically:

```sh
deploy/consequence-control-cloud-run/run-canary.py \
  --config /tmp/emilia-deploy.env \
  --scenario /secure/path/current-approved-canary-scenario.json \
  --application-token-file /secure/path/decision-application-token \
  --private-key-file /secure/path/canary-driver-ed25519-private.pem \
  --output /secure/path/canary-evidence.json \
  --use-google-id-token
```

The scenario contains the current Gate-verified proposal, receipt, AEB
evaluation, and evidence legs for the two pinned canary profiles. It cannot
state outcomes. The driver derives outcomes and provider references from the
authenticated service responses, rejects target substitution, validates the
candidate tag/revision/image bindings live, verifies that its private key
matches the pinned public key before any effect, and will not replace an
existing evidence file without `--overwrite`.

Re-validate the resulting evidence:

```sh
deploy/consequence-control-cloud-run/verify-canary.py \
  --config /tmp/emilia-cloud-run.env \
  --evidence /secure/path/canary-evidence.json \
  --live
```

The verifier rejects unsigned, forged, stale, expired, or future-dated
evidence; duplicate JSON members; project, region, key, revision, service, or
digest mismatches; a timeout that does not become `INDETERMINATE`; replay that
is not refused as `envelope_replayed`; provider invocation counts other than
one; and reconciliation that re-executes or overclaims GitHub attempt
attribution. `traffic.sh` always invokes this live mode for a promotion.

## Traffic and rollback

Promotion is staged and each command is rendered separately:

1. decision candidate 1%;
2. decision candidate 10%;
3. decision candidate 50%;
4. decision candidate 100%;
5. actuator candidate 100%.

The decision moves first because its candidate is pinned to the actuator's
tested revision-tag URL. The old decision is not forced onto a new actuator
during the staged shift.

Rollback order is the reverse dependency-safe order:

1. actuator stable revision 100%;
2. decision stable revision 100%.

The candidate decision continues to address its tagged candidate actuator
during the short rollback interval; then the old decision is restored after
the stable actuator endpoint is ready. Traffic commands require explicit stage
selection. A canary evidence file is mandatory for promotion, but rollback is
not blocked on canary evidence.

Every apply operation also requires the signed stable manifest. File trust
requires its exact configured public-key path through `--stable-public-key`;
the verifier opens it once without following symlinks, verifies safe
ownership/mode and the hash over those exact bytes, and never reopens the path.
KMS trust forbids the file argument and resolves the public key from the
configured versioned KMS URI. Versioned Cloud KMS with HSM protection remains
the production preference. Promotion requires current signed canary evidence
and a signed telemetry document for the exact prior stage. The telemetry
observer is pinned by `ROLLOUT_TELEMETRY_KEY_ID`,
`ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE`, and
`ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256`. The observer's private key must be
separately controlled and unreadable by both runtime identities and the
deployer.

Telemetry schema `emilia-rollout-telemetry.v2` signs the
`EMILIA-ROLLOUT-TELEMETRY-V2` domain plus canonical JSON. It binds the exact
project, region, release, named transition, authorization ID, rollout nonce,
candidate and stable revision/image pairs, immutable thresholds, post-traffic
intent, both services' pre-state generation, observedGeneration, and
resourceVersion, and the protected deployment config, deployer principal,
workflow ref/SHA, WIF provider, final request-body SHA-256, target service, and
pre-resourceVersion. Reusing it across a project, identity, request, release,
transition, or later rollout stage is refused even when the telemetry
signature itself is valid.

Each mutation also requires a separate
`emilia-rollout-authorization.v1` artifact signed by the pinned rollout
authorization authority configured by `ROLLOUT_AUTHORIZATION_KEY_ID`,
`ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE`, and
`ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256`. Authorization and telemetry key IDs
and public-key hashes must be distinct. Authorization signs the
`EMILIA-ROLLOUT-AUTHORIZATION-V1` domain plus canonical JSON, so a signature
from one domain cannot be replayed in the other. Its context is byte-for-byte
equivalent to the telemetry context and its signed consumption record must say
`consumed`, be unexpired, and be bound into telemetry by SHA-256. The external
issuer must atomically consume authorization IDs/nonces before signing.

Immediately before the Cloud Run PUT, `traffic.sh` also requires a protected,
hash-pinned durable attempt-store adapter. This repository ships
`postgres-rollout-attempt-store.sh` plus the forward-only
`20260725160000_rollout_attempt_store.sql` migration. Set
`EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER` to an absolute standalone executable and
`EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER_SHA256` to its protected digest, and
supply the dedicated `rollout_attempt_executor` login through
`EMILIA_ROLLOUT_ATTEMPT_DATABASE_URL`. The adapter parses that URL into private
libpq environment variables; it never places credentials in process argv. The
script opens the adapter once without following symlinks, verifies safe
ownership/mode and exact bytes, copies those bytes privately, and invokes:

- `claim`, with an `emilia-deployment-attempt-claim.v1` JSON object keyed by
  authorization ID, rollout nonce, request SHA-256, and pre-resourceVersion;
- `complete`, with an `emilia-deployment-attempt-store-operation.v1` object
  after exact post-validation; or
- `reconcile`, with the same operation object after an ambiguous HTTP result.

The adapter must atomically and durably insert the claim before returning
`claimed`; enforce uniqueness on the four-part key (or its supplied
`claim_sha256`); reject every duplicate claim; and compare-and-set one terminal
outcome without changing an earlier outcome. It must read one JSON object from
stdin and emit only this exact response shape:

```json
{
  "schema": "emilia-deployment-attempt-store-response.v1",
  "operation": "claim",
  "status": "claimed",
  "claim_sha256": "64-lowercase-hex-characters",
  "final_resource_version": null
}
```

`complete` must return `completed`; `reconcile` must return `applied`,
`not-applied`, or `indeterminate`; and terminal responses must carry the exact
final resourceVersion. Any adapter error, malformed response, duplicate claim,
or unavailable durable store blocks the mutation. This repository intentionally
does not fake persistence or ship a database-backed adapter: its credentials,
atomic datastore, retention, backup, and independent access control remain
production prerequisites.

The gates are release policy, not caller options: `traffic.sh`
rejects attempts to relax them. They are a 10-minute
dwell, at least 100 requests and three readiness samples, error rate at most
1%, p95 latency at most 500 ms, readiness at least 99%, indeterminate rate at
most 0.5%, sample gaps at most five minutes, and telemetry no older than 15
minutes.

Sign an already collected closed telemetry document before promotion:

```sh
deploy/consequence-control-cloud-run/verify-rollout-telemetry.py sign \
  --config /tmp/emilia-cloud-run.env \
  --input /secure/emilia/rollout-telemetry-unsigned.json \
  --output /secure/emilia/rollout-telemetry.json \
  --private-key-file /secure/emilia/rollout-observer-ed25519-private.pem
```

The signer checks that the private key matches the pinned public key and writes
the signed result atomically with mode `0600`. It refuses an existing output
unless `--force` is explicit. The unsigned input must already contain the
strict v2 context and the SHA-256 of the externally consumed authorization.

Cloud Run traffic is changed through a generation/resourceVersion-locked API
update. The only accepted promotion path is stable -> decision 1% -> 10% ->
50% -> 100% -> actuator 100%. Mutations require the exact protected main-branch
workflow and SHA, protected environment, WIF provider, active deployer, and
direct custom-role custody of `run.services.update`; service and effective IAM
must remain closed. The final request is canonicalized and hashed before
authorization, retained as immutable in-memory bytes, and streamed directly to
the API.

After each mutation, both services are read back. Full target validation is
locked to the exact resourceVersion and generation returned by the update
acknowledgement, while the non-target service must retain its exact generation
and resourceVersion. An ambiguous HTTP response is reconciled once against the
locked pre-state and intended post-state, recorded durably as `applied`,
`not-applied`, or `indeterminate`, and never replayed with the consumed
authorization. Config, stable release, IAM, secrets, and both service locks are
checked immediately before the PUT, then config, IAM, secrets, and exact
service states are checked again after settled read-back.

```sh
DEPLOYMENT_CONFIG_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
DEPLOYMENT_APPROVED=true \
deploy/consequence-control-cloud-run/traffic.sh \
  --config /tmp/emilia-traffic.env \
  --evidence /secure/emilia/canary-evidence.json \
  --telemetry /secure/emilia/rollout-telemetry.json \
  --authorization /secure/emilia/rollout-authorization.json \
  --stable-manifest /secure/emilia/stable-release.json \
  --apply-decision-1
```

Repeat with fresh telemetry for `--apply-decision-10`,
`--apply-decision-50`, `--apply-decision-100`, and finally
`--apply-actuator-100`. For file trust, add
`--stable-public-key /secure/emilia/stable-release-ed25519-public.pem` to every
apply. `--apply-rollback` accepts only a recognized rollout state and restores
actuator first, then decision. A rollback invocation performs at most one
traffic mutation; if both services require restoration, the decision step
requires a newly consumed authorization and a second invocation after the
actuator read-back is complete.

## Credential and infrastructure blockers

An apply remains blocked until all of the following exist:

- Google Cloud credentials with permission to manage Cloud Run services,
  runtime service accounts, service-level Invoker IAM, and per-secret IAM,
  with `actAs` granted just in time only on the two runtime identities;
- a distinct active provisioner service account, a distinct deployer service
  account, and at least two independently controlled recovery principals;
- organization-level Policy Analyzer visibility and an explicit
  `--analyzer-scope organizations/NUMBER` whenever the project has any parent
  folder or organization;
- the exact configured `/26` Direct VPC egress subnet with the routing/DNS needed for
  internal Cloud Run service-to-service access;
- every configured Secret Manager secret and numeric version;
- a dedicated actuator database login whose session user exactly matches
  `EMILIA_ACTUATOR_DATABASE_PRINCIPAL` and is a tenant-mapped member of
  `consequence_actuator_executor`;
- distinct decision executor and recovery database principals;
- a repository-scoped GitHub App installation with Issues read/write;
- paired envelope and observation keys placed only on their intended sides;
- a separately controlled Ed25519 canary-driver key and pinned public-key file;
- a separately controlled Ed25519 rollout-observer key and pinned public-key
  file/hash;
- a distinct rollout-authorization Ed25519 authority and pinned public-key
  file/hash;
- an independently protected source for the exact deployment-config SHA-256;
- a durable rollout-authorization issuer that atomically consumes each
  authorization ID/nonce before signing the short-lived receipt;
- the rollout-attempt-store migration applied to a durable PostgreSQL database,
  a dedicated least-privilege executor login, and its protected database URL;
- the exact protected GitHub workflow/environment/WIF/deployer path with sole
  direct `run.services.update` custody;
- digest-pinned actuator and decision images; and
- a current, cryptographically valid canary scenario produced through the
  approval and AEB pipeline.

The provisioning and stable-bootstrap commands create only infrastructure,
identities, and deny-all stable revisions. No command in this tree creates
database roles, secret payloads, GitHub credentials, candidate images,
migrations, or approval/evidence fixtures.

## Focused validation

```sh
deploy/consequence-control-cloud-run/test.sh
```

The test suite uses Bash, ShellCheck, Python, and OpenSSL. It renders deployment
and traffic plans with fixture secret references, verifies exact IAM
reconciliation plus inherited effective-IAM refusal, conditional JIT expiry
and cleanup, permissionless stable bootstrap, trust-root pinning, complete
Cloud Run configuration, credential separation, enabled numeric secrets,
digest/provenance pinning, signed fresh/stale canary evidence,
generation-locked rollout transitions, telemetry/dwell gates, and live
revision binding with a local fake `gcloud`; it does not contact Google Cloud.
