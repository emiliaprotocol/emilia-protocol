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
and an application bearer token readable only by the two runtime service
accounts. The decision client keeps the application token in `Authorization`
and obtains a Google-signed ID token through Application Default Credentials
for the actuator's canonical service URL. It sends that identity token in
`X-Serverless-Authorization`. Acquisition failure is fail-closed; there is no
application-token-only fallback and no direct metadata URL handling.

The actuator is deployed with `--no-allow-unauthenticated`. The deployment lane
grants `roles/run.invoker` only to the decision runtime service account and
never grants `allUsers` or `allAuthenticatedUsers`. The exact tagged actuator
URL remains the request destination, while the canonical service URL remains
the pinned ID-token audience, including during canary traffic.

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

```sh
cp deploy/consequence-control-cloud-run/config.example.env /tmp/emilia-cloud-run.env
# Replace non-secret deployment coordinates and secret-name:version references.
deploy/consequence-control-cloud-run/deploy.sh \
  --config /tmp/emilia-cloud-run.env \
  --render

deploy/consequence-control-cloud-run/traffic.sh \
  --config /tmp/emilia-cloud-run.env \
  --render-promote
```

Rendering is the default-safe operation. Applying requires both `--apply` and
`DEPLOYMENT_APPROVED=true`. This repository change does not grant deployment
approval.

## Apply order

`deploy.sh --apply` is deliberately ordered:

1. verify APIs, pre-existing secrets, service accounts, and secret-level IAM;
2. deploy the actuator candidate by exact digest with zero traffic and a
   revision tag;
3. grant the decision service account `roles/run.invoker` on the actuator;
4. resolve the actuator's canonical service URL for the token audience and the
   exact tag URL for the request destination;
5. deploy the decision candidate by exact digest with zero traffic, configured
   to call the tagged actuator revision with dual-header authentication;
6. stop without changing production traffic.

The actuator must be reachable through the configured VPC path. Cloud Run calls
to an internal-ingress service must route through a VPC considered internal, so
both services use the configured network/subnet and `all-traffic` Direct VPC
egress.

## Canary contract

Before any traffic shift, collect a canary evidence JSON document for the exact
candidate revision names and image digests. It must contain these closed
observations:

```json
{
  "evidence_status": "observed",
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
  }
}
```

Validate it locally:

```sh
deploy/consequence-control-cloud-run/verify-canary.py \
  --config /tmp/emilia-cloud-run.env \
  --evidence /secure/path/canary-evidence.json
```

The verifier rejects templates, mismatched revisions or digests, a timeout that
does not become `INDETERMINATE`, replay that is not refused as
`envelope_replayed`, provider invocation counts other than one, and
reconciliation that re-executes or overclaims GitHub attempt attribution.

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

## Credential and infrastructure blockers

An apply remains blocked until all of the following exist:

- Google Cloud credentials with permission to manage Cloud Run services,
  runtime service accounts, service-level Invoker IAM, and per-secret IAM;
- a `/26` or larger Direct VPC egress subnet with the routing/DNS needed for
  internal Cloud Run service-to-service access;
- every configured Secret Manager secret and numeric version;
- a dedicated actuator database login whose session user exactly matches
  `EMILIA_ACTUATOR_DATABASE_PRINCIPAL` and is a tenant-mapped member of
  `consequence_actuator_executor`;
- distinct decision executor and recovery database principals;
- a repository-scoped GitHub App installation with Issues read/write;
- paired envelope and observation keys placed only on their intended sides;
- digest-pinned actuator and decision images; and
- an external canary driver capable of producing the closed evidence contract.

No command in this tree creates database roles, secret payloads, GitHub
credentials, images, migrations, or approval/evidence fixtures.

## Focused validation

```sh
deploy/consequence-control-cloud-run/test.sh
```

The test suite uses only Bash, ShellCheck, and the Python standard library. It
renders deployment and traffic plans with fixture secret references, verifies
credential separation and digest pinning, checks the canary contract, and does
not call `gcloud`.
