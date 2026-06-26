# PIP-016 — `devops.*` Change-Control Profile

**Status:** Shipped-tier spec (promoted from reserved in the action-type registry).
**Builds on:** `draft-schrock-ep-authorization-receipts` (EP-RECEIPT-v1), `draft-schrock-ep-enforcement-point` (the gate), PIP-013 (human-oversight), PIP-012 (registry).
**Reference:** `@emilia-protocol/gate` + `@emilia-protocol/require-receipt`; CI conformance via `receiptRequiredConformance()` (RR-1).
**Why this one first:** production change control is the closest profile to the developer wedge —
it maps to SOC 2 / SOX / incident-review, and the actions are everyday and high-blast-radius.

## Purpose

Bind a named human (or quorum) to the irreversible *production-change* actions an autonomous agent
or pipeline can take, so each one carries offline-verifiable proof of who authorized it. "No deploy,
migration, secret rotation, or permission grant without a receipt."

## Action-type family

| `action_type` | The irreversible act | Assurance floor |
|---|---|---|
| `devops.deploy` | Promote a build/artifact to a protected environment (prod) | class_a |
| `devops.migration` | Apply a schema/data migration to a protected datastore | class_a |
| `devops.secret_rotation` | Rotate/replace a credential, key, or token | class_a |
| `devops.permission_grant` | Grant/modify a role, scope, or access-control entry | class_a → **quorum** for admin/root or break-glass |
| `devops.infra_apply` | Apply infrastructure changes (e.g. `terraform apply`) to prod | class_a |
| `devops.resource_delete` | Delete a production resource / data store | **quorum** |

## Action object (fields beyond the EP core)

```json
{
  "action_type": "devops.deploy",
  "effect_class": "production_change",
  "environment": "prod",
  "target": "service:payments-api",
  "change_ref": "git:sha256:<commit>",        // deploy/migration/iac: the exact change
  "diff_digest": "sha256:<canonical-plan>",    // e.g. terraform plan / migration DDL digest
  "blast_radius": "service|datastore|org",
  "window": { "not_before": "...", "not_after": "..." },
  "expires_at": "..."
}
```

The signature covers the canonical action including `change_ref` / `diff_digest`, so the receipt
authorizes *this exact change*, not "a deploy" — alter the plan and verification fails.

## Where it runs

At the change boundary, deny-by-default: CI/CD step, IaC apply hook, IAM/permission API,
secrets-manager rotation, or DB-migration runner. Missing/insufficient receipt → `428 Receipt
Required`. On execution, emit an **execution receipt** (gate `recordExecution`) bound to the
authorization — the artifact an auditor or incident review replays.

## Compliance crosswalk

- **SOC 2** CC-series (change management, logical access): receipts are the human-authorization evidence for privileged changes.
- **SOX** ITGC (change management / access): non-repudiable signoff on prod changes affecting financial systems.
- **Incident review:** the decision + execution receipts reconstruct "who authorized this change, when, under what policy."

## Conformance

RR-1: missing receipt refused · valid runs · replay refused · forged refused — run
`receiptRequiredConformance()` against the guarded dispatcher. Quorum-floor actions additionally
require an m-of-n receipt (EP-QUORUM).
