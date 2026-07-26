# Healthcare Consequence-Control Pilot

Status: public synthetic pilot profile. This document does not describe a live
Medicare, Medi-Cal, insurer, provider, clinical, banking, or payment-rail
integration.

## Scope

This profile connects a commercial scanner's prospective control package to the
existing EMILIA Proposal-to-Effect lifecycle for one narrow relying-party
action: a governed hospice payment administrative mutation in an injected
sandbox callback.

The scanner output is triage provenance. In particular, `sourceFinding`:

- does not prove historical or current prior authorization;
- does not authorize execution of the scanned record;
- is not clinical judgment, a fraud determination, or payment authority; and
- is not supplied to Gate or AEB as approval evidence.

Execution authority must come later from exact-action approval evidence and a
fresh, satisfying AEB evaluation under the relying party's pinned configuration.

## Exact scanner input

The public profile accepts
`emilia.commercial.prospective-control-package.v1`. It validates the package
digest and these boundary declarations without weakening or silently dropping
them:

```json
{
  "claimBoundary": "prospective_control_from_triage_not_historical_authorization_or_fraud_proof",
  "controlPurpose": "new_future_action_pre_effect_control",
  "retroactiveAuthorization": "none",
  "sourceFinding": {
    "role": "retrospective_triage_evidence_only",
    "provesHistoricalAuthorization": false,
    "provesFraud": false,
    "authorizesScannedExecution": false
  }
}
```

`tenantId`, the action's `organization_id`, the authenticated tenant, the policy
projection, `caid`, and `actionDigest` must all agree. The package requires raw
PHI to be absent and `member_ref` to be a pairwise pseudonymous commitment.

Field-name normalization is case-insensitive and separator-insensitive as a
defense-in-depth control. Aliases including `SSN`, `patientName`,
`PATIENT-NAME`, `freeText`, and `FREE_TEXT` are refused. This filtering is not
proof that PHI is absent. A deployment still needs source-system data
classification, DLP, access control, retention controls, and authorized privacy
review; values can contain PHI even when their field names look harmless.

The exact action contract is:

```json
{
  "@version": "EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1",
  "profile_id": "medi-cal.hospice-integrity.v1",
  "action_type": "health.medi-cal.hospice-claim-payment.1",
  "organization_id": "string",
  "provider_npi": "10 digit string",
  "member_ref": "member:sha256:<64 lowercase hex>",
  "service_period_start": "YYYY-MM-DD",
  "service_period_end": "YYYY-MM-DD",
  "authorization_form_digest": "sha256:<64 lowercase hex>",
  "amount": "canonical positive decimal string with two places",
  "currency": "USD",
  "payment_destination_digest": "sha256:<64 lowercase hex>",
  "reviewer_id": "string",
  "authority_proof_digest": "sha256:<64 lowercase hex>",
  "policy_id": "string",
  "policy_version": 1,
  "policy_hash": "sha256:<64 lowercase hex>"
}
```

No optional action fields are accepted. Missing, extra, malformed, or
conflicting fields fail before a proposal is created.

## CAID action definition

The exported `HOSPICE_CAID_DEFINITION` is the normative profile definition for
the cross-repository vector. The CAID action type is
`health.medi-cal.hospice-claim-payment.1`, with these required fields in order:

| Field | CAID type |
| --- | --- |
| `@version` | `string` |
| `profile_id` | `string` |
| `organization_id` | `string` |
| `provider_npi` | `string` |
| `member_ref` | `string` |
| `service_period_start` | `string` |
| `service_period_end` | `string` |
| `authorization_form_digest` | `digest` |
| `amount` | `amount-string` |
| `currency` | `enum: USD` |
| `payment_destination_digest` | `digest` |
| `reviewer_id` | `string` |
| `authority_proof_digest` | `digest` |
| `policy_id` | `string` |
| `policy_version` | `integer` |
| `policy_hash` | `digest` |

There are no optional CAID fields. For the fixed synthetic action in
`conformance/vectors/health-proposal-to-effect.v1.json`, the expected values
are:

```text
caid:1:health.medi-cal.hospice-claim-payment.1:jcs-sha256:NrSSZNCIjm7jMWQufBWCRkXixrr8zuuG2c1Zm9qjzx8
sha256:36b49264d0888e6ee331642e7c15824645e2c6bafcceeb86d9cd599bdaa3cf1f
```

## Connected lifecycle

The healthcare module does not create a parallel execution state machine.
Proposal-to-Effect, AEB, AEC, and Gate retain their protocol meanings:

1. The scanner package is validated and normalized into a non-authorizing
   provenance projection.
2. The exact action becomes a signed/integrity-protected Proposal-to-Effect
   request with a server-derived operation and consequence binding.
3. Gate verifies exact-action approval evidence. AEB independently verifies,
   maps, satisfies, authorizes, and reserves one-time evidence.
4. Proposal-to-Effect reserves the exact consequence attempt before entering
   the injected sandbox mutation callback.
5. A completed protected callback produces `EXECUTED`.
6. A timeout or exception after provider entry produces `INDETERMINATE`.
   It never produces a guessed success or a retry recommendation.
7. An indeterminate attempt is frozen. Repeating `execute` is not a replay
   mechanism and must not invoke the mutation again.
8. Reconciliation accepts only provider evidence authenticated by the
   deployment verifier and bound to the same tenant, operation, attempt,
   request digest, provider/account/environment, CAID, and action digest.

The public response exposes the non-secret attempt binding needed to request
reconciliation. The owner/fencing capability remains in a server-only store.

## HTTP adapters and deployment

`POST /api/v1/adapters/health/hospice-claim/execute` accepts three explicit
operations:

- `prepare` with `organization_id`, `proposal_id`, `operation_id`, and
  `prospective_control_package`;
- `execute` with `organization_id`, `proposal`, `approval_evidence`,
  `evaluation`, and `observed_action`; and
- `reconcile` with `organization_id`, `operation_id`, `proposal`, `evaluation`,
  and `provider_evidence`.

`GET /api/v1/adapters/health/hospice-claim/export` requires tenant-bound
authentication plus `organization_id` and `operation_id` query parameters.

Both adapters reject missing authentication, entities without an organization
binding, and cross-tenant identifiers. Reconciliation through the HTTP route is
therefore unavailable to anonymous callers even if they possess an attempt ID.

The adapters resolve a deployment-supplied control instance from
`Symbol.for("emilia.health.hospice-claim.proposal-to-effect-control.v1")`.
They do not construct ephemeral stores, default trust roots, signing keys, or
provider credentials. Tests use the exported handler factories for dependency
injection. Production must inject:

- a configured Proposal-to-Effect controller;
- a durable, ownership-fenced AEB reservation store;
- a durable, compare-and-swap consequence-attempt store;
- a durable append-only, tenant-bound evidence store;
- a durable server-only reconciliation-handle store;
- current-status and authenticated-provider-evidence verifiers; and
- four distinct KMS/HSM-backed Ed25519 assurance signers for the evaluator,
  receipt-verifier, AEB-verifier, and provider-verifier roles; and
- a protected callback that is technically restricted to the intended
  synthetic sandbox.

## Assurance packet

The authenticated export is available only for exact Proposal-to-Effect
terminal states:

- `EXECUTED` requires `COMMITTED`;
- `RECONCILED_EXECUTED` requires `COMMITTED` plus authenticated provider
  evidence with provider outcome `COMMITTED`; and
- `RECONCILED_NOT_EXECUTED` requires `RELEASED` plus authenticated provider
  evidence with provider outcome `NOT_COMMITTED`.

`INDETERMINATE` remains fenced and is not exported as a terminal assurance
packet. Outcome labels cannot substitute for the Proposal-to-Effect state.

The packet contains strict allowlisted projections and cryptographic digests,
not the raw scanner package, action, proposal, receipt, AEB evaluation, or
provider evidence. The receipt, AEB, and reconciled-provider projections are
signed under distinct role keys. An evaluator key signs the complete terminal
packet. Public keys are never accepted from the packet.

`checkHealthcareAssurancePacketInternalConsistency` checks shape, digest, and
cross-field consistency only. It deliberately does not call itself a verifier
and does not establish authenticity. A relying party performs the actual
offline check with `verifyHealthcareAssurancePacketOffline`, supplying an
out-of-band trust bundle that pins four distinct Ed25519 SPKI keys:
`evaluator`, `receipt`, `aeb`, and `provider`. Role substitution, an unpinned
key, a malformed signature, a recomputed digest after outcome substitution, or
a reconciled outcome without the provider assertion fails closed.

The packet can support re-performance under relying-party trust pins. It is not
an audit opinion, certification, population-completeness assertion, clinical
conclusion, or proof of a real payment. `EXECUTED` means only that the configured
protected sandbox callback completed and Proposal-to-Effect committed that exact
attempt. Safe projection and field filtering reduce exposure; they do not prove
PHI absence.
