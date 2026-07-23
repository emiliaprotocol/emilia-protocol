<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/gate` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 0.15.0 (2026-07-22)

### Added

- `./proposal-to-effect`, an orchestration profile over CAID, the existing
  `EP-APPROVAL-v1` acquisition rail, signed AEB evaluation, Gate authorization,
  durable operation reservation, exact effect invocation, and authenticated
  reconciliation.
- An executable end-to-end example and profile vectors covering exact-action
  mutation, stale evidence, one-time replay, indeterminate effects, and
  post-effect commit failure.
- `./aeb-consumption-store`, a tenant- and relying-party-namespaced PostgreSQL
  store that atomically fences the AEB operation and all native replay units,
  with opaque owner tokens and authorized restart recovery.
- `./proposal-to-effect-status`, which verifies server-resolved
  `EP-STATUS-v1` heads and separately requires authenticated local consumption
  state before the atomic execution reservation.
- `./proposal-to-effect-postgres`, a private-schema PostgreSQL store for
  consequence attempts with HMAC-hidden owner capabilities, tenant/provider
  namespaces, owner-fenced transitions, immutable terminal states, exact
  provider-evidence reconciliation, database leases, disjoint executor and
  recovery roles, tenant-principal bindings, and stale-only restart recovery.
- Concrete Remedy Program evidence adapters for signed disputes,
  authorizations, provider outcomes, Action Escrow state, and late revocation.
- A heterogeneous remedy case-set coordinator that completes only after every
  exact child state and signed remedy receipt verifies.
- A PostgreSQL remedy case-set store with tenant RLS, immutable manifests,
  append-only state events, database-clock custody, and owner/revision CAS.

### Security

- A proposal is explicitly non-authoritative and carries no signature, permit,
  or presenter-controlled authorization decision.
- AEB and Gate make independent, fail-closed decisions over the same operation,
  initiator, CAID, normalized action, and relying-party pins.
- Once an effect may have executed, failed bookkeeping cannot release its AEB
  reservation. The operation remains frozen until authenticated provider
  evidence proves `COMMITTED` or `NOT_COMMITTED`.
- A committed effect consumes AEB replay authority before its consequence row
  becomes terminal. `repairAeb` converges legacy or crash-window terminal rows
  without invoking an effect, and opaque attempt-owner capabilities are kept
  out of enumerable results and errors.
- A recovered worker receives a rotated owner capability; the stale worker can
  no longer transition or reconcile the attempt. An in-flight attempt is
  conservatively recovered as `INDETERMINATE`, never retried as unexecuted.
- AEB production consumption state is RPC-only behind tenant-bound, no-bypass
  executor and recovery roles with physically separate pools. Supabase
  `service_role` and both runtime roles have no direct table authority;
  in-memory stores remain test-only.
- Remedy case-set state and append-only history are likewise RPC-only behind a
  tenant-bound no-bypass executor; generic service credentials cannot rewrite
  current or historical remedy state.

## 0.13.0 (2026-07-20)

### Added

- A receipt-program execution kernel that composes CAID matching, Gate
  authorization, bounded capability reservation, provider execution,
  execution evidence, and an operator-signed content-addressed certificate.
- Offline certificate verification under a separately pinned operator key,
  context, and evidence record, including CAID re-performance, exact schemas and
  instruction sequencing, result digest, action/operation binding, and Gate
  evidence-record references.
- A tenant-bound Trust Program kernel for staged, ordered or threshold
  authorization ceremonies, with durable Postgres state, revocation handling,
  exact predecessor/evidence bindings, and tenant-wide replay refusal.
- Explicit `executed`, `refused`, and `indeterminate` terminal states. Provider
  timeout and non-canonical provider output halt the operation without restoring
  replay authority.

### Security

- Production construction requires both a durable atomic evidence log and a
  durable capability store, an external KMS/HSM signer, pinned certificate
  context, pinned result projector, and finite provider deadline. Process-local
  state and keys are available only behind an explicit test/demo opt-in.
- CAID resolution, operation-id field selection, certificate signing and
  context, result projection, deadline, clock, and Gate trust are
  constructor-pinned; runtime requests cannot replace them.
- Provider code receives deep-frozen snapshots rather than Gate's live
  authorization objects. Complete certificates are appended to the atomic
  evidence log, and signer/persistence failures preserve Gate's terminal state
  without issuing contradictory proof.
- The certificate is an operator-signed integrity and binding artifact. It is
  not a zero-knowledge proof and does not attest that an external provider's
  statement is truthful.

## 0.12.0 (2026-07-18)

### Added

- A distinct contractor release-template profile that requires a signed
  `project_record_snapshot_digest` while preserving the closed legacy profile.
- A contractor evidence-package profile that carries and re-verifies the exact
  project-record sidecar bytes under a relying-party-owned verifier.
- A read-only Procore change-order source adapter with complete pagination and
  stable double-fetch snapshots.

### Security

- A project-system source record cannot become agreement acceptance or release
  authority. Replacing its committed snapshot changes the action digest and
  fails closed.
- Existing Action Escrow templates without a project source remain valid under
  their original closed profile; new contractor artifacts use an explicit
  version boundary and cannot be silently downgraded.
- Unmarked project-bound artifacts from the unreleased `0.11.1` preview remain
  readable only through the contractor package path, which requires the exact
  project-record sidecar and a relying-party-owned source verifier.

## 0.11.0 (2026-07-17)

### Added

- Action Escrow modules for exact document/action binding, evidence
  verification, a signed lifecycle state machine, durable Postgres state and
  journal storage, licensed-custodian adapters, portable assurance packages,
  and fail-closed release enforcement.
- Public package exports for `action-escrow`, `action-escrow-state`,
  `action-escrow-postgres`, `action-escrow-custodian`,
  `action-escrow-package`, and `action-escrow-verifiers`.

### Security

- Release requires exact profile, party, final-document, material-term,
  funding, milestone, action, and approval binding under relying-party-pinned
  policy.
- Release approvals are fresh and action-specific, release is consumed once,
  storage failure refuses, and an ambiguous provider effect enters
  reconciliation instead of being retried.
- Release approvals now use the canonical `EP-RESOLUTION-v1` binding-moment
  hash, relying-party-pinned option mapping, initiator, per-party nonce, and
  evaluation time. The reference scenario uses real WebAuthn-shaped P-256
  signatures rather than a resolution-like demo envelope.
- Runtime roles cannot also act as contract parties. Provider and effect
  references are fenced to prevent substitution across actions or sessions.

### Distribution

- Gate now depends on `@emilia-protocol/verify` 3.11.0 and
  `@emilia-protocol/require-receipt` 0.6.1. All shipped imports remain within
  declared package boundaries.

## 0.10.0 (2026-07-16)

### Added

- The EMILIA Gate consequence-control plane, including action coverage,
  settlement, metering, deployment-attestation, network-witness, SIEM, and
  control-plane modules.
- A BYOC GitHub repository-deletion service with complete mediation, strict
  receipt ingress, durable Postgres action/consumption/evidence state,
  authenticated evidence reads, bounded readiness, graceful shutdown, and
  fail-closed recovery of interrupted effects.
- Helm, Terraform, Docker Compose, and SQL deployment assets for the BYOC
  service. Production assets require explicit non-latest images, separate
  runtime and migration credentials, and operator-owned trust configuration.

### Security

- Pinned issuer, approver, policy, actuator, meter, attestation, and
  network-witness trust roots are kept outside presenter-controlled evidence.
- Signed negative human decisions remain durable evidence but cannot satisfy
  authorization, signer, assurance, authority, quorum, or action-material
  predicates.
- Mobile approval and denial evidence is bound to the exact action, profile,
  presentation, app, device enrollment, RP, origin, and single-use challenge.
- A same-sequence network-witness conflict permanently poisons that exact
  witness/capture-point stream. Higher sequence numbers cannot restore trust;
  recovery requires an explicitly provisioned replacement stream identity.
- Ambiguous external effects burn their receipt and become `indeterminate`;
  Gate never retries a consequential effect whose outcome is unknown.

### Distribution

- Gate now declares the exact `@emilia-protocol/require-receipt` and
  `@emilia-protocol/verify` release bytes it imports. The verifier floor is
  `3.10.1`, which includes the signed-denial authorization fix.
- The npm package now carries this changelog and the Apache-2.0 license text.

## 0.9.2 (2026-07-06)

### Added
`EP-EXTERNAL-VERIFICATION-STATEMENT-v1` (`./reports/external-verification`): the
artifact a non-EMILIA verifier signs after checking EP evidence. It records a
procedure, inputs, result, and limitations under the verifier's own Ed25519 key,
and is accepted only by a relying party pinning that key together with the
verifier identity out of band. It does not authorize an action or certify
correctness. A turnkey harness for issuing one over a conformance run lives in
`examples/external-verification/`.

### Fixed
`./reports/external-verification` imported `canonicalize` from outside the
package root, which made the published tarball unloadable
(`ERR_MODULE_NOT_FOUND`) for every consumer, including the package main entry.
It now imports the byte-identical in-package `canonicalize`. A new
`package-boundary` test fails closed if any shipped module ever again resolves a
relative import outside the package root.

### Security
Verification hardening (fail-closed): a pin must name the `verifier_id` it
vouches for, so a pinned key can never validate a different claimed identity
(`pin_missing_or_mismatched_verifier_id`); `key_id` is derived from the carried
public key and a mismatched envelope `key_id` is refused (`key_id_mismatch`),
since the envelope is outside the signed bytes. Default statement limitations now
disclose that a statement carries no expiry and no consumer binding, is
replayable verbatim, and that `generated_at` is signer-asserted, not verified.
