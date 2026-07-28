<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/gate` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 0.20.0 (2026-07-28)

### Added

- A separately signed Loss-Allocation Schedule pinned to an exact Reliance
  Program through a relying-party-owned Admissibility Profile.
- An Open Exposure Ledger with aggregate ceilings across tenant, program,
  counterparty, and action class; durable PostgreSQL custody; and mandatory
  independent reconciliation for indeterminate execution.
- Exact-action signed refusal statements with atomic replay acceptance and
  optional delivery, custody, and transparency evidence references.
- Period Coverage Reconciliation Attestations, governed-taxonomy Receipt Census
  aggregates with coarse primary suppression, and signed external Loss
  Experience Feeds with trusted correction lineage.
- A bounded composed lifecycle model and runtime-refinement trace covering
  admission, exposure reservation, invocation, uncertainty, reconciliation,
  refusal, and terminal-state preservation.

### Security

- Loss schedules, refusal statements, coverage attestations, and loss feeds
  remain separate from authorization and cannot create execution authority.
- Open exposure remains reserved through `INVOKING` and `INDETERMINATE`; there
  is no blind release or retry, and origin, executor, and reconciler authority
  must remain distinct.
- Coverage and census artifacts reconcile only supplied populations. They do
  not establish completeness, causation, insurance coverage, legal liability,
  adjudicated loss, solvency, or payment.

## 0.19.0 (2026-07-28)

### Added

- `./reliance-program`, a closed, relying-party-signed source policy and
  deterministic compiler to the existing
  `EP-GATE-TRUST-PROGRAM-PROFILE-v1` wire format.
- Admissibility Profile references as digest-pinned program fragments, with a
  relying-party-owned evaluator adapter that prevents presenters from choosing
  the acceptance bar.
- A public JSON Schema, compiler trace, and explicit consequence ownership by
  either a receipt program or Action Escrow.

### Security

- Gate now pins the independently published
  `@emilia-protocol/verify@3.17.0` registry tarball. Reliance Program decision
  citations therefore execute against the exact AEB/AEC verifier release whose
  bytes are recorded in the governed package registry.
- Compilation requires an Ed25519 signer whose pinned key is bound to the
  named relying party, recomputes every profile self-hash, and refuses unknown
  fields, substituted profiles, disconnected stages, action drift, and
  ambiguous consequence ownership.
- Compilation proves only that the signed source maps to the existing Trust
  Program. It does not assert evidence sufficiency, authorization, provider
  outcome, observed effect, or deployment completion.

## 0.18.2 (2026-07-27)

### Added

- `./referee`, a closed, non-authorizing `EP-REFEREE-RESULT-v1` self-test
  evaluator that preserves native verification, relying-party acceptance,
  exact-action matching, evidence satisfaction, provider outcome, and observed
  effect as separate dimensions.
- `./referee-runner`, a no-shell local subprocess transport with strict JSON,
  executable SHA-256 verification, bounded input/output and time, and
  fail-closed handling for malformed or ambiguous runner behavior.

### Security

- Referee results are fixed to `claim_scope: SELF_TEST` and
  `execution_authorizing: false`; they cannot authorize, reserve, invoke, or
  certify an action.
- The transport is not an operating-system sandbox and makes no claim to block
  runner network, filesystem, syscall, or descendant-process access.
- Retained the independently published
  `@emilia-protocol/verify@3.16.0` registry dependency. Referee does not depend
  on the new Verify AEB-1 reference runner, so Gate keeps its release graph
  honest instead of declaring an unnecessary coupled upgrade.

## 0.18.1 (2026-07-27)

### Fixed

- Repinned the release dependency to the exact published
  `@emilia-protocol/verify@3.16.0` registry tarball. No runtime or API behavior
  changed from 0.18.0; the protected 0.18.0 tag was never published.

## 0.18.0 (2026-07-26)

### Added

- `./gate-qualification-v2`, with pure qualification/AEB/AEC/local-policy
  composition plus shadow, enforcement, and evidence-only reconciliation
  orchestration around a protected adapter.
- `./admission-store`, a unified immutable admission snapshot, CAS-owned
  lifecycle, one-time execution right, operation/resource fencing,
  predecessor-digest journal, supersession, and remedy reference contract.
- `./admission-store-postgres`, a deployment-bound PostgreSQL RPC adapter for
  the unified store with single-tenant construction, exact output validation,
  bounded transaction retries, and ambiguous-begin readback handling.
- Root-package re-exports, generated declarations, compatibility entry points,
  and focused package tests for the qualification and admission modules.

### Security

- Qualification remains non-authorizing and cannot replace AEB, AEC, or the
  relying party's local authorization policy.
- Authority is consumed before provider entry; uncertain outcomes remain
  reconciliation-required and cannot be blindly retried.
- The checked-in memory store is an explicit test-only, non-durable reference.
  The orchestrator and PostgreSQL adapter consume the canonical unified
  `AdmissionStore` contract.
- Enforcement requires authoritative immediate remeasurement of the candidate,
  qualification status, AEB, AEC, local policy, and protected request before
  transactional consumption. It also requires protected restart-safe custody
  for owner and reconciliation capabilities; memory custody is test-only.
- Qualification decisions bind the exact protected-request digest and cannot
  be replayed across another otherwise-valid admission.
- The PostgreSQL adapter is a single-tenant public reference. Managed
  tenant-principal mapping, deployment migrations, federated atomicity, and
  managed service operation are not claimed.

## 0.17.0 (2026-07-26)

### Added

- `./autonomy-control-plane-profile`, a closed compiler from a human-signed
  root objective into one existing Gate Trust Program per exact child action.
- Typed containment for child actions, audiences, expiries, per-child and
  aggregate sibling budgets, exact code-diff bindings, independent
  proposer/evaluator/executor roles, pinned fitness evidence, bounded canary
  promotion, current suspension status, and separately authorized rollback.
- A bounded TLA+ model and deliberately unsafe self-expansion configuration;
  the safe model checks authority conservation while the negative control
  falsifies it when an agent can grant itself a new action and budget.

### Security

- Unknown profile fields, cyclic goal derivation, role collapse, stale or
  unpinned fitness/status evidence, promotion without canary evidence, and
  rollback under a reused CAID fail closed.
- The claim boundary explicitly excludes natural-language goal entailment,
  provider truth, test adequacy, clocks, storage, and deployment completion.

## 0.16.1 (2026-07-26)

### Fixed

- PostgreSQL 17 role-graph checks now distinguish provider-managed
  administrative grants from executable `INHERIT` or `SET` authority, while
  continuing to reject every usable owner/executor or privileged-role path.
- Forward migrations remove their own temporary owner grant without deleting
  a managed provider's non-usable administrative grant.
- The protected npm publisher uses an explicit local tarball file spec.

## 0.16.0 (2026-07-25)

### Added

- `./consequence-actuator`, a short-lived signed execution-envelope boundary
  for separately deployed credential-owning actuators, with immutable tenant,
  action, CAID, provider account, target, operation, attempt, idempotency,
  nonce, and expiry bindings.
- A PostgreSQL RPC-only permanent envelope store with tenant-principal
  isolation, forced RLS, no direct runtime or `service_role` table authority,
  and no release path after provider invocation.
- `./discovery-permit-resolver`, which retrieves pinned action-control
  discovery without redirect, network-boundary, freshness, or source drift.
- A split managed reference deployment where the decision service owns policy
  and envelope signing while the actuator alone owns provider credentials and
  signs exact execution observations.

### Security

- A provider timeout consumes the execution envelope as `INDETERMINATE`; blind
  replay is refused and only authenticated, attempt-bound evidence may
  reconcile the Proposal-to-Effect lifecycle.
- Production actuator construction requires an atomic, durable,
  ownership-fenced, permanently consuming store. Process-local storage is
  available only through an explicit test-only opt-in.
- The decision process has no provider credential or provider API
  implementation. Signed actuator observations are verified under a pinned key
  and exact execution tuple before use as lifecycle evidence.

## 0.15.2 (2026-07-23)

### Fixed

- Proposal-to-Effect recovery snapshots now preserve PostgreSQL microseconds
  for the exact lease compare-and-swap fence. The previous millisecond
  serialization could make a stale attempt conflict with its own stored lease
  and remain permanently unrecoverable.
- The managed consequence-control readiness gate verifies that the live
  `read_attempt` RPC carries the required microsecond-precision contract
  before admitting traffic.

## 0.15.1 (2026-07-23)

### Added

- A tenant-authenticated `hasReplayFence()` observation on the durable AEB
  consumption store. It reports an exact native replay unit as unavailable
  when either a reserved or permanently consumed fence exists.
- Durable accepted `EP-STATUS-v1` head custody, scoped by tenant, relying
  party, and complete status target, with database-side compare-and-advance.
- A tenant-authorized Proposal-to-Effect attempt lookup over the immutable
  provider tuple and request digest, so a lost indeterminate HTTP response can
  be rediscovered without invoking the effect again or rotating recovery
  ownership.

### Security

- Proposal-to-Effect status verification can now obtain exact, server-side
  replay state without granting direct table access. The observation is a
  preflight check; the immediately following atomic reservation remains the
  race-closing authority boundary.
- Proposal-to-Effect no longer accepts a caller-configurable previous-head
  resolver. Status candidates are verified against the relying party's stored
  predecessor and admitted only if that head still wins an atomic comparison.
- The production readiness contract proves distinct executor and recovery
  session identities, exclusive tenant capabilities, exact role/RPC grants,
  and the required replay, status-head, and attempt-store schema before
  admitting traffic.

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
