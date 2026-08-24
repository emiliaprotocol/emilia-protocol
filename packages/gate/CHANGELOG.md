<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

### Security

- Make a deployment-level `requiredAdmissibilityProfile` authoritative. A
  request or selector may repeat the configured id and digest, but cannot
  replace either with a weaker profile before the trusted verifier runs or a
  receipt is reserved.
- Add the experimental Claim Assurance bridge as non-authorizing, exact-action
  evidence. Gate computes the profile commitment locally and requires the
  reviewed Claim Assurance evaluator and pinned evidence-verifier callbacks as
  explicit deployment trust inputs, avoiding a runtime or type import from a
  Verify subpath that the pinned published dependency does not expose.
- Preserve a schema-valid typed Claim Assurance block byte for byte in reliance
  packets while keeping Gate's separate admissibility interpretation outside the
  typed record. Invalid typed inputs are not re-emitted under the typed field.
- Align admissibility profile identifiers with the public schema and preserve
  conflict and unverifiable failure precedence when bridging legacy evidence.
- Recompute package and profile digests during assurance re-performance and
  support independently supplied package and profile pins. Internal consistency
  is not treated as proof that the presented package or rule was authorized.

## 0.23.20 (2026-08-21)

- Add provider-neutral memory projection records for SHEESH/SOMA and Zep,
  binding pinned source and projection bytes to one exact action while keeping
  verified context separate from authorization.
- Refuse provider/profile substitution, stale verification state, projection
  drift, and replay with seven bounded positive and hostile cases.

## 0.23.19 (2026-08-21)

- Make the installed `ep-protect` executable resolve npm's bin symlink before
  deciding whether it is the process entry point. Version 0.23.18 could exit
  successfully without activating or writing an artifact when invoked through
  the normal npm-installed command.
- Add a subprocess regression that invokes the executable through an
  npm-shaped symlink and requires an activation artifact to be written.

## 0.23.18 (2026-08-21)

- Reissue the customer-owned consequence-protection release after npm 12
  changed `npm pack --json` from an array to a keyed object. The release
  verifier now accepts both documented report shapes without weakening any
  packed-artifact or consumer check.

## 0.23.17 (2026-08-21)

- Reissue the customer-owned consequence-protection release from the exact
  protected `main` commit after the immutable `0.23.16` tag correctly remained
  bound to an earlier commit whose publication preflight failed under npm 12's
  remote-dependency policy.
- Add a sealed protected-action registry and `gate.runRegistered()`. Reviewed
  handlers are installed only during trusted startup, the pinned manifest
  selects the handler, and frozen validated parameters enter the existing
  reserve/provider-entry/commit path. The existing `run(fn)` API is unchanged.
- Coverage reconciliation schema family v2 (`EP-COVERAGE-SOURCE-INVENTORY-v2`,
  `EP-COVERAGE-POPULATION-v2`, `EP-COVERAGE-RECONCILIATION-REPORT-v2`,
  `EP-COVERAGE-RECONCILIATION-ATTESTATION-v2`); v1 artifacts fail closed under
  v2 verifiers and there is no compatibility alias.
  - Rename the `receipt_without_effect` bin to `receipted_without_observation`:
    the join only shows a receipt with no matching record in the supplied
    source population, never that no effect occurred.
  - Require a `classification_rule_id` on every `excluded` and `exception`
    record, resolved against the compiled-in versioned registry
    `EP-COVERAGE-CLASSIFICATION-RULES-v1`; the field rides inside the record
    and is covered by the signed population root. A missing or unresolvable
    rule id demotes the record to the new system-side `system_indeterminate`
    bin instead of widening an exclusion.
  - Assert, in the runner before any report is emitted, that bin counts sum
    back to the signed record counts of both populations
    (`assertCoveragePopulationConservation`), refusing with
    `population_conservation_violation:system` or
    `population_conservation_violation:receipt` on violation.

## 0.23.14 (2026-08-05)

- Carry `@emilia-protocol/require-receipt` 0.8.0 so Gate integrations can use
  the same executor-side exact-action binder as the public framework adapters.

## 0.23.13 (2026-08-04)

- Reissues the recoverable prepared-reservation release from the exact protected
  `main` commit after the immutable `0.23.12` tag was correctly refused by the
  publication gate when `main` advanced before dispatch.

## 0.23.12 (2026-08-04)

### Security

- Allow an orchestrator to durably custody the exact reservation owner token
  before Gate commits the atomic reservation, closing the process-death window
  between those two steps.
- Make deadline recovery program-aware so releasing an expired, provably
  unentered admission also releases its occurrence and reserved budgets.
- Keep post-provider-entry recovery evidence-gated; the deadline reaper does
  not retry or erase an entered effect.

## 0.23.11

- Publish the crash-safe bounded-program provider-entry path from 0.23.10 under
  a fresh immutable tag after the original protected tag stopped before npm
  publication.
- Regenerate package-bound formal, security-case, and proof evidence against
  the exact release bytes. There is no additional API change from 0.23.10.

## 0.23.10

- Add crash-safe, program-aware provider entry with a caller-prepared invocation token.
- Preserve bounded-program status, concurrency, occurrence, and budget checks on that path.

All notable changes to `@emilia-protocol/gate` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- Add the transport- and evidence-format-neutral `./consequence-boundary`
  facade. It re-verifies a signed AEB join for one frozen action, applies local
  policy, atomically fences native replay units, records provider-attempt
  custody, and reports only `EXECUTED`, authoritative `FAILED`, or
  `INDETERMINATE` after provider entry.
- Add `./bounded-execution-acceptance`, a relying-party-signed acceptance
  profile and portable evidence pack over signed bounded-execution reports.
  Evaluation preserves unresolved work as `INDETERMINATE` and deliberately
  makes no legal-compliance, external-effect, safety, or complete-mediation
  claim.

### Security

- Scope legacy receipt consumption by the canonical signed
  `[tenant_id, receipt_id]` pair. Every reserve, consume, commit, and release
  transition now uses the same recorded composite key, preventing one
  tenant's receipt identifier from colliding with another tenant in a shared
  store.
- Require an explicit relying-party verification mode when WebAuthn RP and
  origin pins are authoritative; omitted pins now fail closed instead of
  silently producing an integrity-only result.

### Compatibility

- Pre-composite stores contain bare `receipt_id` rows that the new composite
  keyspace does not consult. Before upgrading a deployment that cannot accept
  one additional admission during the configured `maxAgeSec` window, drain
  in-flight receipts or refuse admission for one complete `maxAgeSec`
  interval. Fresh stores are unaffected.

## 0.23.9 (2026-08-03)

### Security

- Fail closed when an allowance/profile verifier returns only `true` or
  `{ ok: true }`; it must now return an explicit canonical
  `action_fence_digest` derived from the profile-validated material action.
- Derive the built-in Gate Allowance fence from every validated action field
  except the wrapper-specific operation-ID field, so two operation IDs cannot
  execute one material action twice in the shared allowance namespace.

### Compatibility

- Custom allowance/profile verifiers must return
  `{ ok: true, action_fence_digest }`. This intentional security break does not
  change the capability database schema or the exact-digest and CAID scope
  semantics.

## 0.23.8 (2026-08-03)

### Security

- Fence live reservations by a stable material-action digest in addition to
  the exact request digest, so wrapper-specific operation IDs cannot authorize
  the same consequential action twice.
- Permanently quarantine legacy capability IDs whose historical rows do not
  carry authoritative semantic-fence evidence; reviewed recovery issues a new
  capability ID instead of inferring equivalence from old exact digests.
- Reject failed CAID resolver decisions, non-positive spend reservations, and
  mismatched action digests across pre-entry recovery and indeterminate
  reconciliation in both memory and PostgreSQL stores.
- Validate the complete PostgreSQL fence-index contract and enforce semantic
  readiness at the database boundary, including direct table writers.

## 0.23.7 (2026-08-02)

### Release

- Supersedes the unpublished `0.23.6` tag after the protected release gate
  required a source-bound LLM context refresh. Runtime, protocol, and draft
  behavior are unchanged from `0.23.6`.

## 0.23.6 (2026-08-02)

### Security

- Recheck each allowance's authoritative monotonic status head inside the same
  atomic transaction that reserves spend, closing the verify-then-revoke race.
- Persist invocation recovery authority before the durable `INVOKING`
  transition so a process crash cannot strand an unowned operation.
- Distinguish pre-provider reservations from entered effects, allowing only an
  expired, demonstrably unentered reservation to be released automatically;
  post-entry recovery remains evidence-gated and never blindly retries.

## 0.23.5 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.4` tag after protected `main` advanced for a
  standards-only idnits correction before registry publication. Security and
  runtime behavior are unchanged.

## 0.23.4 (2026-08-01)

### Security

- Refuse symbol-keyed members in Gate commit-binding inputs so every in-process
  member is either covered by the exact-action hash or rejected.
- Publish from the post-hardening protected-main baseline after the prior
  approval-wait release was correctly invalidated by a main-branch advance.

## 0.23.3 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.2` tag so Gate and its exact
  `@emilia-protocol/require-receipt` 0.7.2 dependency publish from the same
  protected-main baseline.

## 0.23.2 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.1` tag and pins
  `@emilia-protocol/require-receipt` 0.7.2, whose clean build now reproduces all
  package-declared dist assets from source.

## 0.23.1 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.0` release tag on the corrected protected-
  main evidence baseline.
- Pins `@emilia-protocol/verify` 3.20.1 and
  `@emilia-protocol/require-receipt` 0.7.1 so the published Gate consumes the
  same hardened canonicalization, projection, and receipt behavior verified by
  this release's evidence chain.

## 0.23.0 (2026-08-01)

### Added

- `./coverage-reconciliation-runner`, which verifies independently signed,
  privacy-minimized source inventories, joins exact CAID/action-digest pairs,
  derives conserving counts, and emits a report-bound period attestation.
- `./bounded-execution-program`, a canonical signed finite action DAG with
  exact-action or pinned-profile nodes, typed terminal dependencies, retained-
  occurrence ceilings, multidimensional attempt budgets, suspension,
  revocation, and fresh signed supersession.
- `./bounded-execution-report`, a signed point-in-time, program-to-date record
  of Gate-observed occurrences and budget use with an explicit boundary around
  external effects and actions outside Gate.
- Program-aware in-memory and PostgreSQL AdmissionStore operations that bind
  each occurrence into the immutable admission snapshot and consume the
  one-time execution right in the same transaction as program state.
- The versioned PostgreSQL reference schema in
  `sql/gate-qualification-v2.sql`, deterministic reference vectors, runtime-
  refinement traces, and a bounded TLC model with two intentional negative
  controls.
- Signed Gate Allowances that permit exact, bounded repeated operations while
  retaining immutable provider-action binding, aggregate depletion, current
  status, and one-time operation fencing.
- Conserved-authority delegation across sibling fan-out: every child transfer
  is funded exactly once from its parent in one authoritative state domain,
  with aggregate sibling limits and explicit cross-domain non-guarantees.

### Security

- Source-system identities, mapping-profile digests, source operators, trust
  keys, and verification time are verifier-owned pins. Duplicate joins,
  cross-population CAID/digest conflicts, same-operator source populations, and
  report substitution fail closed. The artifact remains evidence about two
  supplied populations and does not prove either source was complete.
- Program-authorizer keys, roles, status, verification time, action-profile
  matchers, and current program status are store-owned policy. The signed
  program constrains separately authorized actions; it does not prove human
  ceremony, safe intent, provider or effect truth, complete mediation, or the
  absence of actions outside Gate.
- The ordinary and execution-program admission paths both retain monotonic
  authenticator-counter currentness checks immediately before provider entry.

## 0.22.2 (2026-07-31)

### Security

- Reproject the normalized payment action at admission from the exact
  server-owned AP2 payloads and source binding, then require every Gate, human,
  and AEB action digest to match it. A pinned verifier can no longer cause the
  live path to compare a claimed action with itself.
- Support an explicit zero-counter platform-passkey policy without a false
  monotonicity claim; strict counter advancement remains the default, and both
  modes retain exact assertion replay, AP2 token, provider-operation, and
  one-time admission controls.

### Packaging

- Include and export the PostgreSQL Gate Qualification v2 schema used by the
  durable AdmissionStore deployment.

## 0.22.1 (2026-07-31)

### Added

- FIDO/AP2 AdmissionStore builders that re-verify a signed,
  execution-authorizing two-leg AEB record against server-owned pinned
  configuration and authenticated status heads, remeasure the exact AP2 v0.2
  token strings and final provider-request bytes, and require a pinned provider
  adapter to find the exact PaymentMandate token in those frozen bytes.
- Domain-separated one-time resources for the CheckoutMandate token,
  PaymentMandate token, WebAuthn assertion, provider operation, and both
  authenticated status heads, plus a durable monotonic counter resource for
  the RP/credential pair. The signed full AEB evaluation record, including
  initiator, executor, evaluator, nonce, and requirement, is retained in the
  admission evidence.

### Security

- Request-side clocks, trust roots, status maps, actors, provider adapters, and
  provider bytes are not accepted. Gate Qualification v2 plus AdmissionStore
  `beginInvocation()` remain the sole authority-custody and one-time provider
  entry boundary; the bridge creates no parallel consumption store and makes
  no provider-outcome or observed-effect claim.
- Admission builders return recursively frozen clones after validating the
  complete Gate snapshot contract, preventing post-build nested mutation.
- Memory and PostgreSQL AdmissionStores require a trusted enrollment or
  recovery baseline, atomically compare and advance signed WebAuthn counters
  with successful reservation, and recheck their durable head before
  invocation. Missing enrollment, reuse, rollback, and artifact-selected
  baselines fail closed.

## 0.21.0 (2026-07-29)

### Added

- Signed action-refusal delivery from the live reliance boundary, with a
  durable PostgreSQL acceptance store for atomic replay refusal, tenant
  isolation, custody references, and delivery evidence.
- PEDIGREE composition that preserves native verification and keeps completion
  evidence structurally separate from pre-action authorization.
- A relying-party-pinned Trusted Context admission pack and optional
  ApertoMemory adapter for encrypted context evidence without allowing memory
  evidence to authorize an action by itself.

### Security

- Pins `@emilia-protocol/verify@3.18.2`, carrying the PSEA-02 adapter,
  independent industrial effect-evidence predicates, and the current
  PEDIGREE/AEB composition vectors into Gate.
- Refusals remain fail-closed, exact-action bound, and non-authorizing. Trusted
  context remains an optional evidence leg; Gate still owns the final local
  authorization and one-time consequence-admission decision.

## 0.20.1 (2026-07-29)

### Security

- Pins `@emilia-protocol/verify@3.17.1`, carrying the current-status
  compromise boundary and the corrected backdating semantics into every
  Gate installation. The independently published verifier tarball is
  byte-pinned in the governed release registry.

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
