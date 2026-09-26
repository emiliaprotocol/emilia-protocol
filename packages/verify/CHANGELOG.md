# Changelog

All notable changes to `@emilia-protocol/verify` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- The vendored CAID implementation (`vendor/caid.mjs`), which the AEB
  adapters, the AP2 native adapter, the FIDO and AP2 bridge, authorization
  server confirmation, the crossing lab, portable state handoff, and policy
  decision evidence use to compute CAIDs, now applies the
  enum rules of CAID action-type registry v4. Registry v3 named external code
  sets such as ISO 4217 without pinning their contents, and 5.0.0 accepted any
  string for an enum field that had no `values` array. An enum is now closed
  only by a non-empty `values` array, an `inline:` `values_ref`, or an external
  `values_ref` that carries `values_snapshot` and `values_sha256` and whose
  values are supplied and hash to that digest. When the field is present in
  the action, an open enum (`type: "enum"` with no values), a bare or
  unresolved external `values_ref`, a digest mismatch, or a value outside the
  set makes the CAID refuse with `mistyped_field:<field>`. An adapter mapping
  profile that relied on an open or bare external enum, for example `currency`
  naming ISO 4217 with no values, now maps to a refusal and must list its
  accepted values inline. The adapters do not take external snapshots.
- CAID bytes are unchanged for every action that both 5.0.0 and this version
  accept; only the set of accepted actions narrowed. This is a behavior change
  for callers whose profiles used open enums, not a wire format change.
- None of this shipped in 5.0.0.

## 5.0.0 (2026-09-25)

### Security

- The verification result now also carries the label-free replay identity:
  `native_replay_identity`, derived locally from the matched pin's authority
  namespace and the native authorization ID, and `replay_identity_key`, its
  relying-party-scoped key under `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2`.
  The namespace is the issuer unless the pin declares `authority_namespace`,
  in which case the issuer string is not an input. The `system` and `profile`
  labels are not inputs, so one grant relabelled under a second pinned
  profile derives the same identity, and pins that spell one issuer two ways
  but declare the same namespace share it. Both are null unless the source is
  pinned and the pin set passes `verifyAebNativeAuthorizationPins()`.
- `native_replay_unit` and `replay_key` keep the values 4.1.0 reported: the
  label-bearing wire `replay_unit` and its key under
  `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1`. That key changes when one grant
  is relabelled, so a replay fence must hold `replay_identity_key`, and may
  hold `replay_key` beside it to keep grants that 4.1.0-based code recorded;
  it must never hold `replay_key` alone.
- Wire compatibility: the signed `AEB-NATIVE-AUTHORIZATION-HANDOFF-v1`
  encoding, including its carried `replay_unit`, is unchanged. Handoffs issued
  by 4.1.0 verify under this version, and handoffs issued by this version
  verify under 4.1.0. The carried `replay_unit` is checked as part of the wire
  format and is never used as the replay identity.
- `verifyAebNativeAuthorizationHandoff()` reads each caller value once into
  plain JSON and refuses Proxies, accessors, and sparse arrays with a reason
  (`native_handoff_options_invalid`, `native_handoff_schema_invalid`, or
  `native_handoff_expected_action_invalid`) instead of throwing.
- `authorizeAebExecutionDurable()` no longer reports a clean `REFUSED` when
  the reservation's outcome is unknown. In 4.1.0 a reserve call that threw
  became `REFUSED consumption_store_unavailable`, and any answer other than
  `true`, `'RESERVED'`, or `'NATIVE_REPLAY_CONFLICT'` became
  `REFUSED consumption_conflict`, even when the store had applied the
  reservation, which left that evaluation reserved with nothing to recover
  it and refused every later run. Now only `false`, `'CONSUMPTION_CONFLICT'`,
  and `'NATIVE_REPLAY_CONFLICT'` are clean refusals, because they mean the
  call wrote nothing.
  A throw or any other answer may have reserved the row. It is
  resolved through the store's optional durable `state()` read (new
  optional member of `AebDurableConsumptionStore`) only when the read
  shows a permanent state that this call's reserve cannot have written:
  `CONSUMED` or `RELEASED_NOT_ENTERED` is `REFUSED`
  `consumption_conflict`. Anything else, including `AVAILABLE`, a store
  without `state()`, or a read that fails, returns
  `RECONCILIATION_REQUIRED` with `consumption_reservation_unconfirmed`,
  which authorizes nothing and is not a clean refusal. `AVAILABLE` is not
  proof that nothing was reserved, because a reserve write still in flight
  can land after the read.
- Issuer normalization for pin alias detection no longer uses regular
  expressions that can backtrack polynomially on crafted input. An issuer
  longer than the pin identifier grammar's 512-character maximum is
  compared as written, and a shorter one is normalized with linear string
  operations, so a long issuer such as a run of `.` or `/` characters, or
  `//` followed by many `"` characters, is processed in bounded time.
  Which spellings count as aliases is unchanged for every issuer the pin
  grammar admits.
- The verification result adds `legacy_replay_keys`: the verify 4.1.0
  `replay_key` of the grant under every pinned `system`, `profile`, and
  issuer that shares the matched pin's authority namespace, sorted and
  including `replay_key`. Code built on 4.1.0 fenced only the key of the
  label a grant was presented under, so a replay fence that holds all of
  these refuses a grant consumed there under one label and presented here
  under another pinned label. It is null exactly when
  `native_replay_identity` is null.

### Added

- Native source pins accept an optional `authority_namespace`, which replaces
  the issuer in the replay identity. One issuer has exactly one namespace in a
  pin set. Pins for one issuer must all declare a namespace or all omit it
  (`native_pins_namespace_declaration_mixed`), and pins that declare one must
  all declare the same one. Pins whose issuers are different spellings of one
  issuer must all declare the same namespace
  (`native_pins_issuer_alias_without_shared_namespace`). Spellings compare
  equal after the URI scheme and URL host are lower-cased, a trailing dot on
  the host, a default port, and trailing slashes are removed, and dot
  segments in the path are resolved; an http or https URL written without
  `//` compares equal to the URL written with it, and a URN's namespace
  identifier compares case-insensitively. For a DID the method name compares
  case-insensitively; for `did:web` the host also compares case-insensitively
  without trailing dots (a `did:web` issuer with a percent-encoded port
  cannot be pinned, because the pin identifier grammar has no `%`). For
  `spiffe://` the trust
  domain compares case-insensitively without trailing dots, and trailing
  slashes on the path are dropped. Normalization cannot find every alias:
  two issuer strings that denote one authority but do not normalize equal
  need one explicitly shared namespace. One exact
  issuer declared under two different namespaces is refused
  (`native_pins_issuer_namespace_conflict`). Two pins with the same gateway,
  system, profile, and issuer are refused. When a pin set declares any
  namespace, an alias without one shared namespace refuses it outright. When
  it declares none, it is still accepted for handoff verification exactly as
  4.1.0 accepted it, but an aliased issuer derives no replay identity. Changing
  a pin's namespace changes the replay identity derived under it: drain
  in-flight attempts and let grants consumed under the old namespace expire
  before rotating.
- `verifyAebNativeAuthorizationPins()` validates a pin set before use and
  returns one `native_pins_*` reason instead of throwing, so a boundary can
  refuse an unsafe pin set at construction. The reasons are
  `native_pins_schema_invalid`, `native_pins_duplicate_gateway_key`,
  `native_pins_duplicate_source`, `native_pins_source_gateway_unpinned`,
  `native_pins_namespace_declaration_mixed`,
  `native_pins_issuer_namespace_conflict`, and
  `native_pins_issuer_alias_without_shared_namespace`. The handoff verifier
  refuses the same pin sets as `native_handoff_schema_invalid`, except an
  aliasing pin set that declares no namespace, which it accepts as 4.1.0 did
  without deriving a replay identity.
- `deriveAebNativeAuthorizationReplayIdentity()` derives the label-free
  identity from the authority namespace (the issuer by default) and the
  native authorization ID under `AEB-NATIVE-AUTHORIZATION-REPLAY-IDENTITY-v1`,
  and `aebNativeAuthorizationReplayIdentityKey()` keys it under
  `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2`. New constants:
  `AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_DOMAIN` and
  `AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN`.
  `deriveAebNativeAuthorizationReplayUnit()`, `aebNativeAuthorizationReplayKey()`,
  and `AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN` keep their 4.1.0 meanings
  and values.
- Crossing Record v1 and v2 and `EP-AEB-CROSSING-LIFECYCLE-INDEX-v2` verifiers
  accept an optional `evaluation` record and report `evaluation_binding`
  (`BOUND`, `INDETERMINATE`, or `MISMATCH`). The join checks the evaluation
  digest, profile label, operation, CAID, action commitment, the evidence leg
  that matches the native authority, and the verdict. Without an evaluation,
  the cited evaluation digest is an unverified pointer and the binding is
  `INDETERMINATE`. `BOUND` is a join, not authentication: run
  `verifyAebEvaluation()` or `verifyAebEvaluationV2()` on the evaluation too.
- `aebCrossingEvaluationReference()` defines the evaluation reference as the
  digest of the complete signed evaluation (the verifiers' `record_digest`),
  with the `AebCrossingEvaluationBinding` and `AebCrossingEvaluationReference`
  types.

### Fixed

- The v1 lifecycle upgrade no longer reports an unchecked evaluation
  reference as `COMPLETE`. Without a matching `source_evaluation`, the
  index carries the digest under the `AEB-EVALUATION-v1` label that 4.1.0
  wrote for every v1 conversion, and the conversion is `INDETERMINATE` with
  `evaluation_reference_unverified`. That reason code marks the label as
  unchecked, and the verifiers do not compare an unchecked label with a
  supplied evaluation. `lifecycle.evaluation.profile` keeps its 4.1.0
  non-null type. A supplied
  `source_evaluation` that does not bind makes the issuer-side upgrade throw
  the typed `CrossingRecordError` `source_evaluation_mismatch`, and nothing is
  signed. Out-of-order v1
  references are converted as `INDETERMINATE` instead of throwing
  `lifecycle_order_invalid`.
- The lifecycle index refuses a provider entry that is not preceded by a
  custody reservation or consumption.

### Compatibility

- Every value and export that 4.1.0 provided keeps its 4.1.0 meaning:
  `native_replay_unit`, `replay_key`, `aebNativeAuthorizationReplayKey()`,
  `deriveAebNativeAuthorizationReplayUnit()`, and
  `AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN`. A pin set that 4.1.0 accepted
  is still accepted by `verifyAebNativeAuthorizationHandoff()`; when it
  aliases one issuer (for example `https://a.example` and
  `https://a.example/`, or `urn:example:issuer` and `URN:example:issuer`),
  `native_replay_identity` and `replay_identity_key` are null and
  `verifyAebNativeAuthorizationPins()` reports
  `native_pins_issuer_alias_without_shared_namespace`, so a boundary that
  checks pins at construction refuses it. 4.1.0 refused every pin that
  declared `authority_namespace`.
- Version type: major, 5.0.0, by choice. `docs/api/COMPATIBILITY.md` says
  that security patches may change behavior on any surface and are never
  treated as breaking changes, so that policy would permit releasing these
  security fixes as a minor version, 4.2.0. This release is major anyway
  because it refuses artifacts that 4.1.0 accepted and changes outputs for
  the same input, and a dependent that accepts `^4` should not receive that
  without choosing to; 4.0.0 was a major release for the same reason. It
  refuses lifecycle indexes that 4.1.0 verified (a provider entry with no
  custody reference), changes what
  `upgradeAebCrossingRecordV1ToLifecycleIndexV2()` returns for the same
  input (`INDETERMINATE` with `evaluation_reference_unverified` where 4.1.0
  returned `COMPLETE`, and an `INDETERMINATE` conversion where 4.1.0 threw
  `lifecycle_order_invalid`), and returns `RECONCILIATION_REQUIRED` from
  `authorizeAebExecutionDurable()` where 4.1.0 returned `REFUSED`. No export
  is removed and no public TypeScript type is narrowed:
  `lifecycle.evaluation.profile` keeps its non-null type,
  `RECONCILIATION_REQUIRED` was already a state of `AebExecutionDecision`,
  and `state()` and `legacy_replay_keys` are additions. The signed native
  handoff is byte-identical in both directions.
- Release order: publish this Verify release before `@emilia-protocol/gate`.
  Gate imports `verifyAebNativeAuthorizationPins()` and the replay-identity
  fields from this release and pins `@emilia-protocol/verify` exactly, so
  Gate's dependency must be bumped from `4.1.0` to `5.0.0` before Gate is
  published. A Gate published while it still pins 4.1.0 fails to load
  its root entry and every subpath that imports `@emilia-protocol/verify/aeb`,
  not only `@emilia-protocol/gate/aeb`.

## 4.1.0 (2026-09-24)

- Add `AEB-NATIVE-AUTHORIZATION-HANDOFF-v1`, a closed Ed25519 gateway statement
  that binds the stated native authorization identity and `PERMIT` decision to
  one exact action, relying party, audience, executor, provider, validity
  window, revocation handle, and wrapper-neutral replay identity. The gateway,
  source profile, and issuer are relying-party pinned; native-artifact
  verification remains the native system's responsibility. It provides the
  direct handoff for AuthZEN, COAZ, AP2, OAuth, and local sources, and for
  deployments that follow the AIMS profile of existing standards, without
  requiring CAID or AEC.
- Add the stable `./aeb` facade, signed nonauthorizing `AEB-EVALUATION-v2`
  projections, and the separate
  `EP-AEB-CROSSING-LIFECYCLE-INDEX-v2`. Deterministic v1 upgrades preserve
  available provenance and report missing semantic or lifecycle evidence as
  `INDETERMINATE` instead of inventing it. Existing Crossing Record v1 and v2
  bytes and verification rules remain unchanged.

The direct handoff is a repository implementation profile for the direct
native path. When 4.1.0 was published (2026-09-25T02:04Z), AEB-06 was staged
and AEB-05, which requires CAID matching and AEC satisfaction, was current.
AEB-06 was posted later that day, at 2026-09-25T02:15:03Z, as an individual
Internet-Draft and is not adopted by any working group. It makes CAID and AEC conditional but does
not specify the gateway handoff. Source labels do not establish
native-protocol conformance or independent interoperability.

Correction (found after release): the v1 upgrade copies the v1 record's
evaluation digest into the lifecycle index under the `AEB-EVALUATION-v1`
profile label without receiving or re-verifying that evaluation, and can report the
conversion `COMPLETE`. A `COMPLETE` conversion therefore shows only that the
signer committed to the references; it does not show that the referenced
evaluation exists or matches the operation.
The Unreleased section above adds the evaluation join and stops the upgrade
from reporting an unchecked reference as `COMPLETE`.

## 4.0.0 (2026-09-13)

- **Breaking change.** The existing
  `./aeb-wimse-oauth-adapter` subpath now implements the receiver-scoped v3
  profile and no longer accepts its published v1 constructor or artifacts.
  This is a new major package version, not a compatible 3.x update.
  Existing v1 artifacts require the
  frozen v1 verifier or reissuance and verification under v3.

## 3.21.0 (2026-09-05)

- Added the AEB Crossing Lab local adapter workbench. It scaffolds, seals, and
  runs one bundled deterministic `AebAdapter` through the canonical
  `evaluateAebEvidence` path under a real pinned `AEB-ADAPTER-v1`
  configuration. The local report preserves native verification, relying-party
  acceptance, exact-action mapping, freshness, and evidence satisfaction as
  separate axes; repeats identical calls to refuse nondeterministic adapters;
  and exercises explicit action substitution, trust substitution, stale and
  unavailable status, and wrapper-independent replay identity. Reports use a
  published fixed self-test signer and are adapter compatibility self-tests,
  not native-specification validation, independent interoperability,
  certification, authorization, deployment evidence, or execution evidence.

- Added source-locked local OASNT-CAID-01 lifecycle and namespace-separation
  vectors over the OASNT-02 native verifier. The cases cover refusal without
  replay-unit consumption, release after `NOT_COMMITTED`, permanent
  consumption after `COMMITTED`, and executor-owned dual-profile joins without
  treating an OASNT CAID as wire-compatible with an EMILIA CAID. The companion
  draft remains revision -01, so this is same-repository implementation
  evidence rather than a claim of a revised profile or external interop.

- Add the zero-dependency Claim Assurance kernel. Strict, content-addressed
  Claim Cases are evaluated by caller-pinned verifier implementations under a
  pinned profile and produce deterministic, offline-checkable Assurance
  Records. `VERIFIED`, `UNVERIFIED`, `DIVERGED`, and `INDETERMINATE` remain
  evidence states; every record explicitly carries `authorizes_action: false`.
  Evidence outside the profile is rejected before callback dispatch, verifier
  reasons are bounded, and integrity inspection explicitly reports that it did
  not re-perform the Claim Case.

- Added `EP-AEB-CROSSING-RECORD-v1`, a carrier-neutral, hybrid-signed record
  that binds one exact action, native authority instance, replay unit, mapping
  profile, admission reference, consumption evidence, relying-party boundary,
  executor, audience, and state domain. The verifier is evidence-only and
  never authorizes a later crossing. Reference WIMSE/OAuth authorization-server
  and BCR mappings share one open projection contract without claiming native
  semantic equivalence. Fifteen deterministic composition cases cover
  substitution, signature stripping, stale status, missing admission evidence,
  wrong trust roots, local narrowing, forbidden broadening, and carrier
  injection.

- Repinned the OASNT AEB adapter to draft-thallapelly-oasnt-02 (archived text
  SHA-256 3a134b63…) and implemented the -02 `asl` assurance claim: registry
  syntax validation, relying-party assurance floor in the pinned config
  (`required_assurance_level`, explicitly nullable), effective-level
  derivation as the lesser of the claimed level and the enrollment ceiling,
  and the absent-versus-unrecognized distinction reported in the refusal
  reason while deciding identically. Adapter version 2, config version
  AEB-OASNT-CONFIG-v2. The -02 verifier-side lifetime bound was already
  enforced as `max_token_lifetime_seconds`.

- Added a shared native-action projection to the experimental CCS adapter so a
  pinned CCS machine-policy result and another native evidence leg can map to
  the same CAID without role substitution. Added a runnable CCS + OASNT AEB
  composition report with compatibility locking, hostile substitution and
  replay cases, and optional runner signatures.

### Added

- `./aeb-ccs-adapter`, an experimental, source-locked mapping from the HMAC
  result actually shipped by `ccs-verifier==1.1.0` (runtime `0.4.1`) into one
  AEB `machine-policy-decision` leg. The adapter independently re-derives the
  exact tool-and-parameters action, keeps CCS replay separate from execution
  authority, and does not treat a policy allow as authorization or effect
  evidence. A package-generated positive fixture and hostile substitution,
  pinning, freshness, outcome-promotion, and authority-reuse cases document
  the limited local-HMAC composition.
- `EP-AUTHORIZATION-BUNDLE-v1`, a closed pre-execution verifier for portable
  human approval evidence with exact-action, audience, transport-neutral native
  authorization binding, policy-selected approvers, current-policy and status
  checks, three-state results, a pure bundle-to-grant compare-and-set helper,
  and 24 generated hostile cases. `SATISFIED` remains evidence input and never
  becomes a grant, authorization decision, consumption record, or effect proof.
- `./oauth-rar-authorization-binding`, an optional closed OAuth/RAR projection
  profile kept outside the neutral Bundle core. It validates and compares bytes
  independently derived from a natively verified transaction; it does not
  validate OAuth tokens, issue grants, or make authorization decisions.
- `./a2a-receipt-binding`, a strict A2A v1.0 Message-extension presentation
  that binds one verified receipt to the exact initiating Message,
  server-issued Task/context, proof retry, Agent Card, target interface, action,
  and CAID under a relying-party-pinned Ed25519 binder. It emits the
  `EP-RECEIPT-EXTENSIONS-v1` companion and keeps A2A transport authentication,
  receipt verification, local authorization, execution, and outcome proof as
  separate decisions.
- Revision-pinned AEB adapters for OASNT-01, APS-03, McGraw HTTP Agent
  Budget-03, and OAuth Transaction Challenge-00. Each verifies the native
  artifact under constructor-pinned relying-party policy, projects an exact
  action through a content-addressed mapping profile, and leaves evidence
  sufficiency, local authorization, replay custody, and execution to AEB/Gate.
- `EP-AEB-ACCEPTANCE-PROFILE-v1`, one content-addressed relying-party bar with
  fixed monitor and enforce semantics. Monitor mode cannot authorize or
  consume; enforce mode requires current execution verification, local
  authorization, and atomic one-time consumption.
- `AEB-EXECUTION-CONDITIONS-v1`, an internal execution-boundary profile that
  binds an exact action and human-approved opaque predicate set to an
  RP-pinned resolver profile. Typed outcomes keep predicate failure, binding
  invalidity, authorization expiry/revocation, and resolver uncertainty
  distinct; only compare-and-set or provider-enforced evidence can support a
  prevention claim.
  The existing synchronous and durable AEB authorization paths accept this
  local result as a pre-reservation condition and fail closed on every outcome
  other than `ADMIT`.
- Signed OPA/Cerbos policy-decision evidence with exact-action and policy-digest
  binding, relying-party-pinned bridge keys, explicit deny/indeterminate
  handling, and an AEB role that cannot substitute for human authorization.
- Authorization Server confirmation evidence adapter with relying-party-pinned
  Ed25519 trust, exact-action and Resource Server binding, signed policy and
  identity-directory commitments, explicit directory observation time and
  relying-party-pinned maximum snapshot age, current-status separation, and a
  closed human-evidence digest link.
- AEB `evidence-binding` requirement terms. A source leg can satisfy the term
  only by binding the exact digest and, when required, subject of a separately
  verified target leg. The source artifact never satisfies or authorizes the
  target role by itself.

### Security

- Bind every AEB execution-verification result to the digest of the exact
  signed evaluation record it verified. A positive result for one record can
  no longer be reused after swapping an operation, nonce, leg, requirement, or
  other signed field before consumption.

## 3.20.1 (2026-08-01)

### Release

- Supersedes the unpublished `3.20.0` release tag after regenerating the
  selected-scenario conformance artifact from the pinned live TLC oracle. No
  verifier API or acceptance behavior changes from `3.20.0`.

## 3.20.0 (2026-08-01)

### Added

- Memory Projection Record v1 construction and relying-party verification as
  the public `@emilia-protocol/verify/memory-projection` export. The record
  binds a candidate manifest, projection policy, source and projected memory
  digests, transformation disclosure, freshness, and verifier-owned trust
  configuration without treating projection as authorization.

### Security

- The projection verifier rejects unknown fields, malformed or accessor-bearing
  JSON, untrusted issuers, substituted policies or contexts, stale records,
  source and output digest mismatches, and unsupported transformation claims.

## 3.19.1 (2026-07-31)

### Security

- Add an explicit relying-party-pinned `not-relied-upon` WebAuthn counter
  policy for zero-counter platform passkeys while preserving UP, UV, exact
  challenge/action binding, replay identities, and Gate one-time admission.
  The strict above-enrollment policy remains the default.

### Documentation

- State that source commitments and projection helpers prevent AP2 semantic
  splicing only when callers use the exact payloads accepted by their native
  verifier and independently reproject them before reliance. Pure verification
  remains distinct from authorization, admission, and replay prevention.

## 3.19.0 (2026-07-31)

### Added

- A relying-party-pinned WebAuthn ES256/P-256 human-authorization adapter for
  the closed, immediate AP2 v0.2 `CheckoutMandate`/`PaymentMandate` subset.
  Exact canonical SD-JWT token strings, the merchant checkout JWT, the
  normalized action, readable disclosure, protected provider request,
  provider/account, tenant, actors, nonce, and source expiry are bound without
  collapsing AP2-native verification into human authorization.
- A deterministic AP2 v0.2-to-CAID projection and source-binding helper that
  commits exact tokens, disclosure-resolved payloads, and the authenticated
  AP2 checkout-hash algorithm returned by native verifiers.

### Security

- Unknown, legacy, open, recurring, materially lossy, stale, revoked,
  previously consumed, cross-origin, extension-bearing, or malformed evidence
  fails closed. The WebAuthn profile requires UP and UV, a 37-byte
  extension-free assertion, an ES256/P-256 enrolled key, and a counter above
  enrollment; exact one-time use remains a Gate admission property.
- Strict canonicalization now rejects malformed UTF-16 in nested JSON values
  and member names before signing, verification, or digesting.
- The AP2 projection now follows the pinned v0.2 optional-member types and
  represents immediate execution by omitting `execution_date`; schema-invalid
  `null` optionals fail closed. AEB and bridge instants reject precision beyond
  milliseconds instead of truncating a future not-before value.
- Verified source payload commitments prevent valid mandate tokens from being
  spliced onto unrelated projected objects; authenticated AP2 `sha-256`,
  `sha-384`, and `sha-512` checkout linkage is supported.

### Added

- Current-evidence Trust Receipt verification with an explicit relying-party
  clock, exact-target revocation-statement evaluation, optional WebAuthn
  signature-counter enforcement, and high-value financial timestamp policy.
- Approver-directory transition auditing that refuses a retroactive
  `valid_to` narrowing unless compromise or an explicit reviewed exception is
  recorded.

### Security

- Canonicalization now accepts only the closed JSON signing domain and refuses
  non-plain objects, sparse or extended arrays, accessors, symbol members,
  cycles, non-JSON values, unsafe numbers, and malformed UTF-16 before hashing,
  signing, or verification. Complete receipt envelopes are inspected before
  member access, so hostile Proxy traps and hidden top-level properties also
  fail closed instead of escaping or disappearing through a shallow copy.
- Every Trust Receipt result now states that offline authenticity is not
  current admission or replay prevention. Atomic one-time admission remains a
  Gate/consumption-store responsibility.
- WebAuthn results expose `sign_count`, backup eligibility/state, and a
  counter-status signal without treating a non-increasing counter as proof of
  cloning.
- A relying-party clock now refuses future `issued_at`, `signed_at`, and
  consumption `committed_at` values instead of granting presenter-controlled
  future-time tolerance; the reliance kernel forwards its exact decision clock
  into that verification rather than relying on a duplicate caller option.
- Trust Receipt decisions explicitly report whether ordered-quorum linkage was
  merely presented or was evaluated by `verifyQuorum`; base receipt
  verification no longer leaves that policy boundary implicit.

## 3.18.2 (2026-07-29)

### Documentation

- Specify the exact current-profile checkpoint object and signing input used
  by `verifyTrustReceipt`, including that Ed25519 signs the raw SHA-256 digest
  of the UTF-8 JCS bytes rather than JSON text or an encoded digest string.

## 3.18.1 (2026-07-29)

### Fixed

- The reusable npm release workflow now checks the reviewed security case and
  conformance manifest in place instead of regenerating them immediately
  before the proof and reproducibility gates. This preserves the clean,
  commit-bound checkout those gates are designed to require.

## 3.18.0 (2026-07-29)

### Added

- Independent industrial-effect evidence and effect-predicate evaluation for
  outcome binding, preserving executor claims, mediator evidence, and
  independently observed system-of-record evidence as separate inputs.
- A relying-party-pinned PSEA-02 verifier and AEB adapter with exact CAID
  matching, current-status checks, explicit source-semantic loss handling,
  and closed `VERIFIED`, `ACCEPTED`, `SATISFIED`, and `AUTHORIZED` states.
- PEDIGREE composition vectors that keep native PEDIGREE verification
  authoritative while testing the separate CAID and AEB decision legs.

### Security

- PSEA and PEDIGREE evidence cannot authorize an action by themselves. AEB
  still requires the relying party's pinned trust configuration, exact-action
  match, evidence requirements, current status, and local authorization.
- Missing or materially lossy source semantics, stale or revoked evidence,
  indeterminate native status, and effect evidence supplied only by the
  executor fail closed instead of being upgraded into authority or outcome
  truth.

## 3.17.1 (2026-07-29)

### Security

- Trust Receipt verification now treats `compromised_at` in a pinned approver
  key entry as terminal and retroactive instead of as another presenter-time
  validity edge. A stolen key therefore cannot clear verification by
  backdating the signed `issued_at`.
- An optional relying-party `now` refuses presenter-claimed issuance more than
  five minutes in the future while preserving offline historical verification
  when no verifier clock is supplied.
- JavaScript, Python, and Go apply the same rule and agree on shared negative
  conformance vectors.

## 3.17.0 (2026-07-28)

### Added

- AEB execution and Agent Edge Continuity authorization results now carry the
  exact relying-party-pinned `program_digest` that governed the decision.

### Security

- Positive execution authorization refuses when the evaluator's pinned
  configuration digest is absent. Historical verification, evidence
  satisfaction, and local authorization remain separate from executable
  authority.
- Refusal and reconciliation-required results retain an auditable policy
  citation without upgrading either result into authorization.

## 3.16.1 (2026-07-27)

### Added

- `./aeb-consequence-conformance`, a closed, deterministic 22-vector AEB-1
  reference self-test for native verification, relying-party acceptance,
  exact-action matching, evidence
  satisfaction, local authorization, one-time reservation, invocation custody,
  separate provider/effect truth, and authenticated reconciliation.
- `emilia-verify aeb-conformance --reference` emits the complete reference
  report; `--submission <report.json>` validates an offline self-assessment.

### Security

- The suite fails closed on stale, revoked, unavailable, mismatched, replayed,
  non-atomic, blindly retried, or unauthenticated evidence paths.
- `INVOKING` remains consumed custody, provider outcome never implies observed
  effect, and `local_atomic` never claims federated or remote atomicity.
- Reports are explicitly self-attested and non-authorizing; they do not claim
  audit, certification, deployment, complete mediation, or adoption.

## 3.16.0 (2026-07-26)

### Added

- `./gate-qualification`, a zero-network, storage-independent verifier for
  closed Gate Qualification v2 campaign graphs, runtime measurements,
  Qualification Statements, and current Qualification Status chains.
- `./gate-qualification-promptfoo`, a strict adapter that re-derives complete
  Promptfoo v3 result, lineage, coverage, metric, and immutable-pin bindings
  into evaluation-only evidence.
- Root-package re-exports and generated declarations for both modules.

### Security

- Qualification requires independently supplied trust policies, expected
  digests, trusted time, freshness bounds, and minimum model-pinning strength;
  malformed, stale, incomplete, untrusted, or equivocated graphs fail closed.
- Promptfoo output remains `EVALUATION_ONLY` and provider revision claims are
  not upgraded into authenticated model identity.
- `QUALIFIED` is explicitly non-authorizing and does not reserve, consume,
  invoke, or mutate anything.
- Decisions expose the signed protected-request digest; trust thresholds count
  distinct Ed25519 key material rather than aliases; and direct Promptfoo
  library use is bounded by byte, node, depth, and result-count ceilings.

## 3.15.1 (2026-07-26)

### Fixed

- The protected npm publisher now addresses its already-built, attested
  tarball as an explicit local file, preventing npm 11 from interpreting the
  workspace-relative path as a GitHub repository shorthand.

There are no verifier API, wire-format, or runtime-behavior changes in this
patch release.

## 3.15.0 (2026-07-25)

### Added

- Revision-pinned native WIMSE, OAuth Transaction Token, SPT, and HTTP
  signature evidence verification with exact CAID and request-target mapping.
- Signed discovery-permit evidence that binds the resolver configuration,
  source provenance, evaluation time, action digest, and CAID under a
  relying-party-pinned Ed25519 key.
- Public `./aeb-wimse-oauth-adapter`, `./aeb-discovery-permit-adapter`, and
  `./discovery-permit-contract` package exports with conformance vectors.

### Security

- Discovery results are not trusted merely because their fields are internally
  consistent. Verification requires the pinned resolver attestation and
  rechecks source, time, configuration, action, and CAID bindings.
- WIMSE-family evidence remains a delegated-workload evidence leg. It cannot
  fill human authorization, quorum, or local Gate authority requirements.

## 3.14.0 (2026-07-22)

### Added

- `./aeb-adapter-contract`, the relying-party-pinned evidence-adapter boundary
  with deterministic native verification, loss-detecting CAID mapping,
  signed and re-derivable evaluation records, and durable execution lifecycle.
- First-class AEB requirement terms for distinct-human quorum, initiator and
  executor exclusion, and mandatory one-time consumption.
- Concrete relying-party-pinned AgentROA and ORPRG AEB adapters with exact
  CAID mapping and stable native replay identities.
- `./status`, a signed current-status profile with scoped revoker authority,
  freshness, monotonic sequence, predecessor binding, and terminal revocation.
- `./agent-edge-continuity`, a relying-party-pinned provenance and
  action-lineage profile across user, harness, model, MCP, A2A, and effect
  boundaries.

### Security

- Native verification, relying-party acceptance, evidence satisfaction, and
  local authorization remain separate states. Presenter-selected adapters,
  trust roots, mappings, registries, or requirements are refused.
- Stale, revoked, unavailable, materially lossy, mismatched, non-rederivable,
  or replayed evidence fails closed before execution.
- Historical AEB re-derivation is explicitly non-authorizing. Execution mode
  requires the exact action, a verifier clock, fresh authenticated status for
  every leg, and a cryptographically validated Ed25519 evaluator key.
- Federation refuses post-retirement issuance and DNS-rebindable online
  transports; all resolved addresses and the connected address must satisfy a
  relying-party-pinned network boundary, with redirects disabled.
- ORPRG inspection is non-mutating and never claims final native authorization;
  the Gate must atomically reserve its native replay unit with the AEB action.
- Continuity execution requires execution-mode AEB verification and binds the
  operation, proposal, relying party, configuration, initiator, executor, CAID,
  and action. Signer authority is scoped by source, edge, status, and time.
- Fleet execution atomically reserves continuity IDs and handoff nonces with
  native AEB replay identities. Post-effect observations cannot authorize, and
  `INDETERMINATE` remains under Proposal-to-Effect custody.

## 3.12.0 (2026-07-21)

### Added

- Closed Authority Program verification with mandatory relying-party root
  action re-performance, predecessor-stage digest binding, organization and
  execution checks, and explicit freshness/revocation decisions.
- Platform-attestation evidence verification and citeable authority/evidence
  composition artifacts aligned with the shared conformance vectors.

### Security

- Authority programs cannot authorize a presenter-supplied root action. The
  relying party must retrieve or own the root action and independently
  recompute its CAID and action digest.

## 3.11.0 (2026-07-17)

### Added

- `./document-action-binding`, a typed verifier for joining exact final
  document bytes, material terms, and a consequential release action.
- Closed `match`, `mismatch`, and `invalid` results so a malformed or
  differently bound document cannot be mistaken for an authorized action.

## 3.10.1 (2026-07-16)

### Security (please upgrade)

- A validly signed denial remains portable decision evidence but can no longer
  contribute an approver identity, assurance class, authority subject, signed
  action material, or quorum member toward authorization or reliance.
- JavaScript, Python, and Go now share a refusal vector proving that a signed
  denial cannot verify as authorization. The reliance kernel separately tests
  mixed approved/denied receipts and a valid device-signed denied quorum member.

## 3.10.0 (2026-07-15)

### Security (please upgrade)

- Human signoffs, quorum members, provenance links, resolution receipts, trust
  receipts, and evidence-chain components now enforce relying-party ID and
  origin scope consistently across JavaScript, browser, Python, and Go ports.
- Role, issuer, approver, authority, profile-registry, and key-class decisions
  are derived from relying-party pins rather than presenter-controlled labels,
  embedded keys, or self-asserted metadata.
- Strict JSON parsing rejects duplicate members before security-relevant
  canonicalization. SPKI identity comparisons use canonical fingerprints so
  alternate encodings cannot fill multiple quorum seats or alias a pinned key.
- Reliance evaluation now requires an exact action join, pinned organizational
  quorum policy, and pinned registry identity. The CLI treats `--key` as an
  authoritative trust anchor and exposes RP/origin policy flags.
- Shared conformance adds cross-origin, key-role, authority, provenance, and
  hostile-parser refusals. The release security case binds the executable
  claims to the current artifacts and cross-language vectors.

### Changed

- Some artifacts accepted by earlier releases will now be refused until the
  verifier is supplied with the relying party's explicit trust roots, RP ID,
  origin allowlist, and required quorum/profile policy. This is intentional
  fail-closed behavior.

## 3.9.0 (2026-07-14)

### Added

- Additive `EP-RESOLUTION-v1` verifier for durable, device-signed
  `approved | declined | amended | rejected` binding-moment outcomes. Receipt
  validity is separate from execution authority: only an authentic approval
  under a complete relying-party-pinned acceptance context (role key, RP ID,
  origin, option mapping, nonce, initiator, and in-window evaluation time) sets
  `authorizes_action: true`.

### Changed

- `verifyAuthorizationChain` now names its evidence-layer result `satisfied`.
  The `allow` member remains as an equal compatibility alias; authorization is
  still a separate relying-party decision.
- Terminal revocations no longer age out through `maxAgeSeconds`. Verification
  rejects future-effective and impossible calendar timestamps, malformed
  targets, non-Ed25519 algorithm labels, and signatures outside the pinned
  revoker context. Fresh non-revocation status remains a separate input.
- Future-dated currency/status heads now return `stale`, never `fresh`.
- JavaScript, Python, and Go carry the same resolution, revocation, currency,
  and evidence-satisfaction behavior under the shared conformance vectors.

## 3.8.0 (2026-07-09)

### Security (please upgrade)
An adversarial audit found and this release closes a class of verifier
acceptance holes. Reproduced with running exploits, fixed across all four ports
(this package, `lib/`, `emilia-verify` Python 2.5.0, `go-verify` v2.2.0).

- **Principal substitution (critical).** `verifyTrustReceipt` attributed an
  approval to the signer-controlled `ctx.approver` while only checking the
  signature against `approverKeys[approver_key_id]`, with nothing binding the
  key to the named approver. A single low-privilege pinned key could name itself
  any approver (e.g. the CFO) and forge a full multi-party quorum. **Breaking,
  required migration:** each entry in the `approverKeys` directory MUST now carry
  `approver_id`, and a signoff verifies as that approver only when
  `keyEntry.approver_id === ctx.approver`. Directories without `approver_id` will
  now refuse. This is the fix; add the owning approver to every pinned key.
- **Issuer-pin scope bypass (high).** `verifyAuthorityProof` fell back to the
  first public-key match when the issuer-scoped match failed, so a key pinned
  for one authority authenticated another's proof and `pin_mismatched_issuer`
  was unreachable. The issuer pin is now authoritative and fail-closed.
- **Missing action binding (high).** `evaluateReliance` skipped the action-hash
  join when either side was absent, so a valid receipt for one action could be
  relied on for another. The join is now mandatory.
- **Amount ceiling and evidence requirements (high).** The authority amount
  ceiling is now a decimal comparison (numeric-string amounts enforced,
  unprovable amounts refused), and an unknown `required_evidence` name is
  rejected instead of silently ignored.
- Hostile-input hardening of every public verifier entry point.

## 3.7.1 (2026-07-09)

### Security
Delegation-chain head anchoring no longer trusts `parent_ref`. `parent_ref` is
not in `DELEGATION_PROOF_FIELDS`, so it is unsigned and attacker-controlled: a
validly-signed head link whose delegator is a stranger could set `parent_ref`
to a real root approver and falsely attribute the whole chain to a human who
never delegated (authority laundering / false attribution). The
`chain_anchored` check now anchors ONLY on the SIGNED `head.delegator`. Breaks
zero legitimate chains (a valid head's delegator is always the root approver).
Fixed uniformly in this package, `lib/provenance`, `emilia-verify` (Python
2.4.4), and `go-verify` (v2.1.4). Regression vector
`reject_forged_parent_ref_anchor` in `conformance/vectors/delegation-integrity.v1.json`
locks it in all three languages.

## 3.7.0 (2026-07-08)

### Added
The reliance layer: `EP-RELIANCE-KERNEL-v1` (the closed rely / do_not_rely_*
verdict set), `EP-RELIANCE-PROFILE-v1` and the signed, pinnable
`EP-RELIANCE-PROFILE-REGISTRY-v1` for regulated profiles, and the reliance-gap
acceptance preflight (library + CLI). Authority subject is bound to the
verified signer and a pinned profile is required.

### Security
Closed the type-coercion / assertion class across all three ports; closed 6
digest-divergence / mutation-after-sign holes and 6 malformed-input /
type-coercion holes from the surface audit; `verifyReceipt` pins the Ed25519
issuer key (Node/web parity).

## 3.6.1 (2026-07-06)

### Added
`receiptGrantBindingStrength(receipt, grantHash?)` (`./consent-grant`), returning
`signed_action | top_level | caller_override | none`, and a top-level
`binding_strength` field on `verifyReceiptUnderGrant` results. A receipt binds to
a consent grant most strongly when it carries `grant_hash` inside its SIGNED
Action Object (covered by the human signature); a caller-supplied hash is still
honored but labeled `caller_override` (advisory, only as trustworthy as the
caller). `receiptReferencedGrantHash` now prefers the signed reference over any
override. The `witness` and `consumption-proof` reference emitters are now
reachable as package subpaths (`@emilia-protocol/verify/witness.js`,
`@emilia-protocol/verify/consumption-proof.js`).

## 3.6.0 (2026-07-06)

### Added
**EP-CONSENT-GRANT-v1** (`./consent-grant`): the scoped, revocable STANDING
consent grant naming `{asset, control_verb, expiry}`. It fills binding 3 (Consent
Grant) of the Command Authority Envelope (draft-morrison-ot-command-authority) as
its own first-class object, DISTINCT from the per-action receipt at the binding
moment (CAE binding 4, which is what an EP receipt IS). The grant is standing
authority issued once over a window; the receipt is the per-action authorization.

- **The object.** `{ profile: "EP-CONSENT-GRANT-v1", grant_id, principal, asset,
  control_verb, constraints?, issued_at, expires_at, grant_hash, signature }`.
  `grant_hash` is `sha256:` over the JCS/RFC-8785 canonical bytes of the grant
  with grant_hash and signature excluded; `signature` is the principal's
  device-bound Ed25519 signature over those same bytes. Reuses the package's
  `canonicalize()` + SHA-256 and the `crypto.verify(null, ...)` Ed25519
  convention exactly, no new primitives.
- **`buildConsentGrant(spec, signer)`** reference issuer (stamps grant_hash,
  signs), plus `computeGrantHash(grant)` / `verifyGrantHash(grant)`.
- **`verifyConsentGrant(grant, pinnedPrincipalKey, { now, revocation, revokerKeys })`**
  returns `{ valid, checks: { hash, signature, within_window }, reason? }`.
  Fail-closed with a distinct reason: a bad grant_hash, an unpinned or bad
  principal signature, a `now` outside `[issued_at, expires_at]`, or a valid
  revocation statement binding the grant_hash (`grant_revoked`). Revocation is
  checked with the existing `verifyRevocation` against a `commit`-typed target
  keyed on grant_hash; an unpinned revoker cannot revoke.
- **`verifyReceiptUnderGrant(receipt, grant, opts)`** is the composition: the
  per-action receipt acts under the grant by carrying grant_hash. Returns
  `{ ok, checks: { grant, asset_covered, verb_covered, grant_binding }, reason? }`
  and refuses with a distinct reason on any mismatch: `grant_signature_invalid`,
  `grant_expired`, `grant_revoked`, `asset_mismatch`, `verb_mismatch`,
  `grant_binding_mismatch`. What it proves: the grant is authentic and in-window
  and the receipt is scoped-and-bound to it. What it does NOT prove: business
  correctness, or CURRENT validity. Offline verification of either artifact is
  authenticity as of commit; revocation currency needs a fresh revocation
  snapshot, the same as any EP status.

Schema: `public/schemas/ep-consent-grant.schema.json`. Spec:
`docs/EP-CONSENT-GRANT-SPEC.md`. This is a candidate profile to fold into the
authority / receipts drafts in a future revision, shipped in code today.

### Changed
**timestamp-proof (RFC 3161) is now cross-language.** The `timestamp-proof.js`
minimal DER/CMS reader was ported faithfully to Python (`packages/python-verify`,
`verify_timestamp_proof`) and Go (`packages/go-verify`, `VerifyTimestampProof`).
The Python port hand-rolls the same minimal DER reader in pure Python and uses
`cryptography` only for the RSA/ECDSA signature verify (no new dependency); the Go
port uses a pure-stdlib DER reader plus `crypto/rsa` / `crypto/ecdsa` /
`crypto/x509`. A new shared vector suite
(`conformance/vectors/timestamp-proof.v1.json`, 13 vectors minted from a local
test TSA with `openssl`) runs in `conformance/run.mjs`, where the JavaScript,
Python, and Go verifiers must agree, including the exact per-vector refusal path.
This supersedes the earlier "timestamp proof remains JavaScript-only" note in the
3.5.0 entry below.

## 3.5.0 (2026-07-05)

### Added
Five ADDITIVE, OPT-IN transparency/currency knobs in `verifyTrustReceipt`, each
following the existing `priorCheckpoint` pattern: a knob runs ONLY when its
option is supplied, adds exactly one member to `checks` when active, folds into
`valid` by conjunction, and fails closed with a distinct reason. With NO knob
option supplied the result is byte-for-byte unchanged (the frozen seven-member
`checks` set, no extra top-level members). Each knob's full module result is
surfaced under a dedicated, option-gated top-level member.

- **Witness cosignatures (EP-WITNESS-v1).** `opts.witnessQuorum = { cosignatures,
  pinnedWitnessKeys, k }` requires at least `k` DISTINCT pinned witnesses to have
  validly cosigned the receipt's checkpoint head. Adds `checks.witness_quorum`
  and surfaces `result.witness_quorum`. Fail-closed: a receipt with no checkpoint,
  a bad `k`, or fewer than `k` distinct valid cosignatures each refuse. What it
  proves: `k` trusted witnesses attested to ONE head (the local, single-view half
  of equivocation detection). What it does NOT prove: that no different head was
  shown to someone else (that cross-view gossip is the deployment's job).
- **Trusted-time proof (RFC 3161).** `opts.timestampProof = { token,
  expectedDigest, pinnedTsaKeys }` verifies a TSA timestamp token over a
  caller-chosen digest against a PINNED TSA key. Adds `checks.timestamp_proof`
  and surfaces `result.timestamp_proof`. Fail-closed: a missing token, a
  missing/malformed digest, an unpinned TSA, or a bad signature each refuse with
  a distinct reason. What it proves: a TSA asserted the digest existed at
  `gen_time` (the bytes predate `gen_time`). What it does NOT prove: that the
  action was correct or authorized, and it is authentic-as-of-token only (it says
  nothing about current TSA-certificate validity or revocation, which needs a
  fresh online check).
- **Currency evaluation (EP-CURRENCY-v1).** `opts.currency = { now,
  maxStalenessSeconds, freshHead, freshHeadRequired }` evaluates currency-at-T on
  a separate axis from offline authenticity. Adds `checks.currency`, which passes
  ONLY when a supplied recent non-revoking signed head proves status `fresh`.
  BOTH `stale` AND the honest offline default `unknown` FAIL this opted-in gate:
  offline verification can NEVER establish currency, so absence of proof of
  freshness does not pass (fail-closed). The full two-axis result
  (`authentic_as_of_commit` plus `currency_at_T` with status, evaluated_at, and a
  stable reason string) is surfaced as `result.currency` so a caller can tell
  `unknown` (offline only) apart from `stale` (a head that is too old, was
  required but absent, or shows revocation). `maxStalenessSeconds` is an
  action-policy field (tighter for higher-consequence, irreversible actions), not
  a global verifier constant.
- **Consumption proof (EP-SMT-CONSUME-v1).** `opts.consumptionProof` is a
  third-party bundle proving a one-time nonce transitioned absent to present
  exactly once across two append-only-linked heads. Adds `checks.consumption` and
  surfaces `result.consumption`. Fail-closed: any missing, malformed, or invalid
  sub-proof, a non-append-only h1 to h2 link, a present-at-h1, or an absent-at-h2
  each refuse with a distinct reason (`present` is never inferred). What it
  proves: the tree-shaped consumption facts only. What it does NOT prove: the
  checkpoint SIGNATURES (the caller authenticates those separately) or currency of
  the later head.
- **Initiator-software attestation (EP-INITIATOR-ATTESTATION-v1).**
  `opts.requireInitiatorAttestation === true` structurally validates the
  self-asserted initiating-software attestation at
  `receipt.action.initiator_software` (model_id, model_version,
  tool_chain_digest, optional neutralized statement). Adds
  `checks.initiator_attestation` and surfaces `result.initiator_attestation`.
  Fail-closed: an absent or malformed attestation is `false` (the validator never
  repairs a malformed one). What it proves: WHICH software asked. What it does NOT
  prove: that the software behaved (the labels are self-asserted, and the digest
  is authentic-as-supplied, not proof of correct execution).

The five modules (`witness.js`, `timestamp-proof.js`, `currency.js`,
`consumption-proof.js`, `initiator-attestation.js`) now ship in the published
package, and their standalone functions and constants are re-exported from the
package entry (`verifyWitnessCosignature`, `requireWitnessQuorum`,
`witnessSigningDigest`, `WITNESS_VERSION`, `WITNESS_DOMAIN_TAG`,
`verifyTimestampProof`, `TIMESTAMP_PROOF_ALG`, `evaluateCurrency`,
`CURRENCY_VERSION`, `CURRENCY_STATUS`, `CURRENCY_REASON`,
`verifyConsumptionProof`, `ReferenceConsumptionTree`, `CONSUMPTION_PROFILE`,
`CONSUMPTION_LEAF_DOMAIN`, `SMT_DEPTH`, `validateInitiatorAttestation`,
`neutralizeStatement`, `normalizeDigest`, `bindInitiatorAttestation`,
`INITIATOR_ATTESTATION_VERSION`, `INITIATOR_ATTESTATION_FIELD`,
`INITIATOR_STATEMENT_MAX`), with TypeScript types in `index.d.ts`. Note: the
in-repo JS reference verifiers are one team's cross-language ports, not
clean-room independent implementations. EP-CURRENCY-v1, EP-WITNESS-v1,
EP-SMT-CONSUME-v1, and EP-INITIATOR-ATTESTATION-v1 are now ported to Python
(`packages/python-verify`) and Go (`packages/go-verify`) and run cross-language
in `conformance/run.mjs` over shared vector suites (`currency.v1.json`,
`initiator-attestation.v1.json`, `consumption-proof.v1.json`, `witness.v1.json`),
where the JS, Python, and Go verifiers must agree. **Timestamp proof (RFC 3161)
remains JavaScript-only** — its Python/Go ports were deferred because neither the
Python `cryptography` dependency nor the zero-dependency Go module exposes a
CMS/PKCS#7 SignedData / TSTInfo parser, so it has no cross-language vector suite.

## 3.4.0 (2026-07-05)

### Added
- **Opt-in append-only consistency check** in `verifyTrustReceipt`: pass
  `opts.priorCheckpoint = { tree_size, root_hash, consistency_proof }` (a
  checkpoint head you previously observed and pinned, plus the RFC 6962
  consistency proof from that head to the receipt's checkpoint) and the
  verifier adds a fail-closed `checks.consistency` gate. A malformed pin, a
  missing proof, an unusable receipt checkpoint, or an invalid proof each
  refuse with a distinct reason. Honesty note: this proves append-only
  consistency between two observed heads; it does NOT establish currency or
  split-view honesty by itself (that needs independent witnesses).
  `verifyCheckpointConsistency` and `CONSISTENCY_ALG` are now exported from
  the package entry, and `consistency.js` ships in the published package.

### Fixed
- **Empty inclusion path degenerate case (fail-closed).** An empty
  `log_proof.inclusion_path` used to collapse to `leafHash === root_hash` for
  ANY claimed `tree_size`, so a forged checkpoint whose root simply repeated
  the leaf hash would pass. An empty path is now accepted only when the
  checkpoint's `tree_size` is exactly the integer 1 (and `leaf_index`, when
  present, is 0). Any other tree size with an empty path is refused with a
  distinct reason. Applies to both EP-MERKLE-v2 and opt-in legacy folds.
  Behavior for non-empty paths is unchanged.

## 3.0.0 — 2026-06-28

### Changed (BREAKING)
- **Canonicalization is now strict and cross-language byte-identical.** Signed
  material must be strings or safe integers; `verifyReceipt` fails closed on
  payloads outside the profile (non-integer/unsafe numbers, etc.). Fixes the
  JS/Python/Go consensus split — the same payload now hashes identically in all
  three. (`isCanonicalizable` is exported.)
- **Legacy EP-MERKLE-v1 anchors are refused by default.** Production verification
  requires EP-MERKLE-v2 (domain-separated, payload-bound). v1 anchors verify only
  with the explicit `{ allowLegacyMerkle: true }` opt-in — preserving the
  "receipts verify forever" promise for old artifacts without carrying live v1
  risk. New issuance is v2-only.

### Migration
- If you verify pre-v2 anchored receipts, pass `{ allowLegacyMerkle: true }`.
- Ensure signed payloads use strings or integers (no floats like `1.5`/`-0.0`).

## 2.1.0 — 2026-06-25

### Added
- `evaluateAgentBinding(context, { maxAgeSec, at })` (PIP-008 §2.1, L4→L7
  binding): surfaces the external agent-identity / delegation evidence a
  decision relied on (`agent_id`, `delegation {scheme, ref, hash}`,
  `observed_at`) and, when `maxAgeSec` is set, enforces freshness **fail-closed**
  — missing, future-dated, or over-age `observed_at` yields `fresh: false` with
  a reason. With no `maxAgeSec`, evidence is recorded (`fresh: null`) for audit.
  Lets a PDP record which upstream evidence backed a human authorization and
  detect a stale/unconstrained upstream claim after the fact. Additive; no
  change to existing verifier behavior.

## 2.0.0 — 2026-06-23

### Breaking

- **`verifyCommitmentProof()` now rejects unsigned proofs by default.** Previously a
  proof with no signature / no pinned public key was silently accepted. It now returns
  `{ valid: false, error: 'Signature and public key are required' }`. Callers that
  genuinely need to accept an unsigned commitment must opt in explicitly:
  `verifyCommitmentProof(proof, null, { allowUnsigned: true })`. This closes a
  silent-accept gap — the verifier no longer vouches for proofs nothing actually signed.

### Added

- **Strict verifier mode** — `verifyTrustReceipt(receipt, key, { strict: true, rpId, expectedPolicyHash })`.
  Opt-in and safe by default: without `strict: true` the verifier behaves exactly as in
  1.x (`strict: { enabled: false, valid: true, checks: {} }`), so existing callers and
  conformance suites are unaffected. When enabled, the receipt must additionally satisfy:
  - `pinned_keys` — every signoff names an `approver_key_id` resolving to a pinned public key; a trusted `logPublicKey` anchors the log
  - `rp_id` — Class-A WebAuthn `rpIdHash` matches the caller-supplied `rpId`
  - `user_presence` / `user_verification` — Class-A signoffs assert the UP and UV flags
  - `key_windows` — pinned keys carry `valid_from`/`valid_to`, and each signoff's context `issued_at` falls inside its key's validity window
  - `policy_hash` — every context carries a `policy_hash` matching the caller-supplied `expectedPolicyHash`
  - `no_unsigned` — no critical proof is accepted unsigned
- Public TypeScript types for strict mode: `VerifyStrictOptions`, `StrictReport`, `VerifyReceiptOptions`.

### Notes

This release makes third-party offline verification strict enough to stand on its own:
an outside auditor can pin keys, policy, and RP identity and get a hard pass/fail without
trusting the issuer's server. 108/108 package tests; cross-language conformance (JS/Py/Go) green.
