# EP Red Team Case Registry

Catalog of every adversarial scenario the Emilia Protocol has been tested against. Each case identifies the threat class, attack description, expected defensive behavior, test coverage, and code mitigation.

Threat classes reference GOD FILE section 9.1 taxonomy.

---

## Identity & Authority Attacks

### RT-001: Actor spoofing via request body

- **Threat class**: Actor spoofing
- **Attack description**: Attacker supplies a forged `entity_id` in the request body, attempting to act as a different entity.
- **Expected result**: Reject. `resolveAuthority()` derives actor from auth middleware, never from `request.body`.
- **Test coverage**: `adversarial-breakage.test.js` line 344 -- "protocolWrite with actor that does not match resolved authority still resolves correctly"
- **Code mitigation**: `lib/protocol-write.js` `resolveAuthority()`; Invariant 2 (INVARIANTS.md)

### RT-002: Role spoofing -- wrong entity presents for party role

- **Threat class**: Role spoofing
- **Attack description**: Entity A (authenticated) submits a presentation for a party role assigned to Entity B.
- **Expected result**: Reject with `ROLE_SPOOFING` (HTTP 403).
- **Test coverage**: `handshake-attack.test.js` line 550 -- "party cannot present as a different party_role"; `handshake-invariants.test.js` `checkNoRoleSpoofing`
- **Code mitigation**: `lib/handshake/present.js` line 123; `lib/handshake/invariants.js` line 270 `checkNoRoleSpoofing()`

### RT-003: Initiator binding violation -- actor != initiator party

- **Threat class**: Actor spoofing
- **Attack description**: Attacker calls `initiateHandshake()` but authenticated entity does not match the initiator party's `entity_ref`.
- **Expected result**: Reject with `INITIATOR_BINDING_VIOLATION` (HTTP 403).
- **Test coverage**: `handshake-attack.test.js` line 1187 -- "rejects handshake when actor does not match initiator entity_ref"
- **Code mitigation**: `lib/handshake/create.js` line 99

### RT-004: Delegate binding violation -- delegate exceeds principal scope

- **Threat class**: Delegation abuse
- **Attack description**: A delegate attempts to initiate a handshake with scope exceeding what the principal granted.
- **Expected result**: Reject with `DELEGATE_BINDING_VIOLATION` (HTTP 403).
- **Test coverage**: Delegation tests; `conformance.test.js` delegation scope checks
- **Code mitigation**: `lib/handshake/create.js` line 121; `lib/delegation.js` scope validation

### RT-005: Non-participant entity adds presentation

- **Threat class**: Role spoofing
- **Attack description**: An entity not listed in any party role attempts to add a presentation to a handshake.
- **Expected result**: Reject -- role not found for the authenticated entity.
- **Test coverage**: `handshake-attack.test.js` line 563 -- "non-participant entity cannot add presentation"
- **Code mitigation**: `lib/handshake/present.js` party lookup by entity_ref

### RT-006: Issuer spoofing -- unknown issuer in presentation

- **Threat class**: Issuer spoofing
- **Attack description**: Presentation references an `issuer_ref` that does not exist in the `authorities` registry.
- **Expected result**: Presentation stored with `verified = false`, `issuer_status = 'authority_not_found'`.
- **Test coverage**: `handshake-attack.test.js` line 816 -- "unknown/unregistered issuer defaults to untrusted"; `handshake-invariants.test.js` `checkIssuerTrusted`
- **Code mitigation**: `lib/handshake/present.js` authority lookup; `lib/handshake/invariants.js` `checkIssuerTrusted()`

### RT-007: Revoked authority used for presentation

- **Threat class**: Stale authority root
- **Attack description**: Presentation references an authority whose status has been set to `revoked` in the registry.
- **Expected result**: Presentation marked unverified; verification adds `issuer_revoked_{role}` reason code, handshake rejected.
- **Test coverage**: `handshake-attack.test.js` line 785 -- "presentation from revoked authority is rejected"; line 835 -- "authority revoked before presentation is added"
- **Code mitigation**: `lib/handshake/invariants.js` `checkAuthorityNotRevoked()`; `lib/handshake/verify.js` revocation_status check

### RT-008: Expired authority used for presentation

- **Threat class**: Stale authority root
- **Attack description**: Authority's `valid_to` date is in the past.
- **Expected result**: `revocation_status` set to `expired`; presentation marked unverified.
- **Test coverage**: `handshake-attack.test.js` line 1368 -- "sets revocation_status to expired for expired authorities"
- **Code mitigation**: `lib/handshake/present.js` authority validity window check

### RT-009: Not-yet-valid authority

- **Threat class**: Stale authority root
- **Attack description**: Authority's `valid_from` date is in the future.
- **Expected result**: `revocation_status` set to `not_yet_valid`; presentation marked unverified.
- **Test coverage**: `handshake-attack.test.js` line 1389 -- "sets revocation_status to not_yet_valid for future authorities"
- **Code mitigation**: `lib/handshake/present.js` authority validity window check

### RT-010: Forged authority key_id in commit

- **Threat class**: Issuer spoofing
- **Attack description**: Attacker creates a commit with their own key but an unknown `kid` not in the trusted key registry.
- **Expected result**: `verifyCommit` returns `valid: false` with reason `unknown_kid`.
- **Test coverage**: `adversarial-breakage.test.js` line 304 -- "forged authority_id in commit fails with unknown_kid"; line 400 -- "unknown kid returns unknown_kid reason"
- **Code mitigation**: `lib/commit.js` `verifyCommit()` kid lookup against trusted registry

### RT-011: Self-scoring prevention

- **Threat class**: Actor spoofing
- **Attack description**: Entity submits a receipt scoring itself (submitter == target entity).
- **Expected result**: Reject via `createReceipt` self-scoring guard.
- **Test coverage**: `adversarial-breakage.test.js` line 269 -- "auto-submit with entity_id that does not match authenticated principal is rejected"
- **Code mitigation**: `lib/canonical-writer.js` `canonicalSubmitAutoReceipt()` self-score check

### RT-012: System actor bypass for initiation

- **Threat class**: Actor spoofing (negative test)
- **Attack description**: The `system` actor initiates a handshake on behalf of any entity.
- **Expected result**: Allowed -- system actor is exempt from entity_ref binding.
- **Test coverage**: `handshake-attack.test.js` line 1213 -- "allows system actor to initiate for any entity"
- **Code mitigation**: `lib/handshake/present.js` system actor exemption

---

## Replay & Reuse Attacks

### RT-013: Commit nonce replay

- **Threat class**: Replay
- **Attack description**: Attacker forges a commit record reusing a nonce from a legitimate commit.
- **Expected result**: `verifyCommit` returns `valid: false` with reason `nonce_reuse`.
- **Test coverage**: `adversarial-benchmarks.test.js` line 698 -- "same nonce on different commit is detected as replay"; `adversarial-breakage.test.js` line 176 -- "submitting the same commit nonce twice is rejected"
- **Code mitigation**: `lib/commit.js` `verifyCommit()` nonce dedup query

### RT-014: Unique nonce generation

- **Threat class**: Replay (prevention)
- **Attack description**: Two sequentially issued commits must have distinct 32-byte random nonces.
- **Expected result**: Nonces differ; each matches `/^[0-9a-f]{64}$/`.
- **Test coverage**: `adversarial-benchmarks.test.js` line 768 -- "each issued commit gets a unique nonce"
- **Code mitigation**: `lib/commit.js` `issueCommit()` cryptographic nonce generation

### RT-015: Replayed presentation with same hash

- **Threat class**: Replay
- **Attack description**: Attacker replays a presentation hash from one handshake into a different handshake.
- **Expected result**: Rejected -- binding mismatch (presentation bound to wrong handshake).
- **Test coverage**: `handshake-attack.test.js` line 371 -- "replayed presentation with same hash is rejected"
- **Code mitigation**: `lib/handshake/verify.js` binding hash comparison

### RT-016: Replayed nonce on different handshake

- **Threat class**: Replay
- **Attack description**: Attacker reuses a nonce from handshake A when creating handshake B.
- **Expected result**: Each handshake gets a unique nonce; verification detects mismatch.
- **Test coverage**: `handshake-attack.test.js` line 401 -- "replayed nonce on different handshake is rejected"
- **Code mitigation**: `lib/handshake/invariants.js` nonce uniqueness; `lib/handshake/create.js` nonce generation

### RT-017: Replayed binding from expired handshake

- **Threat class**: Replay
- **Attack description**: Attacker attempts to use a binding from an expired handshake for verification.
- **Expected result**: Rejected at verification -- handshake expired.
- **Test coverage**: `handshake-attack.test.js` line 419 -- "replayed binding from expired handshake is rejected at verification"
- **Code mitigation**: `lib/handshake/verify.js` expiry check; `lib/handshake/invariants.js` `checkNotExpired()`

### RT-018: Presentation replay after handshake finalization

- **Threat class**: Replay
- **Attack description**: Attacker submits a presentation to a handshake that has already been finalized (verified/rejected).
- **Expected result**: Rejected -- handshake status prevents adding presentations.
- **Test coverage**: `handshake-attack.test.js` line 439 -- "presentation replay after handshake finalization is rejected"
- **Code mitigation**: `lib/handshake/present.js` status guard

### RT-019: Double consume race (100-way)

- **Threat class**: Replay / double-spend
- **Attack description**: 100 concurrent threads attempt to consume the same verified handshake simultaneously.
- **Expected result**: Exactly 1 succeeds; 99 receive `ALREADY_CONSUMED` or unique constraint error (23505).
- **Test coverage**: `concurrency-warfare.test.js` line 552 -- "100 concurrent consume attempts -> exactly 1 succeeds"; line 577 -- "all 99 losers get ALREADY_CONSUMED errors"
- **Code mitigation**: `lib/handshake/verify.js` consumed_at hard gate; DB unique constraint on `handshake_consumptions`; conditional update `.is('consumed_at', null)`

### RT-020: Consume after revoke

- **Threat class**: Adjacent-action reuse
- **Attack description**: Attacker attempts to consume a handshake that has been revoked.
- **Expected result**: Rejected -- revoked is terminal.
- **Test coverage**: `handshake-adversarial.test.js` line 435 -- "rejects consumption after revocation"; `concurrency-warfare.test.js` line 678 -- "concurrent revoke and consume"
- **Code mitigation**: `lib/handshake/verify.js` status guard (line 83); `lib/handshake/consume.js` status guard

### RT-021: Consume after expire

- **Threat class**: Adjacent-action reuse
- **Attack description**: Attacker attempts to consume a handshake whose `expires_at` has passed.
- **Expected result**: Rejected -- expired is terminal.
- **Test coverage**: `handshake-adversarial.test.js` line 455 -- "rejects consumption of expired handshake"
- **Code mitigation**: `lib/handshake/verify.js` expiry check; `lib/handshake/invariants.js` `checkNotExpired()`

### RT-022: Consume after rejection

- **Threat class**: Adjacent-action reuse
- **Attack description**: Attacker attempts to consume a handshake that was previously rejected.
- **Expected result**: Rejected -- rejected is terminal.
- **Test coverage**: `handshake-adversarial.test.js` line 481 -- "rejects consumption of rejected handshake"
- **Code mitigation**: `lib/handshake/verify.js` status guard; `lib/handshake/consume.js` status guard

### RT-023: Verify after revoke

- **Threat class**: Adjacent-action reuse
- **Attack description**: Attacker attempts to verify a handshake that has been revoked.
- **Expected result**: Rejected -- revoked is terminal. Verification cannot flip a revoked handshake.
- **Test coverage**: `concurrency-warfare.test.js` line 911 -- "revoked handshake cannot be verified as accepted"; line 950 -- "verify cannot flip a revoked handshake back -- 10 attempts"
- **Code mitigation**: `lib/handshake/verify.js` line 83 status guard; `lib/handshake/finalize.js` terminal check

### RT-024: Adjacent-action reuse -- same binding, different target

- **Threat class**: Adjacent-action reuse
- **Attack description**: Attacker takes a valid presentation from handshake A and substitutes it into handshake B with a different target.
- **Expected result**: Rejected -- binding hash mismatch.
- **Test coverage**: `handshake-adversarial.test.js` line 517 -- "prevents same binding hash used for two different targets"; `handshake-attack.test.js` line 727 -- "substituting a valid presentation from a different handshake is rejected"
- **Code mitigation**: `lib/handshake/verify.js` binding hash comparison; `lib/handshake/bind.js` `checkBinding()`

### RT-025: Replaying an expired commit

- **Threat class**: Replay
- **Attack description**: Attacker replays a commit whose `expires_at` is in the past.
- **Expected result**: `verifyCommit` returns `valid: false`, `status: 'expired'`, with reason `expired`.
- **Test coverage**: `adversarial-breakage.test.js` line 201 -- "replaying an expired commit is rejected"
- **Code mitigation**: `lib/commit.js` `verifyCommit()` expiry check

### RT-026: Downstream action retry after consumption

- **Threat class**: Replay
- **Attack description**: After a binding is consumed, the downstream system retries the action (e.g., network timeout recovery).
- **Expected result**: Consumption guard rejects -- `binding_already_consumed`.
- **Test coverage**: `handshake-adversarial.test.js` line 653 -- "repeated downstream action retries hit consumption guard"
- **Code mitigation**: `lib/handshake/verify.js` consumed_at hard gate (lines 52-68); `lib/handshake/bind.js` `checkBinding()`

---

## Policy Attacks

### RT-027: Policy drift -- changed policy after binding

- **Threat class**: Policy drift
- **Attack description**: Policy content is modified after a handshake was initiated (binding includes original policy hash). Verification recomputes the hash and finds mismatch.
- **Expected result**: Rejected with reason code `policy_hash_mismatch`.
- **Test coverage**: `handshake-invariants.test.js` `checkAssuranceLevel`; verification tests with modified policies
- **Code mitigation**: `lib/handshake/verify.js` lines 114, 180 `computePolicyHash()` comparison; PROOF_STATUS.md S12

### RT-028: Missing policy at verification

- **Threat class**: Missing policy fields
- **Attack description**: Handshake has a `policy_id` but the policy record cannot be loaded at verification time.
- **Expected result**: Rejected with reason code `policy_not_found`.
- **Test coverage**: Verification tests with null policy resolution
- **Code mitigation**: `lib/handshake/verify.js` line 173 `policy_not_found` reason code; Invariant 7 (INVARIANTS.md)

### RT-029: Policy load failure

- **Threat class**: Missing policy fields
- **Attack description**: `resolvePolicy()` throws an exception at verification time.
- **Expected result**: Rejected with reason code `policy_load_failed`.
- **Test coverage**: Verification tests with policy exception simulation
- **Code mitigation**: `lib/handshake/verify.js` line 169 `policy_load_failed` reason code; Invariant 7

### RT-030: Assurance level downgrade

- **Threat class**: Policy evasion
- **Attack description**: Attacker provides presentations that achieve a lower assurance level than the policy minimum.
- **Expected result**: Rejected at verification -- assurance level below minimum.
- **Test coverage**: `handshake-attack.test.js` line 687 -- "assurance_level below policy minimum is rejected"; line 750 -- "downgrade from high to low assurance"
- **Code mitigation**: `lib/handshake/invariants.js` `checkAssuranceLevel()`

### RT-031: Missing required presentation

- **Threat class**: Policy evasion
- **Attack description**: Initiator attempts to verify a mutual handshake without the responder's required presentation.
- **Expected result**: Rejected -- `missing_presentation_{role}` reason code.
- **Test coverage**: `handshake-attack.test.js` line 575 -- "initiator cannot verify mutual handshake without responder presentation"; line 712 -- "missing required presentation causes rejection"
- **Code mitigation**: `lib/handshake/invariants.js` `checkAllPartiesPresent()`; `lib/handshake/verify.js` lines 122-131

---

## State Machine Attacks

### RT-032: Terminal state escape -- consumed to active

- **Threat class**: Terminal state escape
- **Attack description**: Attacker attempts to transition a consumed handshake back to an active state.
- **Expected result**: Rejected -- consumed is terminal, no outgoing transitions.
- **Test coverage**: `handshake-attack.test.js` line 909 -- "cannot transition from accepted/verified back to pending"
- **Code mitigation**: `lib/handshake/verify.js` status guard; `lib/handshake/finalize.js` line 78 terminal check; TLA+ `TerminalStateIrreversibility`

### RT-033: Backward transition -- rejected to verified

- **Threat class**: Backward transition
- **Attack description**: Attacker attempts to verify a handshake that was previously rejected.
- **Expected result**: Rejected -- rejected is terminal.
- **Test coverage**: `handshake-attack.test.js` line 909 -- status guard test; PROOF_STATUS.md S7 `RejectedIsTerminal`
- **Code mitigation**: `lib/handshake/verify.js` line 83 status guard; TLA+ `RejectedIsTerminal`

### RT-034: Skip states -- initiated to consumed

- **Threat class**: State skip
- **Attack description**: Attacker attempts to consume a handshake that was never verified (still in `initiated` or `pending` status).
- **Expected result**: Rejected -- consume requires verified status.
- **Test coverage**: `concurrency-warfare.test.js` line 806 -- "consume cannot proceed on unverified handshake"
- **Code mitigation**: `lib/handshake/consume.js` line 47 status guard; PROOF_STATUS.md S2 `ConsumeRequiresVerified`

### RT-035: Add presentation to revoked handshake

- **Threat class**: Terminal state escape
- **Attack description**: Attacker submits a presentation to a handshake that has already been revoked.
- **Expected result**: Rejected -- cannot modify revoked handshake.
- **Test coverage**: `handshake-attack.test.js` line 932 -- "cannot add presentation to revoked handshake"
- **Code mitigation**: `lib/handshake/present.js` status guard

### RT-036: Verify expired handshake

- **Threat class**: Terminal state escape
- **Attack description**: Attacker attempts to verify a handshake whose expiry has passed.
- **Expected result**: Rejected with expiry reason.
- **Test coverage**: `handshake-attack.test.js` line 946 -- "cannot verify expired handshake"
- **Code mitigation**: `lib/handshake/verify.js` expiry check; `lib/handshake/invariants.js` `checkNotExpired()`; PROOF_STATUS.md S6

### RT-037: Result immutability violation

- **Threat class**: Terminal state escape
- **Attack description**: Attacker attempts to overwrite a finalized verification result.
- **Expected result**: Rejected -- finalized result is immutable.
- **Test coverage**: `handshake-invariants.test.js` `checkResultImmutability`
- **Code mitigation**: `lib/handshake/invariants.js` `checkResultImmutability()`; PROOF_STATUS.md T10

---

## Write Path Attacks

### RT-038: Direct DB write bypass

- **Threat class**: Write bypass
- **Attack description**: Route handler or service function attempts to call `insert()`, `update()`, `upsert()`, or `delete()` directly on a trust-bearing table, bypassing `protocolWrite()`.
- **Expected result**: Runtime throws `WRITE_DISCIPLINE_VIOLATION`. CI build fails.
- **Test coverage**: `conformance.test.js` -- "all trust-bearing tables are write-guarded"; `ci-guardrails.test.js` -- trust-table write violation detection
- **Code mitigation**: `lib/write-guard.js` `getGuardedClient()` Proxy (line 73); `scripts/check-write-discipline.js`; `scripts/check-protocol-discipline.js`

### RT-039: Route handler uses getServiceClient instead of getGuardedClient

- **Threat class**: Write bypass
- **Attack description**: A route handler imports `getServiceClient` directly, bypassing the write guard.
- **Expected result**: CI build fails with violation report.
- **Test coverage**: `ci-guardrails.test.js` -- "getServiceClient violation detection"
- **Code mitigation**: `scripts/check-write-discipline.js` scanner

### RT-040: Event omission -- mutation without event

- **Threat class**: Event omission
- **Attack description**: A state transition occurs but no event is recorded to `handshake_events` or `protocol_events`.
- **Expected result**: `EVENT_WRITE_REQUIRED` error thrown; state change rolled back.
- **Test coverage**: Event recording tests; `handshake-adversarial.test.js` D.4 event reconstruction tests
- **Code mitigation**: `lib/handshake/events.js` `requireHandshakeEvent()`; `lib/protocol-write.js` `appendProtocolEvent()`; Invariant 9 (INVARIANTS.md)

### RT-041: Event tampering detection via reconstruction

- **Threat class**: Event omission / integrity
- **Attack description**: Materialized state is tampered with (e.g., status changed directly). Event reconstruction detects drift.
- **Expected result**: Reconstruction from events reveals inconsistency with materialized state.
- **Test coverage**: `handshake-adversarial.test.js` line 941 -- "reconstruction detects drift when materialized state is tampered"
- **Code mitigation**: `lib/handshake/events.js` event reconstruction; DB triggers preventing UPDATE/DELETE on event tables

---

## Concurrency Attacks

### RT-042: Duplicate create storms (100-way idempotency)

- **Threat class**: Duplicate creation
- **Attack description**: 100 concurrent requests attempt to create the same handshake (identical idempotency key) simultaneously.
- **Expected result**: Exactly 1 handshake created; all callers receive the same `handshake_id`.
- **Test coverage**: `concurrency-warfare.test.js` line 442 -- "100 concurrent creates with same idempotency_key -> exactly 1 handshake created"; line 476 -- "all successful callers receive identical handshake_id"; line 503 -- "no duplicate rows exist after storm"
- **Code mitigation**: DB unique constraint on `handshakes.idempotency_key` (23505); `lib/protocol-write.js` idempotency cache

### RT-043: Revoke/consume race

- **Threat class**: Race condition
- **Attack description**: Concurrent revoke and consume operations on the same handshake. Only one should succeed.
- **Expected result**: Exactly one wins. Final state is consumed OR revoked, never both.
- **Test coverage**: `concurrency-warfare.test.js` line 678 -- "concurrent revoke and consume -- exactly one wins"; line 744 -- "final state is consistent"
- **Code mitigation**: DB-level atomicity; conditional update `.is('consumed_at', null)`; PROOF_STATUS.md A2

### RT-044: Verify/consume race

- **Threat class**: Race condition
- **Attack description**: Concurrent verify and consume on an unverified handshake. Consume must fail or wait for verify.
- **Expected result**: Consume fails on unverified handshake; verify succeeds first if race resolves.
- **Test coverage**: `concurrency-warfare.test.js` line 822 -- "concurrent verify + consume on unverified handshake"; `handshake-adversarial.test.js` line 587 -- "verify + consume race"
- **Code mitigation**: `lib/handshake/consume.js` status guard (requires verified); `lib/handshake/verify.js` consumed_at check

### RT-045: Same-actor rapid-fire abuse

- **Threat class**: Abuse pattern
- **Attack description**: Same actor sends rapid-fire consume/revoke requests on the same handshake to exploit timing windows.
- **Expected result**: Only 1 operation succeeds per handshake; subsequent attempts are rejected.
- **Test coverage**: `concurrency-warfare.test.js` line 1099 -- "same actor rapid-fire consume -- only 1 succeeds"; line 1142 -- "same actor rapid-fire revoke"; line 1160 -- "same actor cannot consume then revoke for double effect"
- **Code mitigation**: DB unique constraints; consumed_at conditional update; terminal state guards

### RT-046: Multi-actor contention

- **Threat class**: Race condition
- **Attack description**: Multiple actors concurrently attempt operations on the same handshake. Unauthorized actors should not interfere with authorized operations.
- **Expected result**: Only authorized actors succeed; unauthorized actors are rejected regardless of timing.
- **Test coverage**: `concurrency-warfare.test.js` line 1214 -- "unauthorized actor cannot revoke while authorized actor operates"; line 1253 -- "multiple unauthorized actors cannot overwhelm authorization checks"; line 1286 -- "authorized + unauthorized concurrent consumes"
- **Code mitigation**: Authority checks run before state mutation; `lib/handshake/present.js` entity_ref check

### RT-047: Event append integrity under contention

- **Threat class**: Event omission under race
- **Attack description**: 100 concurrent creates must each produce exactly 1 event. No lost or duplicate events.
- **Expected result**: Exactly 100 events; each `event_id` is unique; ordering is consistent.
- **Test coverage**: `concurrency-warfare.test.js` line 992 -- "100 concurrent creates produce exactly 100 events"; line 1013 -- "no duplicate events"; line 1032 -- "event ordering is consistent"
- **Code mitigation**: `lib/handshake/events.js` `requireHandshakeEvent()`; DB append-only triggers

### RT-048: Concurrent protocolWrite idempotency

- **Threat class**: Duplicate creation
- **Attack description**: Two concurrent `protocolWrite` calls with identical commands race to execute.
- **Expected result**: Both return valid results; at most one is fresh, the other is idempotent.
- **Test coverage**: `adversarial-breakage.test.js` line 753 -- "concurrent protocolWrite calls with same command converge"; line 233 -- "protocolWrite idempotency returns cached result"
- **Code mitigation**: `lib/protocol-write.js` idempotency cache with TTL

### RT-049: Cross-handshake isolation under contention

- **Threat class**: Race condition
- **Attack description**: Concurrent operations on different handshakes by different actors must not interfere.
- **Expected result**: Operations on separate handshakes are fully independent.
- **Test coverage**: `concurrency-warfare.test.js` line 1352 -- "concurrent operations by different actors on different handshakes do not interfere"
- **Code mitigation**: Handshake-level isolation via `handshake_id` scoping in all queries

### RT-050: No phantom consume -- double-success prevention

- **Threat class**: Double-spend
- **Attack description**: Two threads both see `consumed_at = null` and attempt to set it. Only one should succeed.
- **Expected result**: Conditional update `.is('consumed_at', null)` ensures exactly one succeeds.
- **Test coverage**: `handshake-adversarial.test.js` line 560 -- "concurrent double consume: only one succeeds"; `concurrency-warfare.test.js` line 633 -- "no phantom consume"
- **Code mitigation**: `lib/handshake/verify.js` conditional update; DB unique constraint on `handshake_consumptions`

---

## Injection & Data Integrity Attacks

### RT-051: SQL injection in policy_id field

- **Threat class**: Injection
- **Attack description**: Attacker supplies a SQL injection payload as `policy_id`.
- **Expected result**: Treated as opaque string; no SQL execution. Policy lookup returns null, handshake proceeds with policy_not_found.
- **Test coverage**: `handshake-attack.test.js` line 472 -- "SQL-like injection in policy_id field is treated as opaque string"
- **Code mitigation**: Parameterized queries via Supabase client; no string interpolation in queries

### RT-052: XSS payload in presentation claims

- **Threat class**: Injection
- **Attack description**: Attacker embeds XSS script tags in presentation claim fields.
- **Expected result**: Claims are hashed and normalized; XSS content stripped from `normalized_claims`.
- **Test coverage**: `handshake-attack.test.js` line 489 -- "XSS payload in presentation claims is hashed and normalized"
- **Code mitigation**: `lib/handshake/normalize.js` claim normalization; canonical hash computation

### RT-053: Oversized payload (>1MB)

- **Threat class**: Resource exhaustion
- **Attack description**: Attacker submits a payload exceeding 1MB to attempt storage bloat.
- **Expected result**: Payload is hashed to fixed-length SHA-256; no storage bloat.
- **Test coverage**: `handshake-attack.test.js` line 508 -- "oversized payload is hashed to fixed-length"
- **Code mitigation**: `lib/handshake/binding.js` `computePayloadHash()` -- SHA-256 of serialized payload

### RT-054: Malformed JSON in presentation body

- **Threat class**: Injection
- **Attack description**: Attacker sends syntactically invalid JSON as presentation body.
- **Expected result**: Handled gracefully without crash; error returned.
- **Test coverage**: `handshake-attack.test.js` line 522 -- "malformed JSON in presentation body is handled gracefully"
- **Code mitigation**: Input validation in `_handleAddPresentation()`

### RT-055: Score scale confusion (0-1 vs 0-100)

- **Threat class**: Data integrity
- **Attack description**: Raw trust score (0-100) used directly for allow/deny decisions without policy evaluation, potentially confused with 0-1 scale.
- **Expected result**: Without explicit policy, decision defaults to `review`, never `allow`/`deny` from raw score alone.
- **Test coverage**: `adversarial-benchmarks.test.js` line 872 -- "commit decisions never use raw score for trust-critical paths"
- **Code mitigation**: `lib/commit.js` `issueCommit()` -- decision logic requires `policyResult.pass` for `allow`

### RT-056: Out-of-range and NaN score values

- **Threat class**: Data integrity
- **Attack description**: Receipts with `composite_score: 99999`, `Infinity`, `NaN`, or negative values.
- **Expected result**: `computeTrustProfile` always returns score in [0, 100], finite.
- **Test coverage**: `adversarial-benchmarks.test.js` line 807 -- "computeTrustProfile never returns score outside 0-100"
- **Code mitigation**: `lib/scoring-v2.js` `computeTrustProfile()` clamping and NaN guards

### RT-057: Binding field completeness enforcement

- **Threat class**: Data integrity
- **Attack description**: Attacker provides binding material with missing, extra, or incorrect version fields.
- **Expected result**: Rejected with `BINDING_INVARIANT_VIOLATION`.
- **Test coverage**: `handshake-adversarial.test.js` line 692 -- A.4 binding completeness tests (lines 700-819)
- **Code mitigation**: `lib/handshake/create.js` `CANONICAL_BINDING_FIELDS` assertion; `lib/handshake/invariants.js` field validation; Invariant 10

---

## Key Management Attacks

### RT-058: Key rotation -- old commit fails with new key

- **Threat class**: Key rotation
- **Attack description**: After key rotation, verifying a commit signed with the old key against the new key fails.
- **Expected result**: `verifySignature` returns `false`; `verifyCommit` returns `invalid_signature`.
- **Test coverage**: `adversarial-benchmarks.test.js` line 598 -- "old commit fails signature verification after key rotation"; `adversarial-breakage.test.js` line 536 -- "commit verified with key removed from registry is invalid"
- **Code mitigation**: `lib/commit.js` `verifySignature()`; key registry resolution by kid

### RT-059: Revoked key used for commit verification

- **Threat class**: Stale authority root
- **Attack description**: Commit signed with key A, then A is rotated out. Verification fails.
- **Expected result**: `verifyCommit` returns `valid: false`, reason `invalid_signature`.
- **Test coverage**: `adversarial-breakage.test.js` line 370 -- "commit signed by revoked key fails with invalid_signature"
- **Code mitigation**: `lib/commit.js` key registry lookup; `_resetForTesting()` simulates rotation

### RT-060: Multiple keys registered -- kid resolution

- **Threat class**: Key management
- **Attack description**: Multiple keys registered under different kids. Payload signed with key A must only verify under kid-alpha, not kid-beta.
- **Expected result**: Correct kid resolves to correct key; cross-kid verification fails.
- **Test coverage**: `adversarial-breakage.test.js` line 558 -- "multiple keys registered -- correct kid resolves to correct key"
- **Code mitigation**: `lib/commit.js` `registerTrustedKey()`, `getTrustedKey()` kid-based lookup

---

## Trust & Scoring Attacks

### RT-061: Sybil ring detection (5-entity ring)

- **Threat class**: Sybil attack
- **Attack description**: 5 entities form a ring, each scoring the next (A->B->C->D->E->A).
- **Expected result**: `detectClosedLoop` flags the ring; graph_weight reduced to 0.1x; trust score severely limited.
- **Test coverage**: `adversarial-benchmarks.test.js` line 117 -- "detects closed-loop pattern in a 5-entity ring"; line 227 -- "ring receipts with 0.1 graph_weight produce near-zero trust"
- **Code mitigation**: `lib/sybil.js` `detectClosedLoop()`, `analyzeReceiptGraph()`, `runReceiptFraudChecks()`

### RT-062: Reciprocal farming detection

- **Threat class**: Reciprocal farming
- **Attack description**: Two entities exclusively score each other (A->B and B->A).
- **Expected result**: `detectClosedLoop` flags both directions; 0.4x weight dampening applied.
- **Test coverage**: `adversarial-benchmarks.test.js` line 255 -- "detectClosedLoop flags two entities that only score each other"; line 282 -- "reciprocal farming receipts get 0.4x weight dampening"
- **Code mitigation**: `lib/sybil.js` `detectClosedLoop()` bidirectional receipt check

### RT-063: False dispute resilience -- dispute spam

- **Threat class**: Dispute abuse
- **Attack description**: Attacker files disputes against all 10 of a target entity's receipts to tank their score.
- **Expected result**: Disputed receipts dampened at 0.3x weight, but score does not collapse to zero. 7 undisputed receipts still contribute fully.
- **Test coverage**: `adversarial-benchmarks.test.js` line 381 -- "entity score does not collapse from dispute spam"; line 404 -- "disputing ALL receipts dampens but does not annihilate score"
- **Code mitigation**: `lib/scoring-v2.js` `DISPUTE_DAMPENING_FACTOR = 0.3`; `computeTrustProfile()` dampening logic

### RT-064: Cold start exploitation

- **Threat class**: Cold start abuse
- **Attack description**: Attacker creates a new entity and tries to achieve `established` status with minimal, collusive receipts.
- **Expected result**: 0 receipts = score 50, confidence pending; establishment requires >= 5 receipts from >= 3 unique submitters.
- **Test coverage**: `adversarial-benchmarks.test.js` line 305 -- "entity with 0 receipts gets score: 50"; line 326 -- "establishment requires minimum receipts and unique submitters"
- **Code mitigation**: `lib/sybil.js` `isEstablished()` threshold check; `lib/scoring-v2.js` confidence levels

### RT-065: Appeal reversal correctness (upheld -> reversed)

- **Threat class**: Appeal abuse
- **Attack description**: Appeal overturns an original `upheld` resolution, neutralizing the receipt.
- **Expected result**: Receipt `graph_weight` set to 0.0.
- **Test coverage**: `adversarial-benchmarks.test.js` line 430 -- "appeal_reversed against original upheld -> receipt gets graph_weight 0.0"
- **Code mitigation**: `lib/canonical-writer.js` `canonicalResolveAppeal()` weight adjustment logic

### RT-066: Appeal reversal correctness (reversed -> restored)

- **Threat class**: Appeal abuse
- **Attack description**: Appeal overturns an original `reversed` resolution, restoring the receipt.
- **Expected result**: Receipt `graph_weight` restored to 1.0.
- **Test coverage**: `adversarial-benchmarks.test.js` line 511 -- "appeal_reversed against original reversed -> receipt gets graph_weight 1.0"
- **Code mitigation**: `lib/canonical-writer.js` `canonicalResolveAppeal()` weight restoration logic

---

## Data Exfiltration Attacks

### RT-067: Normalized claims strip sensitive fields

- **Threat class**: Data exfiltration
- **Attack description**: Attacker attempts to embed sensitive data in presentation claims and extract it via `getHandshake`.
- **Expected result**: `normalized_claims` strips non-canonical sensitive fields.
- **Test coverage**: `handshake-attack.test.js` line 1094 -- "getHandshake normalized_claims strips non-canonical sensitive fields"
- **Code mitigation**: `lib/handshake/normalize.js` canonical claim normalization

### RT-068: Error responses do not leak internals

- **Threat class**: Data exfiltration
- **Attack description**: Attacker triggers errors to extract internal stack traces or DB schema information.
- **Expected result**: Error responses contain only safe error codes and messages; no stack traces or schema details.
- **Test coverage**: `handshake-attack.test.js` line 1130 -- "error responses do not leak internal stack traces or DB schema"
- **Code mitigation**: `HandshakeError` structured error responses; error sanitization in route handlers

### RT-069: Read scoping -- non-party cannot read handshake

- **Threat class**: Data exfiltration
- **Attack description**: Entity not listed as a party attempts to read a handshake's details.
- **Expected result**: Rejected -- non-party reads are blocked.
- **Test coverage**: `handshake-attack.test.js` line 1273 -- "getHandshake rejects non-party reads"
- **Code mitigation**: `lib/handshake/index.js` `getHandshake()` party membership check

### RT-070: Read scoping -- listHandshakes scoped to actor

- **Threat class**: Data exfiltration
- **Attack description**: Attacker calls `listHandshakes` without authentication or with a different entity to enumerate handshakes.
- **Expected result**: Returns empty when no actor; scoped to actor's entity_ref otherwise.
- **Test coverage**: `handshake-attack.test.js` line 1241 -- "listHandshakes returns empty when no actor"; line 1250 -- "listHandshakes scopes to actor entity_ref"
- **Code mitigation**: `lib/handshake/index.js` `listHandshakes()` actor scoping

---

## Timing Attacks

### RT-071: Presentation at exact expiry boundary

- **Threat class**: Timing attack
- **Attack description**: Presentation submitted at the exact millisecond the handshake expires.
- **Expected result**: Rejected -- boundary condition treated as expired.
- **Test coverage**: `handshake-attack.test.js` line 613 -- "presentation submitted exactly at expiry boundary is rejected"
- **Code mitigation**: `lib/handshake/invariants.js` `checkNotExpired()` strict comparison

### RT-072: Verification 1ms after expiry

- **Threat class**: Timing attack
- **Attack description**: Verification attempt 1 millisecond after `expires_at`.
- **Expected result**: Rejected -- handshake expired.
- **Test coverage**: `handshake-attack.test.js` line 634 -- "verification attempted 1ms after expiry is rejected"
- **Code mitigation**: `lib/handshake/verify.js` expiry check; `lib/handshake/invariants.js` `checkNotExpired()`

### RT-073: Zero-second expiry window

- **Threat class**: Timing attack
- **Attack description**: Handshake created with `binding_ttl_ms: 0`, attempting instant-expire exploit.
- **Expected result**: TTL clamped to minimum value; handshake not instantly expired.
- **Test coverage**: `handshake-attack.test.js` line 654 -- "handshake with 0-second expiry window is clamped to minimum TTL"
- **Code mitigation**: `lib/handshake/create.js` minimum TTL enforcement

---

## Batch & Resilience Attacks

### RT-074: Mixed batch -- valid and invalid commands

- **Threat class**: Batch poisoning
- **Attack description**: Batch of 8 commands where 5 are valid and 3 are invalid (missing required fields).
- **Expected result**: 5 succeed independently; 3 fail with `VALIDATION_ERROR`. No cross-contamination.
- **Test coverage**: `adversarial-breakage.test.js` line 629 -- "batch with 5 valid + 3 invalid -- valid succeed, invalid fail independently"
- **Code mitigation**: `lib/protocol-write.js` independent command processing

### RT-075: DB error surfacing in batch

- **Threat class**: Error swallowing
- **Attack description**: One command in a batch hits a database error (e.g., disk full). The error must not be swallowed.
- **Expected result**: Failed command surfaces error; other commands proceed normally.
- **Test coverage**: `adversarial-breakage.test.js` line 656 -- "batch with one DB error surfaces the error"
- **Code mitigation**: `lib/protocol-write.js` error propagation; no silent error swallowing

### RT-076: Idempotency cache TTL expiry

- **Threat class**: Cache exploitation
- **Attack description**: After the 10-minute idempotency cache TTL expires, the same command can be re-executed.
- **Expected result**: Expired cache entry allows fresh execution.
- **Test coverage**: `adversarial-breakage.test.js` line 783 -- "idempotency cache entry expires after TTL"
- **Code mitigation**: `lib/protocol-write.js` idempotency cache timestamp check

---

## Signoff Attacks (Planned)

### RT-077: Approval laundering

- **Threat class**: Signoff abuse
- **Attack description**: Attacker routes a signoff request through a compromised approver to launder an illegitimate action.
- **Expected result**: Planned -- dual control requirement ensures minimum 2 independent approvers; compromised single approver insufficient.
- **Test coverage**: `dual-control.test.js` -- DUAL_CONTROL_ACTIONS coverage (planned expansion)
- **Code mitigation**: Planned -- `lib/dual-control.js` minimum approver threshold; independent approver verification

### RT-078: Signoff fatigue exploitation

- **Threat class**: Signoff abuse
- **Attack description**: Attacker floods legitimate approvers with trivial signoff requests to induce rubber-stamping, then slips in a malicious request.
- **Expected result**: Planned -- rate limiting on signoff requests per approver; anomaly detection on approval velocity.
- **Test coverage**: Planned
- **Code mitigation**: Planned -- abuse detection integration; per-approver rate limits

### RT-079: Signoff social engineering

- **Threat class**: Signoff abuse
- **Attack description**: Attacker manipulates signoff request metadata to mislead approvers about the action being approved.
- **Expected result**: Planned -- signoff requests display canonical action description derived from binding material, not attacker-supplied text.
- **Test coverage**: Planned
- **Code mitigation**: Planned -- canonical signoff display derived from binding hash

### RT-080: Dual signoff bypass

- **Threat class**: Signoff abuse
- **Attack description**: Attacker attempts to approve a dual-control action with a single signoff or with the same entity signing off twice.
- **Expected result**: Planned -- enforcement that N distinct entities must approve; same-entity duplicate detection.
- **Test coverage**: `dual-control.test.js` -- dual control enforcement (planned expansion for same-entity check)
- **Code mitigation**: Planned -- `lib/dual-control.js` distinct approver enforcement

### RT-081: Signoff replay

- **Threat class**: Signoff replay
- **Attack description**: Attacker replays a signoff approval from a previous action to authorize a new action.
- **Expected result**: Planned -- signoff bound to specific binding hash; replayed signoff does not match new binding.
- **Test coverage**: Planned
- **Code mitigation**: Planned -- signoff binding to action hash via canonical binding material

---

## Issuer Status Vocabulary Attacks

### RT-082: Unregistered issuer status vocabulary

- **Threat class**: Issuer spoofing
- **Attack description**: Unregistered issuer incorrectly labeled as `revoked` instead of `unknown`.
- **Expected result**: `revocation_status` set to `unknown` (not `revoked`) for unregistered issuers.
- **Test coverage**: `handshake-attack.test.js` line 1309 -- "sets revocation_status to unknown for unregistered issuers"
- **Code mitigation**: `lib/handshake/present.js` issuer status vocabulary

### RT-083: Authority table unavailable

- **Threat class**: Fail-closed
- **Attack description**: Authority registry table is unreachable at verification time.
- **Expected result**: `revocation_status` set to `registry_unavailable`; fails closed (does not assume trusted).
- **Test coverage**: `handshake-attack.test.js` line 1329 -- "sets revocation_status to registry_unavailable when authority table missing"
- **Code mitigation**: `lib/handshake/present.js` error handling; fail-closed default `issuerTrusted = false`

---

## Delegation Attacks

### RT-084: Delegation cycle detection

- **Threat class**: Delegation abuse
- **Attack description**: Attacker creates a circular delegation chain (A delegates to B, B delegates to A).
- **Expected result**: Rejected -- cycle detected.
- **Test coverage**: Delegation tests; PROOF_STATUS.md S11
- **Code mitigation**: `lib/delegation.js` cycle detection; TLA+ `DelegationAcyclicity`; Alloy `NoDelegationCycles` (A8)

### RT-085: Self-delegation prevention

- **Threat class**: Delegation abuse
- **Attack description**: Entity attempts to delegate to itself.
- **Expected result**: Rejected -- principal and delegate must be distinct.
- **Test coverage**: Delegation tests
- **Code mitigation**: `lib/delegation.js`; Alloy `NoSelfDelegation` (F20)

---

## Summary

| Category | Cases | Coverage Status |
|----------|-------|-----------------|
| Identity & Authority Attacks | RT-001 through RT-012 | Tested |
| Replay & Reuse Attacks | RT-013 through RT-026 | Tested |
| Policy Attacks | RT-027 through RT-031 | Tested |
| State Machine Attacks | RT-032 through RT-037 | Tested |
| Write Path Attacks | RT-038 through RT-041 | Tested |
| Concurrency Attacks | RT-042 through RT-050 | Tested |
| Injection & Data Integrity | RT-051 through RT-057 | Tested |
| Key Management Attacks | RT-058 through RT-060 | Tested |
| Trust & Scoring Attacks | RT-061 through RT-066 | Tested |
| Data Exfiltration Attacks | RT-067 through RT-070 | Tested |
| Timing Attacks | RT-071 through RT-073 | Tested |
| Batch & Resilience Attacks | RT-074 through RT-076 | Tested |
| Signoff Attacks (Planned) | RT-077 through RT-081 | Planned |
| Issuer Status Vocabulary | RT-082 through RT-083 | Tested |
| Delegation Attacks | RT-084 through RT-085 | Tested |

**Total red team cases**: 85
**Tested**: 80
**Planned**: 5

---

## Test File Cross-Reference

| Test File | Cases Covered |
|-----------|---------------|
| `tests/adversarial-benchmarks.test.js` | RT-013, RT-014, RT-055, RT-056, RT-061 through RT-066 |
| `tests/adversarial-breakage.test.js` | RT-001, RT-010, RT-011, RT-013, RT-025, RT-048, RT-058 through RT-060, RT-074 through RT-076 |
| `tests/handshake-attack.test.js` | RT-002, RT-003, RT-005 through RT-009, RT-012, RT-015 through RT-018, RT-030, RT-031, RT-032, RT-033, RT-035, RT-036, RT-051 through RT-054, RT-067 through RT-073, RT-082, RT-083 |
| `tests/handshake-adversarial.test.js` | RT-019, RT-020, RT-021, RT-022, RT-024, RT-026, RT-040, RT-041, RT-044, RT-050, RT-057 |
| `tests/concurrency-warfare.test.js` | RT-019, RT-023, RT-034, RT-042 through RT-050 |
| `tests/handshake-invariants.test.js` | RT-002, RT-006, RT-007, RT-017, RT-027, RT-030, RT-037 |
| `tests/conformance.test.js` | RT-038, RT-057 |
| `tests/ci-guardrails.test.js` | RT-038, RT-039 |
| `tests/dual-control.test.js` | RT-077, RT-080 |
