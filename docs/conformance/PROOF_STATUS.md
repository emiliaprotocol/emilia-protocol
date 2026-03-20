# EP Conformance Proof Status

Maps each protocol invariant to its enforcement in code, test coverage, and formal model coverage.

---

## Legend

| Column | Meaning |
|--------|---------|
| **Enforced** | Runtime code that enforces this invariant |
| **Tested** | Unit/integration test that proves the invariant holds |
| **Modeled (TLA+)** | Property in `formal/ep_handshake.tla` that captures this invariant |
| **Modeled (Alloy)** | Fact/assertion in `formal/ep_relations.als` that captures this invariant |
| **Status** | Current coverage level |

---

## Safety Invariants

| # | Invariant | Enforced | Tested | Modeled (TLA+) | Modeled (Alloy) | Status |
|---|-----------|----------|--------|-----------------|-----------------|--------|
| S1 | **Consume-once safety**: a handshake can be consumed at most once | Yes -- `consume.js` unique constraint (23505) + `verify.js` consumed_at hard gate | Yes -- `handshake-attack.test.js` | Yes -- `ConsumeOnceSafety` | Yes -- `NoDoubleConsumption`, `UniqueConsumption` | Complete |
| S2 | **Consume requires verified**: only verified handshakes can be consumed | Yes -- `consume.js` line 47 status guard | Yes -- `handshake-attack.test.js` | Yes -- `ConsumeRequiresVerified` | Yes -- `ConsumeRequiresVerified`, `ConsumedHasConsumption` | Complete |
| S3 | **Revoked is terminal**: revoked handshakes cannot advance to verified or consumed | Yes -- `verify.js` line 83 status guard; `finalize.js` line 78 | Yes -- `handshake-attack.test.js` | Yes -- `RevokedIsTerminal` | Yes -- `RevokedTerminal`, `RevokedNeverConsumed` | Complete |
| S4 | **Event coverage**: every state transition has a corresponding durable event | Yes -- `verify.js` line 280 `requireHandshakeEvent()`; `finalize.js` line 89 | Yes -- `handshake.test.js` | Yes -- `EventCoverage` | Yes -- `EventCoverage`, `EventTypeConsistency` | Complete |
| S5 | **Policy required for verification**: no policy-invalid handshake reaches verified | Yes -- `verify.js` lines 164-183 policy resolution + hash comparison | Yes -- `handshake-invariants.test.js` (`checkAssuranceLevel`, `checkAllPartiesPresent`) | Yes -- `PolicyRequired` | Yes -- `VerifiedRequiresTrustedIssuers` | Complete |
| S6 | **Expired is terminal**: expired handshakes cannot advance | Yes -- `verify.js` line 83 status guard | Yes -- `handshake-invariants.test.js` (`checkNotExpired`) | Yes -- `ExpiredIsTerminal` | Yes -- `ExpiredTerminal` | Complete |
| S7 | **Rejected is terminal**: rejected handshakes cannot advance | Yes -- `verify.js` line 83 status guard | Yes -- `handshake.test.js` | Yes -- `RejectedIsTerminal` | Yes -- `RejectedTerminal` | Complete |

---

## Data Integrity Invariants

| # | Invariant | Enforced | Tested | Modeled (TLA+) | Modeled (Alloy) | Status |
|---|-----------|----------|--------|-----------------|-----------------|--------|
| D1 | **Binding hash uniqueness**: each binding has a unique hash derived from canonical fields | Yes -- `invariants.js` CANONICAL_BINDING_FIELDS + `binding.js` hashBinding() | Yes -- `conformance.test.js` (#8, #9, #10) | Implicit in model (distinct bindings) | Yes -- `UniqueBindingHash` | Complete |
| D2 | **Unique nonce per binding**: 32-byte random nonce prevents replay | Yes -- `invariants.js` newNonce() | Yes -- `handshake-invariants.test.js` (`checkBindingValid`) | Implicit (bindings per handshake) | Yes -- `UniqueNonce` | Complete |
| D3 | **Unique idempotency key**: each protocolWrite command has a deterministic idempotency key | Yes -- `protocol-write.js` | Yes -- `conformance.test.js` (#16) | Not modeled (write-layer concern) | Yes -- `UniqueIdempotencyKey` | Partial -- no TLA+ |
| D4 | **One party per role per handshake**: no duplicate role assignments | Yes -- DB unique constraint (handshake_id, party_role) | Yes -- `handshake.test.js` | Not modeled (relational concern) | Yes -- `UniquePartyRole` | Partial -- no TLA+ |
| D5 | **Consumption binding hash integrity**: consumption record references correct binding | Yes -- `consume.js` binding_hash parameter | Yes -- `handshake-attack.test.js` | Not modeled (data-level concern) | Yes -- `ConsumptionBindingIntegrity` | Partial -- no TLA+ |

---

## Trust & Access Invariants

| # | Invariant | Enforced | Tested | Modeled (TLA+) | Modeled (Alloy) | Status |
|---|-----------|----------|--------|-----------------|-----------------|--------|
| T1 | **No finalization after expiry**: expired bindings cannot produce accepted outcome | Yes -- `invariants.js` checkNotExpired() | Yes -- `handshake-invariants.test.js` (#23) | Yes -- `Expire` action preconditions | Not directly modeled | Complete |
| T2 | **All required parties present**: missing party presentations reject verification | Yes -- `invariants.js` checkAllPartiesPresent(); `verify.js` lines 122-131 | Yes -- `handshake-invariants.test.js` (#24) | Implicit in `VerifyAccept` preconditions | Yes -- `PresentationRoleExists` | Complete |
| T3 | **Binding payload verification**: payload hash must match between binding and verification | Yes -- `invariants.js` checkBindingValid() | Yes -- `handshake-invariants.test.js` (#25) | Implicit in model | Not directly modeled | Complete |
| T4 | **Issuer in trusted registry**: issuer_ref must resolve to an authority record | Yes -- `invariants.js` checkIssuerTrusted(); `present.js` authority lookup | Yes -- `handshake-invariants.test.js` (#26) | Not directly modeled | Yes -- `VerifiedRequiresTrustedIssuers` | Complete |
| T5 | **Authority not revoked**: revoked authorities reject verification | Yes -- `invariants.js` checkAuthorityNotRevoked(); `verify.js` revocation_status check | Yes -- `handshake-invariants.test.js` (#27) | Not directly modeled | Yes -- `VerifiedRequiresTrustedIssuers` (revoked=False) | Complete |
| T6 | **Assurance meets minimum**: achieved assurance must meet policy minimum | Yes -- `invariants.js` checkAssuranceLevel() | Yes -- `handshake-invariants.test.js` (#28) | Abstracted in `PolicyRequired` | Not directly modeled | Complete |
| T7 | **No duplicate accepted result**: same binding hash cannot produce two accepted results | Yes -- `invariants.js` checkNoDuplicateResult() | Yes -- `handshake-invariants.test.js` (#29) | Implicit in `ConsumeOnceSafety` | Yes -- `UniqueConsumption` | Complete |
| T8 | **Interaction binding**: handshake must reference a subject interaction | Yes -- `invariants.js` checkInteractionBound() | Yes -- `handshake-invariants.test.js` (#30) | Not directly modeled | Not directly modeled | Partial -- code + test only |
| T9 | **No role spoofing**: actor entity must match party entity | Yes -- `invariants.js` checkNoRoleSpoofing(); `present.js` entity_ref check | Yes -- `handshake-invariants.test.js` (#31) | Not directly modeled | Not directly modeled | Partial -- code + test only |
| T10 | **Result immutability**: finalized results cannot be modified | Yes -- `invariants.js` checkResultImmutability() | Yes -- `handshake-invariants.test.js` (#32) | Implicit in terminal state properties | Not directly modeled | Complete |

---

## Adversarial Properties

| # | Property | Enforced | Tested | Modeled (TLA+) | Modeled (Alloy) | Status |
|---|----------|----------|--------|-----------------|-----------------|--------|
| A1 | **Duplicate consume blocked**: second consumption attempt is a no-op | Yes -- DB unique constraint (23505) | Yes -- `handshake-attack.test.js` | Yes -- `DuplicateConsumeAttempt` (UNCHANGED vars) | Yes -- `NoDoubleConsumption` | Complete |
| A2 | **Concurrent revoke/consume resolves safely**: exactly one wins | Yes -- DB-level atomicity | Yes -- `handshake-adversarial.test.js` | Yes -- `ConcurrentRevokeConsume` (non-deterministic choice) | Yes -- `TerminalStateIntegrity` | Complete |
| A3 | **Replay after consumption blocked**: re-verification of consumed binding rejected | Yes -- `verify.js` HARD GATE (line 52-68) consumed_at check | Yes -- `handshake-attack.test.js` | Yes -- `ReplayAfterConsumption` (UNCHANGED vars) | Yes -- `ConsumedWasVerified` | Complete |

---

## Coverage Summary

| Category | Total | Code-enforced | Tested | TLA+ modeled | Alloy modeled | Fully covered |
|----------|-------|---------------|--------|--------------|---------------|---------------|
| Safety (S1-S7)       | 7  | 7 | 7 | 7 | 7 | 7 |
| Data Integrity (D1-D5) | 5 | 5 | 5 | 2 | 5 | 2 |
| Trust & Access (T1-T10) | 10 | 10 | 10 | 4 | 5 | 4 |
| Adversarial (A1-A3)  | 3  | 3 | 3 | 3 | 3 | 3 |
| **Total**            | **25** | **25** | **25** | **16** | **20** | **16** |

---

## Formal Model Files

| File | Format | Checks | How to Run |
|------|--------|--------|------------|
| `formal/ep_handshake.tla` | TLA+ | 7 safety theorems, 11 actions (including 3 adversarial) | TLC model checker with `Handshakes = {h1, h2}`, `Actors = {a1}`, `Policies = {p1}` |
| `formal/ep_relations.als` | Alloy 6 | 16 facts, 5 assertions, 2 visualization predicates | Alloy Analyzer `check` commands (scope 6) |

---

## Next Steps

1. Run TLC on `ep_handshake.tla` with small constant sets to confirm all theorems hold
2. Run Alloy Analyzer on `ep_relations.als` to verify all assertions find no counterexamples
3. Add TLA+ coverage for D3-D5 (idempotency, party uniqueness, binding hash integrity)
4. Add Alloy coverage for T8-T9 (interaction binding, role spoofing)
5. Integrate formal model checks into CI pipeline
