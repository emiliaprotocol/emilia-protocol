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
| **CI Gate** | Checked by `scripts/check-invariant-coverage.js` |
| **Status** | Current coverage level |

---

## Safety Invariants

| # | Invariant | Enforced | Tested | Modeled (TLA+) | Modeled (Alloy) | CI Gate | Status |
|---|-----------|----------|--------|-----------------|-----------------|---------|--------|
| S1 | **Consume-once safety**: a handshake can be consumed at most once | Yes -- `consume.js` unique constraint (23505) + `verify.js` consumed_at hard gate | Yes -- `handshake-attack.test.js` | Yes -- `ConsumeOnceSafety` | Yes -- `NoDoubleConsumption`, `UniqueConsumption` | Yes | Complete |
| S2 | **Consume requires verified**: only verified handshakes can be consumed | Yes -- `consume.js` line 47 status guard | Yes -- `handshake-attack.test.js` | Yes -- `ConsumeRequiresVerified` | Yes -- `ConsumeRequiresVerified`, `ConsumedHasConsumption` | Yes | Complete |
| S3 | **Revoked is terminal**: revoked handshakes cannot advance to verified or consumed | Yes -- `verify.js` line 83 status guard; `finalize.js` line 78 | Yes -- `handshake-attack.test.js` | Yes -- `RevokedIsTerminal` | Yes -- `RevokedTerminal`, `RevokedNeverConsumed` | Yes | Complete |
| S4 | **Event coverage**: every state transition has a corresponding durable event | Yes -- `verify.js` line 280 `requireHandshakeEvent()`; `finalize.js` line 89 | Yes -- `handshake.test.js` | Yes -- `EventCoverage`, `EventCompleteness` | Yes -- `EventCoverage`, `EventTypeConsistency`, `EventStateCorrespondence` | Yes | Complete |
| S5 | **Policy required for verification**: no policy-invalid handshake reaches verified | Yes -- `verify.js` lines 164-183 policy resolution + hash comparison | Yes -- `handshake-invariants.test.js` (`checkAssuranceLevel`, `checkAllPartiesPresent`) | Yes -- `PolicyRequired`, `PolicyHashMismatchDetection` | Yes -- `VerifiedRequiresTrustedIssuers`, `PolicyVersionConsistency`, `PolicyHashConsistency` | Yes | Complete |
| S6 | **Expired is terminal**: expired handshakes cannot advance | Yes -- `verify.js` line 83 status guard | Yes -- `handshake-invariants.test.js` (`checkNotExpired`) | Yes -- `ExpiredIsTerminal` | Yes -- `ExpiredTerminal` | Yes | Complete |
| S7 | **Rejected is terminal**: rejected handshakes cannot advance | Yes -- `verify.js` line 83 status guard | Yes -- `handshake.test.js` | Yes -- `RejectedIsTerminal` | Yes -- `RejectedTerminal` | Yes | Complete |
| S8 | **Write-bypass safety**: no state mutation without canonical write path | Yes -- `write-guard.js` `getGuardedClient()` Proxy; `protocol-write.js` | Yes -- write-guard tests, `conformance.test.js` | Yes -- `WriteBypassSafety`, `DirectWriteBypassAttempt` | Yes -- `WritePathExclusivity`, `NoDirectWriteMutations`, `WritePathExclusive` (A6) | Yes | Complete |
| S9 | **Terminal state irreversibility**: once in terminal state, no transition possible | Yes -- `verify.js` status guard; `finalize.js` terminal check | Yes -- `handshake-attack.test.js` | Yes -- `TerminalStateIrreversibility`, `TerminalEscapeAttempt` | Yes -- `TerminalStateIntegrity` (A5) | Yes | Complete |
| S10 | **Delegate cannot exceed principal**: delegate scope bounded by principal | Yes -- `delegation.js` scope validation | Yes -- delegation tests | Yes -- `DelegateCannotExceedPrincipal`, `GrantDelegation` preconditions | Yes -- `DelegationScopeBounded` (F19), `DelegationScopeRespected` (A7) | Yes | Complete |
| S11 | **Delegation acyclicity**: no circular delegation chains | Yes -- `delegation.js` cycle detection | Yes -- delegation tests | Yes -- `DelegationAcyclicity`, `GrantDelegation` acyclicity guard | Yes -- `DelegationAcyclic` (F21), `NoSelfDelegation` (F20), `NoDelegationCycles` (A8) | Yes | Complete |
| S12 | **Policy-hash mismatch detection**: changed policy after binding rejects verification | Yes -- `verify.js` `computePolicyHash()` comparison; `policy_hash_mismatch` reason code | Yes -- verification tests | Yes -- `PolicyHashMismatchDetection`, `PolicyChange` action, `VerifyAccept` precondition | Yes -- `PolicyVersionConsistency` (F23), `PolicyHashConsistency` (A9) | Yes | Complete |
| S13 | **Event completeness**: exactly one event per state transition | Yes -- `requireHandshakeEvent()` in verify.js/finalize.js | Yes -- event tests | Yes -- `EventCompleteness` (per-status event count = 1) | Yes -- `EventStateCorrespondence` (F25), `EventStateExactCorrespondence` (A11) | Yes | Complete |
| S14 | **Signoff requires verified handshake**: challenge cannot be issued unless handshake is verified | Pending -- `lib/signoff/challenge.js` status guard | Pending | Yes -- `SignoffRequiresVerifiedHandshake` | Yes -- `SignoffRequiresVerifiedHandshake` (F26), `SignoffRequiresHandshake` (A14) | Pending | Partial -- formal model only |
| S15 | **Signoff consume-once**: signoff consumed_at set exactly once per handshake | Pending -- `lib/signoff/approve.js` unique constraint | Pending | Yes -- `SignoffConsumeOnce` | Yes -- `SignoffConsumeOnce` (F29), `SignoffConsumeOnce` (A13) | Pending | Partial -- formal model only |
| S16 | **Signoff binding match**: signoffBinding must equal bindingHash at every signoff transition | Pending -- `lib/signoff/challenge.js` binding hash comparison | Pending | Yes -- `SignoffBindingMatch` | Yes -- `SignoffAttestationBindingMatch` (F27), `SignoffConsumptionBindingMatch` (F28), `SignoffBindingIntegrity` (A12), `FullChainIntegrity` (A15) | Pending | Partial -- formal model only |
| S17 | **Signoff terminal irreversibility**: denied, consumed_signoff, expired_signoff, revoked_signoff are terminal | Pending -- `lib/signoff/approve.js` terminal state guard | Pending | Yes -- `SignoffTerminalIrreversible`, `SignoffTerminalEscapeAttempt` | Yes -- `NoAttestationForDeniedOrExpired` (F31), `NoConsumptionForRevokedAttestation` (F32) | Pending | Partial -- formal model only |
| S18 | **Deny cannot be approved**: denied signoff has no transition to approved | Pending -- `lib/signoff/approve.js` status guard | Pending | Yes -- `DenyCannotBeApproved` | Yes -- `NoAttestationForDeniedOrExpired` (F31) | Pending | Partial -- formal model only |
| S19 | **Signoff authority match**: signoffActor must have authority class matching policy requirement | Pending -- `lib/signoff/challenge.js` authority class check | Pending | Yes -- `SignoffAuthorityMatch` | Yes -- `SignoffAuthorityRequired` (F30) | Pending | Partial -- formal model only |

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
| T7 | **No duplicate accepted result**: same binding hash cannot produce two accepted results | Yes -- `invariants.js` checkNoDuplicateResult() | Yes -- `handshake-invariants.test.js` (#29) | Implicit in `ConsumeOnceSafety` | Yes -- `UniqueConsumption`, `MultiActorConsumptionUniqueness` (F24), `MultiActorNoDoubleConsume` (A10) | Complete |
| T8 | **Interaction binding**: handshake must reference a subject interaction | Yes -- `invariants.js` checkInteractionBound() | Yes -- `handshake-invariants.test.js` (#30) | Not directly modeled | Not directly modeled | Partial -- code + test only |
| T9 | **No role spoofing**: actor entity must match party entity | Yes -- `invariants.js` checkNoRoleSpoofing(); `present.js` entity_ref check | Yes -- `handshake-invariants.test.js` (#31) | Not directly modeled | Not directly modeled | Partial -- code + test only |
| T10 | **Result immutability**: finalized results cannot be modified | Yes -- `invariants.js` checkResultImmutability() | Yes -- `handshake-invariants.test.js` (#32) | Implicit in terminal state properties (`TerminalStateIrreversibility`) | Not directly modeled | Complete |

---

## Adversarial Properties

| # | Property | Enforced | Tested | Modeled (TLA+) | Modeled (Alloy) | Status |
|---|----------|----------|--------|-----------------|-----------------|--------|
| A1 | **Duplicate consume blocked**: second consumption attempt is a no-op | Yes -- DB unique constraint (23505) | Yes -- `handshake-attack.test.js` | Yes -- `DuplicateConsumeAttempt` (UNCHANGED vars) | Yes -- `NoDoubleConsumption` | Complete |
| A2 | **Concurrent revoke/consume resolves safely**: exactly one wins | Yes -- DB-level atomicity | Yes -- `handshake-adversarial.test.js` | Yes -- `ConcurrentRevokeConsume` (non-deterministic choice) | Yes -- `TerminalStateIntegrity` | Complete |
| A3 | **Replay after consumption blocked**: re-verification of consumed binding rejected | Yes -- `verify.js` HARD GATE (line 52-68) consumed_at check | Yes -- `handshake-attack.test.js` | Yes -- `ReplayAfterConsumption` (UNCHANGED vars) | Yes -- `ConsumedWasVerified` | Complete |
| A4 | **Direct write bypass blocked**: mutation attempt outside protocolWrite is a no-op | Yes -- `write-guard.js` Proxy throws `WRITE_DISCIPLINE_VIOLATION` | Yes -- write-guard tests | Yes -- `DirectWriteBypassAttempt` (UNCHANGED vars) | Yes -- `WritePathExclusivity` (F17), `NoDirectWriteMutations` (F18) | Complete |
| A5 | **Terminal escape blocked**: attempt to transition out of terminal state is a no-op | Yes -- `verify.js` status guard; `finalize.js` terminal check | Yes -- `handshake-attack.test.js` | Yes -- `TerminalEscapeAttempt` (UNCHANGED vars) | Yes -- `TerminalStateIntegrity` (A5) | Complete |

---

## Coverage Summary

| Category | Total | Code-enforced | Tested | TLA+ modeled | Alloy modeled | CI gated | Fully covered |
|----------|-------|---------------|--------|--------------|---------------|----------|---------------|
| Safety (S1-S13)        | 13 | 13 | 13 | 13 | 13 | 13 | 13 |
| Safety — Signoff (S14-S19) | 6 | 0 | 0 | 6 | 6 | 0 | 0 |
| Data Integrity (D1-D5) | 5  | 5  | 5  | 2  | 5  | -- | 2  |
| Trust & Access (T1-T10) | 10 | 10 | 10 | 4  | 6  | -- | 4  |
| Adversarial (A1-A5)    | 5  | 5  | 5  | 5  | 5  | -- | 5  |
| **Total**              | **39** | **33** | **33** | **30** | **35** | **13** | **24** |

---

## Formal Model Files

| File | Format | Checks | How to Run |
|------|--------|--------|------------|
| `formal/ep_handshake.tla` | TLA+ | 26 safety theorems (T1–T26, all verified by TLC 2.19, including the 6 EP-IX continuity properties); 32 actions (including 9 EP-IX continuity actions); 15 variables | TLC model checker with `Handshakes = {h1}`, `Actors = {a1, a2}`, `Policies = {p1}`, `Claims = {c1}` — see `formal/PROOF_STATUS.md` |
| `formal/ep_relations.als` | Alloy 6 | 35 facts (F1-F35), 15 assertions (A1-A15), 5 visualization predicates, 6 new signatures (Mutation, Delegation, PolicyVersion, SignoffChallenge, SignoffAttestation, SignoffConsumption) | Alloy Analyzer `check` commands (scope 6-8) |

---

## CI Invariant Gate

| Script | Purpose | Exit code |
|--------|---------|-----------|
| `scripts/check-invariant-coverage.js` | Verifies all 26 verified safety invariants (T1–T26) have coverage across 4 layers: code guard, test, formal model, documentation | `0` = all covered, `1` = missing coverage |

The CI gate checks each invariant for:
1. **Code guard**: literal term found in `lib/` source files
2. **Test coverage**: literal term found in `tests/` test files
3. **Formal model**: property/fact/assertion name found in `formal/` model files
4. **Documentation**: invariant description found in `docs/` documentation files

If any critical invariant loses any coverage layer, CI fails with a detailed report showing which layers are missing.

---

## Expanded Formal Model Coverage (New)

### TLA+ Additions (`formal/ep_handshake.tla`)

| Property | Type | What it proves |
|----------|------|----------------|
| `WriteBypassSafety` | Safety theorem | Every non-initial state was reached via canonical write path |
| `TerminalStateIrreversibility` | Safety theorem | No transition out of consumed/revoked/expired/rejected (unified proof) |
| `DelegateCannotExceedPrincipal` | Safety theorem | Delegate scope is subset of principal scope |
| `DelegationAcyclicity` | Safety theorem | No circular delegation chains |
| `PolicyHashMismatchDetection` | Safety theorem | Policy version mismatch blocks verification |
| `EventCompleteness` | Safety theorem | Exactly one event of matching type per terminal state |
| `DirectWriteBypassAttempt` | Adversarial action | Models direct write attempt; proves UNCHANGED vars |
| `TerminalEscapeAttempt` | Adversarial action | Models terminal-state escape; proves UNCHANGED vars |
| `PolicyChange` | Environment action | Models policy update after binding (version increment) |
| `GrantDelegation` | Delegation action | Models delegation creation with scope/acyclicity guards |

### Alloy Additions (`formal/ep_relations.als`)

| Fact/Assertion | Type | What it proves |
|----------------|------|----------------|
| `WritePathExclusivity` (F17) | Fact | All mutations use CanonicalWrite channel |
| `NoDirectWriteMutations` (F18) | Fact | No DirectWrite mutations exist |
| `DelegationScopeBounded` (F19) | Fact | Delegate scope subset of principal maxScope |
| `NoSelfDelegation` (F20) | Fact | Principal and delegate are distinct entities |
| `DelegationAcyclic` (F21) | Fact | No cycles in delegation relation |
| `DelegationTransitivityBounded` (F22) | Fact | Transitive delegations respect scope bounds |
| `PolicyVersionConsistency` (F23) | Fact | Binding policyHash matches policy's hash |
| `MultiActorConsumptionUniqueness` (F24) | Fact | At most one consumption per handshake across all actors |
| `EventStateCorrespondence` (F25) | Fact | Exactly one terminal event per terminal state |
| `WritePathExclusive` (A6) | Assertion | No mutation bypasses protocolWrite |
| `DelegationScopeRespected` (A7) | Assertion | Delegation scope never exceeds principal |
| `NoDelegationCycles` (A8) | Assertion | No circular delegation chains |
| `PolicyHashConsistency` (A9) | Assertion | Binding policy hash matches policy |
| `MultiActorNoDoubleConsume` (A10) | Assertion | Two actors cannot both consume same handshake (scope 8) |
| `EventStateExactCorrespondence` (A11) | Assertion | Terminal events appear exactly once |

### TLA+ Accountable Signoff Additions (`formal/ep_handshake.tla`)

| Property | Type | What it proves |
|----------|------|----------------|
| `SignoffRequiresVerifiedHandshake` (S14) | Safety theorem | Challenge cannot be issued unless handshake is verified |
| `SignoffConsumeOnce` (S15) | Safety theorem | Signoff consumed at most once per handshake |
| `SignoffBindingMatch` (S16) | Safety theorem | Signoff binding hash equals handshake binding hash at all transitions |
| `SignoffTerminalIrreversible` (S17) | Safety theorem | denied/consumed_signoff/expired_signoff/revoked_signoff are terminal |
| `DenyCannotBeApproved` (S18) | Safety theorem | Denied signoff cannot transition to approved |
| `SignoffAuthorityMatch` (S19) | Safety theorem | Signoff actor must have authority class matching policy |
| `IssueChallenge` | Signoff action | Issues challenge for verified handshake with binding snapshot |
| `ViewChallenge` | Signoff action | Marks challenge as viewed |
| `ApproveSignoff` | Signoff action | Approves signoff with binding integrity check |
| `DenySignoff` | Signoff action | Denies signoff (terminal) |
| `ConsumeSignoff` | Signoff action | One-time consumption of approved signoff |
| `ExpireSignoff` | Signoff action | Expires signoff after TTL |
| `RevokeSignoff` | Signoff action | Revokes signoff (terminal) |
| `SignoffTerminalEscapeAttempt` | Adversarial action | Models terminal-state escape; proves UNCHANGED vars |

### Alloy Accountable Signoff Additions (`formal/ep_relations.als`)

| Fact/Assertion | Type | What it proves |
|----------------|------|----------------|
| `SignoffRequiresVerifiedHandshake` (F26) | Fact | SignoffChallenge only exists for verified handshakes |
| `SignoffAttestationBindingMatch` (F27) | Fact | Attestation binding matches challenge binding |
| `SignoffConsumptionBindingMatch` (F28) | Fact | Consumption binding matches attestation binding |
| `SignoffConsumeOnce` (F29) | Fact | At most one consumption per attestation |
| `SignoffAuthorityRequired` (F30) | Fact | Attestation human has required authority |
| `NoAttestationForDeniedOrExpired` (F31) | Fact | No attestation for denied or expired challenges |
| `NoConsumptionForRevokedAttestation` (F32) | Fact | No consumption for revoked attestations |
| `SignoffBindingIntegrity` (A12) | Assertion | Binding hash consistent across all signoff objects |
| `SignoffConsumeOnce` (A13) | Assertion | At most one consumption per attestation |
| `SignoffRequiresHandshake` (A14) | Assertion | No signoff without verified handshake |
| `FullChainIntegrity` (A15) | Assertion | Binding chain: handshake = challenge = attestation = consumption |

---

## Next Steps

1. ~~Run TLC on `ep_handshake.tla` with `Handshakes = {h1}`, `Actors = {a1, a2}`, `Policies = {p1}`, `Claims = {c1}`~~ — **DONE (2026-04-30)**: 413,137 states, 0 errors, all 26 theorems hold including the EP-IX continuity properties (T21–T26).
2. ~~Run Alloy Analyzer on `ep_relations.als`~~ — **DONE (2026-04-30)**: 15 of 15 assertions pass with 0 counterexamples (including A12–A15 signoff assertions). 35 facts (F1–F35) verified. CI runs Alloy 6.0.0 on every push.
3. Implement signoff runtime code (`lib/signoff/challenge.js`, `lib/signoff/approve.js`, `lib/signoff/revoke.js`) to enforce S14-S19
4. Add signoff test coverage for S14-S19
5. Add TLA+ coverage for D3-D5 (idempotency, party uniqueness, binding hash integrity)
6. Add Alloy coverage for T8-T9 (interaction binding, role spoofing)
7. Update `scripts/check-invariant-coverage.js` to include S14-S19 invariants in CI pipeline
8. Consider property-based testing to bridge formal models and runtime behavior
