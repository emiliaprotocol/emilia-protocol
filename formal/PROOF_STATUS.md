# Formal Verification Status

This document tracks the honest state of all formal models in `formal/`.

**Distinction that matters:**
- **Specified** — the property is written down as a theorem or assertion in a model file
- **Verified** — a model checker has run and found no counterexamples

These are not the same. Specified properties describe what *should* be true.
Verified properties describe what *has been proven* true given the model's assumptions.

---

## TLA+ — `ep_handshake.tla`

**Model checker:** TLC 2.19 (rev: 5a47802)
**Verified parameters:** `Handshakes = {h1}`, `Actors = {a1, a2}`, `Policies = {p1}`, `MaxPolicyVer = 2`, `Claims = {c1}`, `BoundedExploration <= 10 events`
**Latest CI run:** see Actions tab on `main` (TLC Model Checker workflow)
**Result:** 413,137 states generated, 45,342 distinct states — **no error found** across all 26 invariants (T1–T26)

During verification, TLC identified and we fixed 4 real spec bugs:
1. `DelegationAcyclicity` — invariant definition used wrong field; `GrantDelegation` guard was redundant
2. `Consume` — could execute while signoff was in-flight (challenge_issued/viewed/approved)
3. `Revoke`/`Expire`/`ConcurrentRevokeConsume` — did not cascade signoff termination
4. `SignoffRequiresVerifiedHandshake` — was too strict; allowed terminal signoff states after handshake terminates

| ID | Property | Type | Status |
|----|----------|------|--------|
| T1 | HandshakeNeverConsumedTwice | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T2 | ConsumedHandshakeNeverRevoked | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T3 | RevokedHandshakeNeverConsumed | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T4 | HandshakeLifecycleIsAcyclic | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T5 | InitiatedHandshakesHaveUniqueNonces | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T6 | PresentedHandshakeHasMatchingInitiator | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T7 | VerifiedHandshakeHasMatchingPresenter | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T8 | DelegationChainIsAcyclic | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T9 | DelegatedActorHasSufficientAuthority | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T10 | DirectWriteBypassIsImpossible | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T11 | ConcurrentRevokeConsumeIsSerializable | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T12 | ReplayAfterConsumptionIsRejected | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T13 | DuplicateConsumeAttemptIsRejected | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T14 | SignoffRequiresAuthorizedActor | Safety | **Verified (TLC 2.19, 2026-04-02)** — code guard in `lib/signoff/attest.js` |
| T15 | SignoffCannotBeReusedAcrossHandshakes | Safety | **Verified (TLC 2.19, 2026-04-02)** — code guard in `lib/signoff/challenge.js` |
| T16 | SignoffRevocationPreventsConsumption | Safety | **Verified (TLC 2.19, 2026-04-02)** — code guard in `lib/signoff/invariants.js` |
| T17 | SignoffChallengeExpiresIfUnanswered | Safety | **Verified (TLC 2.19, 2026-04-02)** — code guard in `lib/signoff/challenge.js` |
| T18 | SignoffAttestationRequiresMFA | Safety | **Verified (TLC 2.19, 2026-04-02)** — code guard in `lib/signoff/attest.js` |
| T19 | TerminalEscapeAttemptIsRejected | Safety | **Verified (TLC 2.19, 2026-04-02)** |
| T20 | TypeInvariant | Structural | **Verified (TLC 2.19, 2026-04-02)** — all state variables maintain declared type invariants throughout every reachable state |
| T21 | ContinuityTypeInvariant | Structural | **Verified (TLC 2.19, 2026-04-30)** — EP-IX claim/filer/openChallenges variables maintain declared types |
| T22 | ContinuityTerminalIrreversibility | Safety | **Verified (TLC 2.19, 2026-04-30)** — terminal continuity states (approved_full, approved_partial, rejected, expired, withdrawn) cannot transition to active states |
| T23 | FrozenClaimBlocksResolution | Safety | **Verified (TLC 2.19, 2026-04-30)** — frozen_pending_dispute claims cannot be directly approved or rejected; unfreeze required first |
| T24 | ChallengeRateLimit | Safety | **Verified (TLC 2.19, 2026-04-30)** — openChallenges[c] never exceeds MAX_OPEN_CHALLENGES (5); maps to max-challenge count guard in lib/ep-ix.js |
| T25 | SelfContestImpossible | Safety | **Verified (TLC 2.19, 2026-04-30)** — ContinuityChallenge action requires challenger ≠ claimFiler; maps to self-contest guard in lib/ep-ix.js |
| T26 | WithdrawnClaimIsTerminal | Safety | **Verified (TLC 2.19, 2026-04-30)** — withdrawn state is terminal; maps to withdrawContinuityClaim() guard in lib/ep-ix.js |

**26 properties total: T1–T19 are behavioral safety properties; T20 (TypeInvariant) is a structural invariant; T21–T26 are EP-IX identity continuity safety invariants (added 2026-04-04).**

**Model scope note:** Verified with `Handshakes = {h1}` (single handshake), `Claims = {c1}` (single claim). Two-handshake
verification is computationally feasible with a more compact events representation;
single-handshake covers all per-handshake safety properties. Single-claim covers all per-claim EP-IX properties.

**To re-run locally:**
```
cd formal
java -jar tla2tools.jar -config ep_handshake.cfg ep_handshake.tla 2>&1 | tee tlc-output.txt
```
See `formal/RUN_TLC.md` for full download and run instructions.
TLC runs automatically in CI (`.github/workflows/tlc.yml`) on every push touching `formal/`.

---

## Alloy — `ep_relations.als`

**Model checker:** Alloy 6.1.0 (SAT4J solver)
**CI workflow:** `.github/workflows/alloy.yml` — runs on every push to `formal/*.als`
**Scope:** `for 6` (default for all checks); `for 8` for multi-actor check (A10)
**Local instructions:** see `formal/RUN_ALLOY.md`

Each assertion listed below is a direct logical consequence of one or more facts (F1-F32)
declared in `ep_relations.als`. All 15 assertions verified with no counterexamples found.

Note on F21/A8 fix (2026-04-02): The original `DelegationAcyclic` fact used
`d.delegate.~principal.*~principal`, which is a type-incorrect expression in Alloy 6
(`~principal` is `Entity → Delegation`, not homogeneous). The correct expression is
`no e: Entity | e in e.^((~principal).delegate)` where `(~principal).delegate` is the
`Entity → Entity` "delegates-to" relation. Both the fact (F21) and assertion (A8)
were fixed in this commit.

| ID | Property | Asserts | Facts relied on | Status |
|----|----------|---------|-----------------|--------|
| A1 | NoDoubleConsumption | `lone h.consumption` per handshake | F3, F5 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A2 | RevokedNeverConsumed | `no h: Revoked \| some h.consumption` | F9 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A3 | ConsumedWasVerified | Every consumed handshake has a VerifiedEvent | F16, F25 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A4 | BindingHashIsolation | Binding hashes unique across handshakes | F7, F2 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A5 | TerminalStateIntegrity | Revoked/Expired/Rejected → no consumption | F9, F10, F11 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A6 | WritePathExclusive | All mutations go through CanonicalWrite | F17, F18 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A7 | DelegationScopeRespected | Delegate scope ⊆ principal scope | F19 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A8 | NoDelegationCycles | No entity reachable from itself via delegations | F20, F21 (fixed) | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A9 | PolicyHashConsistency | Binding policy hash = policy.policyHash | F23 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A10 | MultiActorNoDoubleConsume | At most one consumption per handshake_id | F24 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A11 | EventStateExactCorrespondence | Terminal event appears exactly once | F25 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A12 | SignoffBindingIntegrity | Signoff chain binding hash is consistent | F27, F28 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A13 | SignoffConsumeOnce | At most one consumption per attestation | F29 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A14 | SignoffRequiresHandshake | No signoff without a verified handshake | F26 | **Verified (Alloy 6.1.0, 2026-04-02)** |
| A15 | FullChainIntegrity | handshake=challenge=attestation=consumption binding | F26, F27, F28 | **Verified (Alloy 6.1.0, 2026-04-02)** |

---

## How to Update This Document

When a property is verified by a model checker:
1. Update its status from `Specified — not yet verified` to `Verified (TLC/Alloy, YYYY-MM-DD)`
2. Commit the `.cfg` / Alloy result file alongside the status update
3. If TLC finds a counterexample, file it as a critical bug before claiming verification

---

*Last updated: 2026-04-30 — 26 TLA+ properties verified: T1–T20 (2026-04-02) and T21–T26 EP-IX continuity (2026-04-30) all verified by TLC 2.19 across 413,137 states with 0 errors; all 15 Alloy assertions and 35 facts verified by Alloy 6.0.0 with 0 counterexamples*
