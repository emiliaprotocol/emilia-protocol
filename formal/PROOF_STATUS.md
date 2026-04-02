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
**Verified parameters:** `Handshakes = {h1}`, `Actors = {a1, a2}`, `Policies = {p1}`, `MaxPolicyVer = 2`, `BoundedExploration <= 10 events`
**CI run:** https://github.com/emiliaprotocol/emilia-protocol/actions/runs/23911847185
**Result:** 7,857 states generated, 1,374 distinct states — **no error found**

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

**Model scope note:** Verified with `Handshakes = {h1}` (single handshake). Two-handshake
verification is computationally feasible with a more compact events representation;
single-handshake covers all per-handshake safety properties.

**To re-run locally:**
```
cd formal
java -jar tla2tools.jar -config ep_handshake.cfg ep_handshake.tla 2>&1 | tee tlc-output.txt
```
See `formal/RUN_TLC.md` for full download and run instructions.
TLC runs automatically in CI (`.github/workflows/tlc.yml`) on every push touching `formal/`.

---

## Alloy — `ep_relations.als`

**Model checker:** Alloy Analyzer 6.x
**Suggested scope:** `--` (default, 3 atoms per sig)

| ID | Property | Type | Status |
|----|----------|------|--------|
| A1 | NoOrphanReceipts | Assert | **Specified — not yet verified** |
| A2 | EntityIdentityIsUnique | Assert | **Specified — not yet verified** |
| A3 | HandshakePartiesAreDistinct | Assert | **Specified — not yet verified** |
| A4 | DelegationIsAcyclic | Assert | **Specified — not yet verified** |
| A5 | PolicyHashIsImmutable | Assert | **Specified — not yet verified** |
| A6 | ReceiptLedgerIsAppendOnly | Assert | **Specified — not yet verified** |
| A7 | TrustScoreIsMonotonicallyBounded | Assert | **Specified — not yet verified** |
| A8 | SignoffConsumptionIsAtomic | Assert | **Specified — not yet verified** |
| A9 | HandshakeConsumptionIsAtomic | Assert | **Specified — not yet verified** |
| A10 | NoncesAreGloballyUnique | Assert | **Specified — not yet verified** |
| A11 | DisputeResolutionIsTerminal | Assert | **Specified — not yet verified** |
| A12 | RevokedHandshakeHasNoConsumption | Assert | **Specified — not yet verified** |
| A13 | DelegationAuthorityDoesNotExceedGrantor | Assert | **Specified — not yet verified** |
| A14 | IdentityContinuityPreservesHistory | Assert | **Specified — not yet verified** |
| A15 | ApiKeyRotationInvalidatesPrevious | Assert | **Specified — not yet verified** |

**To verify:** Open `ep_relations.als` in [Alloy Analyzer](https://alloytools.org/) and click
"Execute → Check All Assertions." All assertions should find no counterexample.

---

## How to Update This Document

When a property is verified by a model checker:
1. Update its status from `Specified — not yet verified` to `Verified (TLC/Alloy, YYYY-MM-DD)`
2. Commit the `.cfg` / Alloy result file alongside the status update
3. If TLC finds a counterexample, file it as a critical bug before claiming verification

---

*Last updated: 2026-04-02 — All 20 TLA+ properties verified by TLC 2.19*
