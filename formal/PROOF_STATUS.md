# Formal Verification Status

This document tracks the honest state of all formal models in `formal/`.

**Distinction that matters:**
- **Specified** — the property is written down as a theorem or assertion in a model file
- **Verified** — a model checker has run and found no counterexamples

These are not the same. Specified properties describe what *should* be true.
Verified properties describe what *has been proven* true given the model's assumptions.

---

## TLA+ — `ep_handshake.tla`

**Model checker:** TLC (included with the TLA+ Toolbox or tla2tools.jar)
**Suggested parameters:** `Handshakes = {h1, h2}`, `Actors = {a1, a2}`, `Policies = {p1}`

| ID | Property | Type | Status |
|----|----------|------|--------|
| T1 | HandshakeNeverConsumedTwice | Safety | **Specified — not yet verified** |
| T2 | ConsumedHandshakeNeverRevoked | Safety | **Specified — not yet verified** |
| T3 | RevokedHandshakeNeverConsumed | Safety | **Specified — not yet verified** |
| T4 | HandshakeLifecycleIsAcyclic | Safety | **Specified — not yet verified** |
| T5 | InitiatedHandshakesHaveUniqueNonces | Safety | **Specified — not yet verified** |
| T6 | PresentedHandshakeHasMatchingInitiator | Safety | **Specified — not yet verified** |
| T7 | VerifiedHandshakeHasMatchingPresenter | Safety | **Specified — not yet verified** |
| T8 | DelegationChainIsAcyclic | Safety | **Specified — not yet verified** |
| T9 | DelegatedActorHasSufficientAuthority | Safety | **Specified — not yet verified** |
| T10 | DirectWriteBypassIsImpossible | Safety | **Specified — not yet verified** |
| T11 | ConcurrentRevokeConsumeIsSerializable | Safety | **Specified — not yet verified** |
| T12 | ReplayAfterConsumptionIsRejected | Safety | **Specified — not yet verified** |
| T13 | DuplicateConsumeAttemptIsRejected | Safety | **Specified — not yet verified** |
| T14 | SignoffRequiresAuthorizedActor | Safety | **Specified — code guard pending** |
| T15 | SignoffCannotBeReusedAcrossHandshakes | Safety | **Specified — code guard pending** |
| T16 | SignoffRevocationPreventsConsumption | Safety | **Specified — code guard pending** |
| T17 | SignoffChallengeExpiresIfUnanswered | Safety | **Specified — code guard pending** |
| T18 | SignoffAttestationRequiresMFA | Safety | **Specified — code guard pending** |
| T19 | TerminalEscapeAttemptIsRejected | Safety | **Specified — not yet verified** |

**To verify:** Run TLC on `ep_handshake.tla` with the suggested parameters.
See [TLA+ Toolbox setup](https://lamport.azurewebsites.net/tla/toolbox.html) or use the CLI:
```
java -jar tla2tools.jar -config ep_handshake.cfg TLCHandshake
```

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

*Last updated: 2026-04-02*
