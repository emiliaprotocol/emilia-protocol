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

The 26 invariants below are exactly the `INVARIANT` list TLC checks in
[`ep_handshake.cfg`](./ep_handshake.cfg) — grep any name there to confirm it exists.
CI ([`.github/workflows/tlc.yml`](../.github/workflows/tlc.yml)) runs TLC on every push
and fails the build on any violation.

**Core state machine and delegation — 14 invariants**

| Invariant (as in `ep_handshake.cfg`) | What it proves |
|---|---|
| `TypeInvariant` | every state variable keeps its declared type in every reachable state |
| `ConsumeOnceSafety` | an authorization is consumed at most once |
| `ConsumeRequiresVerified` | consumption is reachable only from a verified handshake |
| `RevokedIsTerminal` | a revoked handshake never returns to an active/consumable state |
| `ExpiredIsTerminal` | an expired handshake is terminal |
| `RejectedIsTerminal` | a rejected handshake is terminal |
| `TerminalStateIrreversibility` | no terminal state transitions back to a non-terminal one |
| `WriteBypassSafety` | no approval-bearing write is reachable without passing the gate |
| `PolicyRequired` | an authorization cannot proceed without its policy reference |
| `PolicyHashMismatchDetection` | a policy-hash mismatch is detected and refused |
| `DelegateCannotExceedPrincipal` | a delegate's authority never exceeds the principal's |
| `DelegationAcyclicity` | the delegation chain is acyclic |
| `EventCoverage` | every modeled transition emits its evidence event |
| `EventCompleteness` | the evidence log is complete over the reachable state space |

**Accountable signoff / quorum — 6 invariants**

| Invariant | What it proves |
|---|---|
| `SignoffRequiresVerifiedHandshake` | a signoff is valid only against a verified handshake |
| `SignoffConsumeOnce` | a signoff is consumed at most once (no reuse across handshakes) |
| `SignoffBindingMatch` | a signoff binds to the exact action context |
| `SignoffTerminalIrreversible` | a terminal signoff state cannot be reversed |
| `DenyCannotBeApproved` | a denied action can never become approved (separation of duties) |
| `SignoffAuthorityMatch` | the signing actor is an authorized approver |

**EP-IX identity continuity — 6 invariants**

| Invariant | What it proves |
|---|---|
| `ContinuityTypeInvariant` | EP-IX claim/filer/challenge variables keep their declared types |
| `ContinuityTerminalIrreversibility` | terminal continuity states cannot return to active |
| `FrozenClaimBlocksResolution` | a frozen-pending-dispute claim cannot be approved/rejected without unfreezing |
| `ChallengeRateLimit` | open challenges never exceed `MAX_OPEN_CHALLENGES` |
| `SelfContestImpossible` | a filer cannot challenge their own claim |
| `WithdrawnClaimIsTerminal` | a withdrawn claim is terminal |

**26 machine-checked invariants total** — 14 core + 6 signoff/quorum + 6 EP-IX, each the exact
identifier TLC runs. The Alloy models (`ep_quorum.als`, `ep_relations.als`, `ep_federation.als`)
separately check the m-of-n two-person-rule and no-key-fills-two-slots properties.

**Enforced in code, NOT model-checked (do not count as TLC-verified):** a few properties are
enforced by code guards and covered by unit/conformance tests, not by the TLA+/Alloy models —
notably signoff attestation user-verification / MFA gating (`lib/signoff/attest.js`, exercised by
the WebAuthn signoff conformance vectors) and challenge wall-clock expiry (`lib/signoff/challenge.js`).
The models deliberately do NOT cover WebAuthn/device binding, the approver directory, log
checkpoints, or wall-clock time. See the model scope note below.

**Model scope note:** The CI default is `Handshakes = {h1}` (single handshake), `Claims = {c1}` (single claim):
exhaustively checked, 413,137 states / 45,342 distinct, depth 20, all 26 invariants hold with no counterexample.
Single-handshake covers all per-handshake safety properties; single-claim covers all per-claim EP-IX properties.

The two-handshake configuration (`Handshakes = {h1, h2}`) was also run under this representation. It explored
several million distinct states with no counterexample before the search was stopped: the state space explodes
(tens of millions of states, frontier still growing) and does not terminate at a CI-friendly scale, so
cross-handshake concurrency here is bounded-tested, not exhaustively proven. Exhaustively proving the composed,
concurrent case is future work and is better suited to a symbolic protocol prover (Tamarin/ProVerif with a
Dolev-Yao attacker over the full WebAuthn / directory / log composition) than to TLC brute force. We do not
claim exhaustive verification beyond one handshake.

**To re-run locally:**
```
cd formal
java -jar tla2tools.jar -config ep_handshake.cfg ep_handshake.tla 2>&1 | tee tlc-output.txt
```
See `formal/RUN_TLC.md` for full download and run instructions.
TLC runs automatically in CI (`.github/workflows/tlc.yml`) on every push touching `formal/`.

---

## Alloy — `ep_relations.als`

**Model checker:** Alloy 6.2.0 (SAT4J solver)
**CI workflow:** `.github/workflows/alloy.yml` — compiles `formal/AlloyCheck.java` and
runs all four `formal/*.als` models headless on every push/PR touching `formal/**.als`,
failing the build on any counterexample (mirrors the `tlc.yml` gating pattern).
**Scope:** `for 6` (default for all checks); `for 8` for multi-actor check (A10)
**Local instructions:** see `formal/RUN_ALLOY.md`

**CI-gated execution (2026-07-18):** all four Alloy models were run headless against
Alloy 6.2.0 via `formal/AlloyCheck.java` — **32/32 checks held with no counterexample,
8/8 `run` predicates satisfiable** in their bounded scopes. The workflow pins the
`org.alloytools.alloy.dist.jar` by tag and SHA-256, so the gate is reproducible. (The
earlier per-row "Alloy 6.1.0" version tag was inaccurate — no such release asset exists;
`v6.2.0` is the version now pinned and executed.)

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
| A1 | NoDoubleConsumption | `lone h.consumption` per handshake | F3, F5 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A2 | RevokedNeverConsumed | `no h: Revoked \| some h.consumption` | F9 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A3 | ConsumedWasVerified | Every consumed handshake has a VerifiedEvent | F16, F25 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A4 | BindingHashIsolation | Binding hashes unique across handshakes | F7, F2 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A5 | TerminalStateIntegrity | Revoked/Expired/Rejected → no consumption | F9, F10, F11 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A6 | WritePathExclusive | All mutations go through CanonicalWrite | F17, F18 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A7 | DelegationScopeRespected | Delegate scope ⊆ principal scope | F19 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A8 | NoDelegationCycles | No entity reachable from itself via delegations | F20, F21 (fixed) | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A9 | PolicyHashConsistency | Binding policy hash = policy.policyHash | F23 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A10 | MultiActorNoDoubleConsume | At most one consumption per handshake_id | F24 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A11 | EventStateExactCorrespondence | Terminal event appears exactly once | F25 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A12 | SignoffBindingIntegrity | Signoff chain binding hash is consistent | F27, F28 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A13 | SignoffConsumeOnce | At most one consumption per attestation | F29 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A14 | SignoffRequiresHandshake | No signoff without a verified handshake | F26 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| A15 | FullChainIntegrity | handshake=challenge=attestation=consumption binding | F26, F27, F28 | **Verified (Alloy 6.2.0, 2026-07-18)** |

---

## Alloy — `ep_federation.als` (PIP-006 Federation)

**Model checker:** Alloy 6.2.0 (SAT4J solver)
**CI workflow:** `.github/workflows/alloy.yml` — CI-gated with the other three models (see above)
**Scope:** `for 8` (all checks)
**Local instructions:** see `formal/RUN_ALLOY.md`

All 7 assertions re-executed and held with no counterexample under Alloy 6.2.0 in the
2026-07-18 CI-gated run.

Models the cross-operator verification path (PIP-006): an EP-RECEIPT-v1 issued
by Operator A, verified by an independent relying party using only A's published
discovery surfaces. Ed25519 unforgeability is abstracted as fact C1
(`verifiesUnder` = the signing key for an untampered receipt; the empty set once
tampered). Maps to `packages/verify/federation.js`. All 7 assertions verified
with no counterexample.

| ID | Property | Asserts | Facts relied on | Status |
|----|----------|---------|-----------------|--------|
| S1 | AcceptedIsAuthentic | accepted ⇒ signed by an advertised key over an untampered payload | C1, C2 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| S2 | TamperedNeverAccepted | a tampered receipt is never accepted | C1 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| S3 | UnadvertisedKeyRejected | a receipt signed by a key the operator does not advertise is rejected | C1 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| S4 | HistoricalKeyStillVerifies | a pre-rotation receipt (advertised historical key) is still accepted | C1, C3 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| S5 | RevokedNeverAccepted | a receipt the issuer revoked is never accepted | C4 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| S6 | NoTrustLaundering | acceptance routes only through a key owned by the receipt's own signer | C1, C2 | **Verified (Alloy 6.2.0, 2026-07-18)** |
| S7 | PortabilityIsObserverIndependent | acceptance depends only on the receipt + its signer's surfaces, not on who verifies | C1 | **Verified (Alloy 6.2.0, 2026-07-18)** |

---

## Alloy — `ep_quorum.als` (two-person rule)

**Model checker:** Alloy 6.2.0 (SAT4J solver)
**CI workflow:** `.github/workflows/alloy.yml` — CI-gated with the other three models
**Scope:** `for 6` (all checks)
**Local instructions:** see `formal/RUN_ALLOY.md`

Models m-of-n quorum signoff. All 6 assertions verified with no counterexample and
`showStrongQuorum` satisfiable in the 2026-07-18 CI-gated run.

| ID | Property | Asserts | Status |
|----|----------|---------|--------|
| Q1 | SelfApprovalImpossible | the requester can never fill an approval slot | **Verified (Alloy 6.2.0, 2026-07-18)** |
| Q2 | NoHumanFillsTwoSlots | one human occupies at most one quorum slot | **Verified (Alloy 6.2.0, 2026-07-18)** |
| Q3 | NoKeyFillsTwoSlots | one signing key occupies at most one quorum slot | **Verified (Alloy 6.2.0, 2026-07-18)** |
| Q4 | TwoPersonRuleHolds | a satisfied quorum has ≥2 distinct human approvers | **Verified (Alloy 6.2.0, 2026-07-18)** |
| Q5 | OrderedChainAcyclic | an ordered approval chain has no cycle | **Verified (Alloy 6.2.0, 2026-07-18)** |
| Q6 | OrderedChainLinear | an ordered approval chain is a single linear path | **Verified (Alloy 6.2.0, 2026-07-18)** |

---

## Alloy — `ep_delegation.als` (EP-CAPABILITY-DELEGATION-v1)

**Model checker:** Alloy 6.2.0 (SAT4J solver)
**CI workflow:** `.github/workflows/alloy.yml` — CI-gated with the other three models
**Scope:** `for 6` (`but 5 int` for the arithmetic checks)
**Local instructions:** see `formal/RUN_ALLOY.md`

States the ingest-time structural invariants the runtime validator enforces at the chain
level — mirrors `packages/gate/capability-receipt.js` `assertDelegationChain()` and the
`DelegationAuthorityNonIncreasing` invariant in `formal/ep_capability.tla`. This is the
model that closes the "Alloy authored-not-run" gap: it was authored to the repo's Alloy
convention but had never been executed. All 4 assertions now verified with no
counterexample and `showChain` satisfiable in the 2026-07-18 CI-gated run.

| ID | Property | Asserts | Status |
|----|----------|---------|--------|
| D1 | DelegationAcyclic | a valid chain is acyclic; no parent recurs | **Verified (Alloy 6.2.0, 2026-07-18)** |
| D2 | DelegationIdsUnique | each hop's delegation_id is distinct | **Verified (Alloy 6.2.0, 2026-07-18)** |
| D3 | LeafIsNotItsOwnAncestor | the leaf capability is never a parent in its own chain | **Verified (Alloy 6.2.0, 2026-07-18)** |
| D4 | AuthorityNonIncreasing | authority is monotonically non-increasing root→leaf | **Verified (Alloy 6.2.0, 2026-07-18)** |

---

## How to Update This Document

## Tamarin (symbolic, Dolev-Yao) : `tamarin/ep_receipt_core.spthy`

**Status: first symbolic-crypto model, machine-checked 2026-07-05** (tamarin-prover 1.10.0,
Maude 3.4, via Docker; full tool output and the re-run one-liner are in `formal/tamarin/README.md`).
Unlike the TLA+/Alloy models above, this model does NOT treat "signature verifies" as an axiom:
it runs a Dolev-Yao attacker (full network control, may request the human to sign other actions,
explicit key-compromise rule) against the core receipt lemma.

Verbatim tool summary:

```
executable_honest_receipt (exists-trace): verified (8 steps)
core_authenticity_uv_gated (all-traces): verified (12 steps)
no_replay_across_actions (all-traces): verified (12 steps)
injective_acceptance_with_consumption (all-traces): verified (6 steps)
unchecked_acceptance_is_injective (all-traces): falsified - found trace (10 steps)
```

The falsified lemma is a deliberate, by-design result: it asserts injective acceptance WITHOUT a
consumption check, and Tamarin's counterexample is a same-receipt replay (the one honest receipt
delivered twice; no forgery, no key reveal). Adding the one-time-consumption restriction restores
injectivity, which Tamarin proved. The model thereby demonstrates mechanically that one-time
consumption is load-bearing, not defense-in-depth.

**Scoped out (stated in the model header):** the Approver Directory / Merkle log / checkpoints
(pinning is one out-of-band step), WebAuthn attestation internals (user verification is assumed as
the spec's MUST, not proven), policy/quorum/expiry (covered by the state-machine models above), JCS
canonicalization (symbolic injective-encoding assumption; exercised by the EP-CANONICALIZATION-v1
vectors), and any computational/algorithm-specific claim. The full WebAuthn / directory / log
composition under a symbolic prover remains future work.

---

## Tamarin (symbolic, Dolev-Yao) : `tamarin/ep_quorum_core.spthy`

**Status: second symbolic-crypto model, machine-checked 2026-07-06** (tamarin-prover 1.10.0,
Maude 3.4, via Docker; full tool output, the falsification history, and the re-run one-liner are
in `formal/tamarin/README.md`). Layers m-of-n quorum, in the smallest non-trivial instance
(2-of-2), on top of the same UV-gated signature machinery proven in `ep_receipt_core.spthy`.
It does NOT re-prove the single-signature core lemma; it assumes the per-signature core
guarantees and asks whether a satisfied 2-of-2 quorum necessarily consists of two distinct
UV-gated signatures over the same action, and whether an initiator can count toward its own
quorum. Same Dolev-Yao attacker as the core model, additionally choosing which action goes up
for quorum and which identity is named the initiator.

Verbatim tool summary:

```
executable_quorum (exists-trace): verified (12 steps)
quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (20 steps)
initiator_cannot_self_approve (all-traces): verified (4 steps)
no_single_signer_fills_quorum (all-traces): verified (4 steps)
commit_requires_signature_over_that_action (all-traces): verified (7 steps)
```

| Lemma | Result | Meaning |
|---|---|---|
| `executable_quorum` | verified | A 2-of-2 quorum can commit with two distinct honest UV-gated approvers, neither the initiator, no key compromise (model not vacuous). |
| `quorum_requires_two_distinct_uv_gated_signatures` | verified | Any commit of action a with uncompromised approvers H1, H2 forces H1 != H2 and a UV-then-signature over exactly a by each, before the commit. |
| `initiator_cannot_self_approve` | verified | No commit names the initiator as either approver (Section 6 SelfApprovalImpossible / G4); the initiator identity is attacker-chosen. |
| `no_single_signer_fills_quorum` | verified | The two committing approvers are never the same identity (distinct pinned keys entail distinct enrolled identities). |
| `commit_requires_signature_over_that_action` | verified | No commit of a while an uncompromised named approver never signed exactly a; rules out transplanting a signature over any other action. |

**Falsification history (honest record):** an earlier revision of this model omitted the
initiator identity from the signed Authorization Context. Under that revision Tamarin FALSIFIED
`quorum_requires_two_distinct_uv_gated_signatures` and `commit_requires_signature_over_that_action`:
approvers signed action a under one initiator label and the executor committed a under a different
one, because the approver signatures were not tied to the committing initiator. The fix was
spec-faithful, not a lemma weakening: bind the initiator into the signed context
(`<'ep_signoff_v1', h(action), initiator, nonce>`, per Section 3), after which all five lemmas
verify. The falsification identified a load-bearing binding.

**Scoped out (stated in the model header):** COLLUSION, one-human-many-identities, and COERCION
(Section 11.7 is explicit that separation of duties guarantees distinct signing IDENTITIES, not two
independent wills; the one-human-to-one-identity binding is the directory's job); the Approver
Directory / Merkle log / checkpoints (pinning is one out-of-band step); WebAuthn attestation
internals (UV assumed as the spec's MUST, not proven); general m-of-n for arbitrary m,n (only the
2-of-2 instance is modeled); expiry / policy-hash / one-time consumption of the committed quorum
(consumption is `ep_receipt_core.spthy`'s subject, G3); JCS canonicalization and any computational
claim. `ep_receipt_core.spthy` and `ep_quorum_core.spthy` are TWO focused models: the quorum model
assumes rather than re-derives the core lemmas, and both abstract key pinning. The composed v2 model
below now re-derives an abstract 2-of-2 quorum together with consumption, CAID, authority,
registry-view, revocation, issuer pinning, and execution. Full WebAuthn internals, directory
publication, Merkle-log mechanics, arbitrary k-of-n, and wall-clock semantics remain unmodeled.

---

## Tamarin (symbolic, Dolev-Yao) : `tamarin/ep_reliance_composed.spthy`

**Status: composed acceptance path, machine-checked 2026-07-10.** This model
puts signed challenge, computed CAID, exact profile/audience/initiator binding,
two distinct UV-gated approvals, scoped authority under an exact pinned registry
epoch/head, revocation state, pinned receipt issuer, one-time consumption, and
execution in one trace. The pinned container digest, model
SHA-256, command, and exact output summary are recorded in
`formal/tamarin/results/ep_reliance_composed.summary.txt` and re-run by CI.

```
executable_composed_reliance (exists-trace): verified (19 steps)
execution_requires_full_composition (all-traces): verified (97 steps)
caid_binds_family_and_material (all-traces): verified (2 steps)
initiator_cannot_self_approve (all-traces): verified (4 steps)
no_single_signer_fills_quorum (all-traces): verified (2 steps)
no_issuer_laundering (all-traces): verified (781 steps)
strict_registry_view_is_exact (all-traces): verified (25 steps)
no_cross_action_profile_or_audience_replay (all-traces): verified (37 steps)
execution_has_honest_approvals_or_prior_compromise (all-traces): verified (170 steps)
injective_execution_with_consumption (all-traces): verified (2 steps)
unchecked_composition_is_injective (all-traces): falsified - found trace (31 steps)
unchecked_registry_view_is_current (all-traces): falsified - found trace (20 steps)
```

The falsified comparison lemmas demonstrate same-receipt replay without
consumption and stale/equivocating registry-view acceptance without exact head
binding. The strict paths verify. The model proves exact binding and required
composition under uncompromised pinned roots; it does not
prove WebAuthn internals, canonical parsers, amount arithmetic, policy authorship,
clock freshness, transparency-log completeness, collusion resistance, or
downstream exactly-once effects.

---

When a property is verified by a model checker:
1. Update its status from `Specified — not yet verified` to `Verified (TLC/Alloy, YYYY-MM-DD)`
2. Commit the `.cfg` / Alloy result file alongside the status update
3. If TLC finds a counterexample, file it as a critical bug before claiming verification

---

*Last updated: 2026-07-10 (composed reliance-path v2: 10 strict lemmas verified; no-consumption and unpinned-registry-view comparisons falsified with concrete traces; all well-formedness checks clean). Prior: 2026-07-06 (Tamarin quorum model added: 5 lemmas verified). Prior: 2026-07-05 (Tamarin core-receipt model added). Prior: 2026-06-11 — 26 TLA+ properties verified across 413,137 states with 0 errors; 15 relation assertions and 7 federation assertions verified with 0 counterexamples.*
