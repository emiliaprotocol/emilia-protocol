# Conservation of Authority

## Status and claim boundary

**Conservation of Authority** is the name of a composed safety property over
EMILIA's existing bounded formal models. It is not a claim of a new
mathematical theorem, an unbounded proof of the implementation, or a proof
about legal authority, human intent, provider truth, cryptographic algorithms,
or database correctness.

The exact citeable result in this repository is:

> **[COA-B1]** In the checked finite scopes of EMILIA's TLC and Alloy models,
> no modeled delegation or receipt-program transition creates authority beyond
> its parent grant, reopens terminal authority, or permits a second provider
> effect under the same stable operation identifier.

Every qualifier in that sentence is load-bearing. “Checked finite scopes” means
the exact model bounds below; “modeled” excludes implementation details the
models abstract; and “same stable operation identifier” is not a claim that an
external provider implements idempotency correctly.

## Property

For a root authority `A0`, a derived authority `Ai`, and a consequential
operation `o`, authority is conserved in the bounded model when all four parts
hold:

1. **Containment:** `scope(Ai) subseteq scope(Ai-1)`,
   `budget(Ai) <= budget(Ai-1)`, and
   `expiry(Ai) <= expiry(Ai-1)`.
2. **No authority creation by structure:** delegation is acyclic, each hop is
   uniquely identified, and the leaf cannot appear as its own ancestor.
3. **Single-use consequence:** an effect can begin only for the attempt that
   owns the atomic reservation for `o`; no second attempt for `o` reaches the
   effect boundary.
4. **Fail-closed terminality:** committed authority never becomes available
   again, and an uncertain post-effect outcome either commits as indeterminate
   or leaves the reservation locked.

This is a conjunction of previously separate model properties. Naming the
conjunction makes the architecture easier to cite; it does not strengthen the
underlying checker results.

## Machine-checked evidence map

| Conservation part | Model and checked property | What the property contributes |
|---|---|---|
| Scope containment | `ep_handshake.tla`: `DelegateCannotExceedPrincipal` | Delegate scope remains a subset of principal scope in the bounded handshake state machine. |
| Scope containment | `ep_relations.als`: `DelegationScopeRespected` | Every modeled delegation's scope is contained by its declared maximum scope. |
| Budget containment | `ep_capability.tla`: `ReserveWithinBudget`, `DelegationAuthorityNonIncreasing`, `BudgetImmutable` | Reserved plus consumed spend does not exceed the immutable budget; delegated budget does not increase. |
| Expiry containment | `ep_capability.tla`: `ChildExpiryBoundedByParent` | A child expiry does not exceed its parent's expiry. |
| Structural non-creation | `ep_capability.tla`: `DelegationAcyclic`; `ep_delegation.als`: `DelegationAcyclic`, `DelegationIdsUnique`, `LeafIsNotItsOwnAncestor`, `AuthorityNonIncreasing` | The bounded capability path is acyclic, has unique hops, excludes the leaf as an ancestor, and does not increase amount along the chain. |
| Single-use consequence | `ep_handshake.tla`: `ConsumeOnceSafety`; `ep_relations.als`: `NoDoubleConsumption`, `MultiActorNoDoubleConsume` | A modeled authorization/handshake has at most one consumption. |
| Single-use consequence | `ep_capability.tla`: `NoDoubleCommit`, `CommitRequiresReserve`, `ConsumptionMonotonic` | Commit is one-way, requires a reservation, and consumed authority does not decrease. |
| Single-use consequence | `ep_receipt_program.tla`: `EffectRequiresReservation`, `ReservationOwnership`, `SingleEffectOwner`, `ReplayFailClosed` | Only the reservation owner enters the provider effect; an in-flight or committed operation blocks a second attempt. |
| Fail-closed terminality | `ep_handshake.tla`: `TerminalStateIrreversibility`; `ep_receipt_program.tla`: `IndeterminateLocksAuthority`, `TerminalAttemptStability`, `CommittedOperationStability`, `ReservationNeverReopens` | Terminal outcomes do not reverse; uncertainty cannot silently restore authority. |

Registry-view exactness is a prerequisite to knowing which authority set is
being evaluated, but it is not re-proved by the TLC/Alloy conjunction above.
The separate Tamarin composed-reliance model checks
`strict_registry_view_is_exact` under its symbolic assumptions and deliberately
falsifies `unchecked_registry_view_is_current` when exact registry-head binding
is omitted. Conservation therefore applies **under the pinned registry view in
the relevant model**, not to an unpinned or universally current registry.

## Exact checked bounds

- `ep_handshake.tla`: one handshake, two actors, one policy, policy versions up
  to 2, one continuity claim, and at most 10 modeled events in the CI model.
- `ep_capability.tla`: three capability atoms, two operation atoms, budget and
  time domains `0..2`, and delegation depth at most 2.
- `ep_relations.als`: scope 6 for the delegation assertion and scope 8 for the
  multi-actor consumption assertion.
- `ep_delegation.als`: scope 6, with 5-bit integers for amount monotonicity.
- `ep_receipt_program.tla`: two attempts contending for one stable operation
  identifier.

Within each finite model, TLC/Alloy exhaustively checks all reachable
states/instances permitted by that model and configuration. The result does not
generalize automatically to arbitrary cardinalities.

## Explicit exclusions

The property does **not** establish:

- a refinement proof from TypeScript, SQL, or Solidity to the formal models;
- unbounded delegation depth, attempts, operations, budgets, or concurrency;
- database serializability, durability, or reservation-token unpredictability;
- cryptographic unforgeability or canonicalization correctness;
- that CAID hashes do not collide;
- that an approver understood or freely intended the action;
- that an external provider performed the claimed effect exactly once;
- that a registry view is globally current, complete, or non-equivocating; or
- that authority is legally valid in a jurisdiction.

Those exclusions are why the repository should say “no counterexample in the
checked bounds,” not “authority can never increase” without qualification.
