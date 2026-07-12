<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-AUTHORITY-REGISTRY-v1

**Scoped human authority: from "a human approved" to "the right human had authority for this exact action."**

## The gap this closes

EMILIA already proves a great deal about an approval: a signature proves a key
produced the bytes; a Class-A signoff proves a *named human* was present with a
device-bound ceremony under user verification. None of that proves the human was
**entitled** to approve *this* action, at *this* amount, under *this* policy, at
*that* time. Until now the mint path fabricated that entitlement — it fed the
rules engine a stub authority with `max_amount_usd: Number.MAX_SAFE_INTEGER` and
`scope: [the requested action]`, so the four authority-side hard-deny checks
(amount, scope, revocation, expiry) could never fire.

EP-AUTHORITY-REGISTRY-v1 resolves **real** scoped authority and binds a closed
verdict into the receipt. It completes the chain the rest of the stack leaves
open:

```
identity → ceremony → AUTHORITY → policy → receipt → admissibility
```

## The closed verdict set

The resolver (`lib/authority/resolver.js`, `evaluateAuthorityVerdict`) returns
exactly one of a fixed, closed set. Nothing outside this set is ever returned, so
a relying party can switch on it exhaustively:

| Verdict | Meaning |
|---|---|
| `authorized` | The subject held a valid, in-scope, in-limit, in-window, non-revoked authority for this action under the pinned policy. |
| `unknown_authority` | No authority record exists for this subject in this org. |
| `revoked_authority` | The authority was revoked, or its status is not `active`. |
| `expired_authority` | `valid_to` is before the authorization time. |
| `not_yet_valid` | `valid_from` is after the authorization time. |
| `wrong_role` | A role was required and the record's role does not match. |
| `wrong_scope` | The action_type is not in the authority's `action_scopes`. |
| `amount_exceeded` | The amount is above the ceiling, or is in a currency the ceiling is not denominated in (no FX oracle → fail closed). |
| `policy_mismatch` | The authority is pinned to a policy hash that differs from the action's. |
| `delegation_broken` | A delegated authority widened its parent's organization, scope, ceiling/currency, policy, or assurance; an ancestor is missing/revoked/out-of-window/malformed; or the chain cycles or is too deep. |
| `insufficient_assurance` | The record's assurance class is below the required class. |
| `registry_unavailable` | The registry could not be read, or is staler than the relying party's pinned minimum epoch. |

**The non-negotiable invariant.** A non-`authorized` verdict never becomes
"unknown but allow." Under enforcement it yields `not_admissible`; an unresolved
authority (registry unavailable / no record) carries the umbrella code
`authority_unresolved`.

## Registry data model

The `authorities` table (migrations 033/102/118/119, extended by **131**) is the
substrate. 131 adds the scope/limit/delegation/policy columns:

| Column | Role |
|---|---|
| `subject_type`, `subject_ref`, `organization_id` | who the grant is for, in which org |
| `role` | the role the grant confers |
| `assurance_class` | highest assurance the subject may act at. Stored values are the legacy letters `A`/`B`/`C` (ordered `C` < `B` < `A`), predating the Class S/H/V/Q taxonomy of draft-schrock-ep-assurance-classes: stored `A` = Class V, `B` = Class H, `C` = Class S. These are stored registry values, not the key-custody classes of receipts-06 Section 5.1; migration to the new letters is planned (docs/ASSURANCE-LETTER-MIGRATION.md) |
| `status`, `valid_from`, `valid_to`, `revoked_at` | lifecycle and window |
| `action_scopes TEXT[]` | action_type values this grant covers; NULL = unscoped |
| `max_amount_usd NUMERIC` | amount ceiling in `currency`; NULL = unbounded |
| `currency TEXT` | denomination of the ceiling (default `USD`) |
| `delegation_parent TEXT` | the authority this one narrows; constrained dimensions are inherited, so omission cannot reopen them |
| `policy_hash TEXT` | when set, pins the grant to a specific policy |

## Registry epoch and head

Each org's registry has a monotonic `epoch` (a counter bumped by trigger on any
`authorities` change) and a `head` — a `sha256` commitment over the org's grant
set at that epoch (`lib/authority/registry-head.js`, order-independent). Both are
bound into every receipt as `authority_registry_epoch` / `authority_registry_head`.
They let an offline relying party:

- **refuse a stale registry** — "I will not rely on an epoch older than N"; and
- **detect equivocation** — the head it recomputes from the registry snapshot it
  holds must equal the head the receipt committed to.

The epoch counter lives in SQL (trivial trigger); the cryptographic head is
computed in the application layer so its canonicalization is byte-identical to
the verifier and the conformance vectors (RFC 8785 / JCS, `lib/canonical-json.js`).

## Receipt binding

The six binding fields are folded into the canonical action **before** it is
hashed, so they are covered by `action_hash` and, transitively, by every
approver signature over `context_hash`. They cannot be altered after the fact to
pretend a different authority decision was relied on:

```json
{
  "authority_id": "…",
  "authority_verdict": "authorized",
  "authority_result_hash": "sha256:…",
  "authority_registry_head": "sha256:…",
  "authority_registry_epoch": 17,
  "policy_hash": "sha256:…"
}
```

`authority_result_hash` commits to the *request facts* (action, amount, currency,
subject, issued_at) alongside the verdict, so two authorizations that share a
verdict but differ in amount produce different hashes.

## Staged enforcement (server-pinned)

Authority enforcement rolls out on its own axis, resolved from the environment
(`EP_AUTHORITY_ENFORCEMENT`) and **never** from the request body — unlike the
guard enforcement mode, which the caller sets and which can downgrade a block to
observe. Authority must not inherit that hole.

```
shadow  →  warn  →  enforce_critical  →  enforce_default
```

- **shadow** (default) — resolve, bind into the receipt, and log what *would*
  have been denied. Never blocks. Behavior is identical to before the registry
  existed, which is what makes it safe to ship ahead of a fully-populated
  registry.
- **warn** — same, surfaced to the caller as a warning. Never blocks.
- **enforce_critical** — critical actions (money movement, payee change, the
  Class-A set — anything the guard escalates to a named human or signoff) **fail
  closed** on a non-`authorized` verdict. Non-critical actions still only warn.
- **enforce_default** — every action fails closed on a non-`authorized` verdict.

The rollout discipline: advance the mode only after the shadow logs
(`rules-engine.v0.shadow` and `guard.authority.denied` events) show the registry
denies nothing legitimate.

## Portable proof

A verdict alone forces the relying party to trust EP's live database at
verification time. `EP-AUTHORITY-PROOF-v1` (see
[EP-AUTHORITY-PROOF-SPEC.md](EP-AUTHORITY-PROOF-SPEC.md)) is a signed, offline
snapshot of one grant, accepted only against a pinned registry issuer key.

## Verified vs. accepted

Registered in the [Admissibility Invariant Registry](ADMISSIBILITY-INVARIANT-REGISTRY.md)
as `scoped-human-authority-valid-at-authorization`:

- **VERIFIED** = the resolver returns a closed verdict over the registry snapshot
  it was handed, and any proof signature checks out.
- **ACCEPTED** = that snapshot is the org's real registry — the relying party
  pinned the registry issuer key out of band, and the receipt's epoch/head meet
  its freshness pin. A closed verdict against an unpinned or stale registry is
  verified, not accepted.

## Conformance

`conformance/vectors/authority.v1.json` carries a positive case and a reject
case for every failure mode (unknown, revoked, expired, not-yet-valid,
out-of-scope, wrong-role, over-limit, currency-mismatch, policy-mismatch,
delegation-broken, unavailable, stale, plus proof unpinned/tampered/head-
mismatch/stale/forged-key-id). Driven by `tests/authority-registry.test.js`. The
authority-claim guard (`scripts/check-authority-claims.mjs`, CI) fails the build
if any public surface claims enforced/scoped authority without this registry
entry and these passing vectors.
