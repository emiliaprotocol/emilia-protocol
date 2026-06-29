# Assurance-Tier Enforcement at Consume (design note)

**Status:** IMPLEMENTED and **default ON (fail-closed)** — see `lib/guard-tier.js`,
the consume route's dual gate, and `tests/guard-tier.test.js`. A receipt the policy
labeled `dual` now requires two distinct Class-A approvers to consume by default;
set `EP_TIER_QUORUM_ENFORCE=false` to explicitly opt out (permissive dev/demo).
Scopes two requests into one mechanism: (1) value-tier → enforced quorum,
(2) revocation-at-execution. Before flipping an already-live deployment, operators
should audit in-flight `dual` receipts and either complete them under the old
policy or require the second Class-A approval before consume.

## What already exists (do NOT rebuild)
- **Value tiers** (`lib/guard-policies.js`): payment release ≥ $50k → `single`,
  ≥ $1M → `dual`. Score-independent (`evaluateGuardPolicy` takes no trust score;
  locked by `tests/guard-policies.test.js`).
- **Revocation-at-execution** (`consume/route.js`, single-signoff branch): the
  approver's authority is resolved via `resolveGuardAuthority(...)`, which checks
  **in-org, in-role, in-window, not revoked, sufficient assurance** at consume
  time. So "live revocation above tier" is *already* enforced for the approving
  authority. (Kartheik's CRL/OCSP point: freshness bounds staleness; this is the
  liveness check.)
- **Named multi-party quorum** (EP-QUORUM-v1): `quorumGate` enforces a SATISFIED
  quorum (distinct humans, roles, order, window, signatures) when the receipt
  carries a `quorum_policy`. This is caller-supplied with a named approver roster.

## The gap (the only thing to wire)
`signoff_tier: 'dual'` (≥ $1M) with **no** caller `quorum_policy` routes into the
single-signoff branch, which requires exactly **one** `guard.signoff.approved`.
A $1M "dual authorization" receipt is therefore *labeled* dual but enforced as
single. EP-QUORUM-v1 can't be auto-derived for it — it needs a named roster the
caller didn't supply. So dual must be enforced as a **count-based** rule, not a
named quorum.

## The mechanism (count-based dual at consume)
In `consume/route.js`, single-signoff branch, gate behind `EP_TIER_QUORUM_ENFORCE`
(default **off** → zero prod behavior change until reviewed + flipped):

1. Read `tier = base.signoff_tier` and `required = tier === 'dual' ? 2 : 1`.
2. Gather **all** `guard.signoff.approved` decisions bound to this receipt
   (`boundSignoffDecisionEvents(...)`), not just the first.
3. Keep only decisions that are:
   - **Class-A** (`after_state.key_class === 'A'`) when `required_assurance === 'A'`;
   - from an approver **≠ the initiator** (self-approval guard);
   - backed by a **valid, not-revoked authority** (`resolveGuardAuthority` per
     approver — reuse the existing check, which already does revocation).
4. Require **≥ `required` DISTINCT approver_ids** passing (3). Else
   `403 dual_authorization_required` (or `insufficient_assurance`).
5. Single tier (`required === 1`) is unchanged — backward compatible.

This makes the value tier *structurally* require N distinct, individually-authorized,
not-revoked Class-A humans before a high-value action consumes — the economic
defense from the adversarial-economics model, enforced at the gate.

## Revocation-at-execution: formalize the tier rule
Already enforced per-approver via `resolveGuardAuthority`. The only addition is to
state it as policy: **for `tier ∈ {single, dual}` (or amount ≥ threshold),
not-revoked-at-consume is REQUIRED** (it already is). Optionally extend the same
not-revoked check to a bound **initiator/L4 authority** if one is present on the
receipt, closing Kartheik's "L4 credential revoked inside the freshness window"
case at the execution gate (not just the approver side).

## Tests (must accompany the implementation)
- A `dual` ($1M) receipt with **one** Class-A approval → `403` (cannot consume).
- Same receipt with **two distinct** Class-A approvals (neither the initiator,
  both valid authority) → consumes.
- Two approvals from the **same** human → still `403` (distinct required).
- A `single` ($50k) receipt with one approval → consumes (unchanged).
- An approval whose authority is **revoked** at consume → refused (regression-guard
  the existing behavior).
- Flag **off** → behavior identical to today (safety net).

## Rollout
DONE: default-off → default-on (fail-closed). The consume test matrix is green.
A deployment that needs the old permissive behavior sets `EP_TIER_QUORUM_ENFORCE=false`
explicitly after a conscious risk decision. Before flipping an existing production
environment, audit in-flight `dual` receipts for compatibility. The third-party
pentest (RFP staged) should exercise the now-default path. No migration required;
`signoff_tier` is already persisted in the receipt's `after_state`.
