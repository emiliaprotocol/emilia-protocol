# Finance Operations Protected-Workflow Pilot

**Current offer:** $25,000 · 90 days · one buyer-selected workflow

## The workflow

Choose one consequential finance action:

- a vendor bank-detail change, **or**
- a payment release.

EMILIA Gate places a customer-owned authority check immediately before the
executor or system of record. The customer defines the operating mandate,
required evidence, trust roots, expiry, and exception path. The safety rule is
simple: **no accepted exact-action authority and required evidence, no provider
entry.**

A standing mandate may authorize unattended work inside its limits. Fresh human
approval is required only when the customer requires it or when the requested
action falls outside the mandate.

## Observe first

The pilot starts with synthetic data and read-only validation. Together, we:

1. map the real approval path, executor boundary, credentials, and bypasses;
2. define the material fields for the selected action and the customer's
   authority and evidence requirements;
3. run synthetic and read-only cases in observe mode, including missing, stale,
   invalid, mismatched, and replayed authority; and
4. compare Gate's decisions with the buyer's current process and agree on
   acceptance criteria.

No production path changes until the buyer accepts the Gate boundary, operating
rules, exception path, and complete-mediation design. If accepted, the remaining
pilot work can bind Gate to the covered production workflow only after every
route to the selected action is mediated. If not, the pilot ends with the mapped
boundary, test results, and recommended next decision.

## What the buyer receives

- one action contract for the selected vendor change or payment release;
- a boundary map naming the protected path and every known bypass;
- customer-owned mandate, evidence, expiry, and exception rules;
- synthetic and read-only decision results, including refusal cases;
- a portable evidence packet for the admission decision and any authenticated
  uncertainty; and
- a production acceptance plan, or a documented no-go decision.

The packet can be cryptographically re-verified under customer-pinned keys
without an EMILIA callback. That verifies the packet's integrity and the scoped
decision. It does not establish source truth or prove what the payment provider
did.

## Production claim boundary

On a completely mediated covered path, missing, stale, exhausted, invalid, or
mismatched authority does not admit provider entry. Gate reserves accepted
authority before entry, refuses replay, and records admission separately from
provider and effect evidence. If entry occurred but the provider outcome cannot
be established, the operation remains `INDETERMINATE`; Gate does not infer
success or permit a blind retry.

The pilot does **not**:

- prove that bank details or payee identity are correct;
- promise fraud prevention or cover an unmediated path;
- produce a SOX-ready or SOX-grade conclusion, audit opinion, or certification;
- prove provider success, settlement, or exact physical execution; or
- take custody of or move money.

## Acceptance decision

At day 90, the buyer decides whether the tested boundary and evidence are fit for
production. The decision is based on the buyer's workflow, controls, integration
constraints, and observed results, not on a generic security score.

**Request the pilot:** [emiliaprotocol.ai/pilot?v=fin](https://www.emiliaprotocol.ai/pilot?v=fin)
