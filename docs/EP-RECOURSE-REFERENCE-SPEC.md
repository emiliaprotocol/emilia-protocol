<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RECOURSE-REFERENCE — who stands behind an authorized agent action

> Agents don't just need permission. They need someone to be on the hook. The
> Recourse Reference is the signed, offline-verifiable answer to *"who pays if
> this exact action causes loss, and under what terms."*

**What EMILIA does:** proves the reference — that a named responsible party
committed to specific terms and bound that commitment, by digest, to a **genuine
authorization** for **this exact action**.

**What EMILIA does NOT do:** bear the loss, adjudicate whether a loss is covered,
verify solvency, move funds, or make any legal determination. This is
**claim-not-guarantee, evidence-not-adjudication.** EMILIA is the instrument the
risk-bearer requires — not the balance sheet.

That boundary is the whole strategy. A pure-standards layer captures little value;
*being* the risk network means becoming a licensed, capitalized surety, which EP
is not and should not be. The defensible, capital-light position is the middle:
**the evidence-and-adjudication rail that makes agent-action recourse
underwritable at all.** An insurer cannot price agent risk today because there is
no verifiable artifact to underwrite against — they price blind and deny claims.
The EMILIA receipt + evidence chain + execution binding is what turns an agent
loss into a provable, in-scope-checkable event. The Recourse Reference is the
socket that lets the insurer / surety / employer / facilitator plug their balance
sheet into that proof.

- Schema: [`public/schemas/ep-recourse-reference.schema.json`](../public/schemas/ep-recourse-reference.schema.json)
- Runnable vector + verifier: [`examples/recourse/recourse-reference-vector.mjs`](../examples/recourse/recourse-reference-vector.mjs) (`node examples/recourse/recourse-reference-vector.mjs`) · frozen [`.json`](../examples/recourse/recourse-reference-vector.json) · CI: `tests/recourse-reference.test.ts`
- Extends the advisory `named-owner liability` block in [`lib/provenance/chain.js`](../lib/provenance/chain.js) into full, verifiable terms.

## The high-risk request, completed

```
Authorization: yes        (this exact action was allowed)
Identity:      yes        (which workload/agent acted — WIMSE/OAuth)
Receipt:       yes        (a named human authorized it — EMILIA apex)
Recourse:      <signed reference to who is on the hook, terms, and status URL>
```

A gateway fronting a consequential action checks the Recourse Reference before
allowing it. EMILIA verifies the reference; the *named party* bears the loss.

## The object (EP-RECOURSE-REFERENCE-v1)

RFC 8785 (JCS) canonical, SHA-256, Ed25519 — the frozen EP primitives, no new
cryptography.

| field | meaning |
|---|---|
| `subject_digest` | SHA-256(JCS(action)) — the exact action this recourse is FOR (same join key as the receipt and the capsule seam) |
| `authorization.receipt_payload_digest` | binds the reference to a **genuine** authorization — recourse cannot ride a bare claim or a forged approval |
| `responsible_party` | `{entity, legal_name, role}` — role ∈ self / employer / third_party; EMILIA proves this party **signed**, not that it is solvent |
| `coverage` | `action_class` (urn:ep:action:…), `limit {amount, currency}`, `exclusions_digest` (EMILIA binds the exclusions by hash; it never interprets them), `window {not_before, not_after}` |
| `dispute_endpoint` / `settlement_instruction` | opaque to EMILIA — where a claimant files, how settlement occurs (EMILIA never moves funds) |
| `evidence_requirements` | the artifacts a claim must present (EP-RECEIPT-v1, execution attestation) — the reason the action is underwritable |
| `status_url` | revocation/status — offline proves the signed *terms*; whether the recourse is *live* is server-state, checked here (same authenticity-vs-currency split as receipt revocation) |
| `signature` / `issuer_key` | Ed25519 over the canonical body, by the responsible party's key |

## Verification — verified vs accepted

Same discipline as federation. A reference **verifies** when its signature and
bindings hold; it is **accepted** only when the relying party has **pinned** the
responsible-party issuer out-of-band and the action falls in the coverage window.
A self-asserted recourse reference verifies but is never accepted unpinned — no
one gets to declare their own recourse.

**Fail-closed MUST-reject cases** (all enforced in the vector):

| id | outcome |
|---|---|
| `tampered_terms` | raising the coverage limit after signing breaks the signature |
| `wrong_action` | a reference for action A is refused against action B (`subject_binding`) |
| `authorization_mismatch` | a reference that doesn't bind the presented receipt is refused |
| `expired_window` | an action outside the coverage window is not accepted (terms verify, coverage isn't live) |
| `untrusted_issuer` | a non-pinned responsible party verifies but is never accepted |

## Composition

The Recourse Reference is a profile over the authorization receipt, composed **by
digest, not containment** — like the evidence chain (EP-AEC) and the capsule seam.
It references the receipt's `receipt_payload_digest` and the action's
`subject_digest`; it embeds neither. It slots into the four-leg SCITT picture as a
fifth, optional leg carried alongside the WHO receipt: *permit (CAN) → EMILIA
(WHO) → Capsule (WHAT) → GAR (audit) → recourse (WHO'S ON THE HOOK)*.

## Honest boundary (what a claimant still needs beyond EMILIA)

EMILIA makes the commitment and its binding **verifiable**. It does not make the
responsible party **solvent**, does not decide whether the loss falls inside the
`exclusions_digest` document, and does not enforce payment. Those are the
responsible party's and the dispute process's. EMILIA's contribution — and it is
the load-bearing one — is that none of that adjudication can even begin without a
verifiable, action-bound, authorization-backed artifact, and that is exactly what
this is.

## Commercial shape (why this is the business, not just a schema)

The Recourse Reference is what an insurer/surety/facilitator issues and prices
against. The revenue is theirs (premiums, bps, dispute fees); EMILIA's revenue is
the **operated rail** — issuing/verifying references, retaining the evidence a
claim needs, and the status/revocation service — plus being the artifact a
carrier's product is built on. The go-to-market is not "sell verification"; it is
**land one underwriter who will price real coverage against EMILIA receipts.**
That reliance event is the wedge (see the underwriter design-partner brief).
