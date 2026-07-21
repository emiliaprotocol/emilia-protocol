<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RECOURSE-REFERENCE — who stands behind an authorized agent action

**Status:** repository reference specification; not a deployment,
standardization, coverage, or legal-enforceability claim

> Agents do not just need permission. A relying party may also require signed
> evidence that a named party made a stated recourse commitment for this exact
> action. The Recourse Reference makes that commitment and its terms
> offline-verifiable; it does not decide who legally must pay.

**What EMILIA does:** verifies the reference — that a named responsible party
signed specific terms and bound that commitment, by digest, to an authorization
receipt accepted under the relying party's pinned profile for **this exact
action**.

**What EMILIA does NOT do:** bear the loss, adjudicate whether a loss is covered,
verify solvency, move funds, decide a dispute, or make any legal determination.
This is
**claim-not-guarantee, evidence-not-adjudication.** EMILIA is the instrument the
risk-bearer requires — not the balance sheet.

That boundary is the whole strategy. A pure-standards layer captures little value;
*being* the risk network means becoming a licensed, capitalized surety, which EP
is not and should not be. The defensible, capital-light position is the middle:
**the evidence-and-commitment rail that can make agent-action recourse easier to
underwrite.** The EMILIA receipt, evidence chain, and execution binding can make
an action and its stated recourse terms verifiable under a pinned profile. The
Recourse Reference is the socket through which an insurer, surety, employer, or
facilitator can bind its own commitment to that evidence. Whether the evidence
is sufficient for underwriting, coverage, liability, or payment remains that
party's decision under external terms and law.

- Schema: [`public/schemas/ep-recourse-reference.schema.json`](../public/schemas/ep-recourse-reference.schema.json)
- Runnable vector + verifier: [`examples/recourse/recourse-reference-vector.mjs`](../examples/recourse/recourse-reference-vector.mjs) (`node examples/recourse/recourse-reference-vector.mjs`) · frozen [`.json`](../examples/recourse/recourse-reference-vector.json) · CI: `tests/recourse-reference.test.ts`
- Extends the advisory `named-owner liability` block in [`lib/provenance/chain.js`](../lib/provenance/chain.js) into full, verifiable terms.

## The high-risk request, technically gated

```
Authorization: accepted under the relying party's pinned profile
Workload:      identifier evidence verified under its pinned profile
Receipt:       exact-action approval evidence verified under its pinned profile
Recourse:      signed commitment reference accepted under its pinned profile
```

A gateway fronting a consequential action can require an accepted Recourse
Reference before allowing its configured path to advance. EMILIA verifies and
technically gates on the reference; the named party's actual legal obligation,
coverage decision, and payment remain external.

## The object (EP-RECOURSE-REFERENCE-v1)

RFC 8785 (JCS) canonical, SHA-256, Ed25519 — the frozen EP primitives, no new
cryptography.

| field | meaning |
|---|---|
| `subject_digest` | SHA-256(JCS(action)) — the exact action this recourse is FOR (same join key as the receipt and the capsule seam) |
| `authorization.receipt_payload_digest` | binds the reference to an authorization receipt that the relying party must independently accept under its pinned profile — recourse cannot ride a bare claim or a forged approval |
| `responsible_party` | `{entity, legal_name, role}` — role ∈ self / employer / third_party; EMILIA verifies the signature under the pinned key, not civil identity, solvency, or legal capacity |
| `coverage` | `action_class` (urn:ep:action:…), `limit {amount, currency}`, `exclusions_digest` (EMILIA binds the exclusions by hash; it never interprets them), `window {not_before, not_after}` |
| `dispute_endpoint` / `settlement_instruction` | opaque routing and instruction data — where a claimant may file and how an external settlement may occur; EMILIA neither adjudicates nor moves funds |
| `evidence_requirements` | the artifacts a claim must present (EP-RECEIPT-v1, execution attestation) — the reason the action is underwritable |
| `status_url` | revocation/status — offline verification covers the signed *terms*; whether the recourse is *live* is server-state, checked here (same authenticity-vs-currency split as receipt revocation) |
| `signature` / `issuer_key` | Ed25519 over the canonical body, by the responsible party's key |

## Verification — verified vs accepted

Same discipline as federation. A reference **verifies** when its signature and
bindings hold; it is **accepted** only when the relying party has **pinned** the
responsible-party issuer out-of-band and the action falls in the coverage window.
A self-asserted recourse reference verifies but is never accepted unpinned — no
one gets to declare their own recourse.

Acceptance is a technical reliance decision under the pinned profile. It does
not establish that the commitment is legally enforceable, that a future claim
is covered, or that a decision-maker will order or make payment.

**Fail-closed MUST-reject cases** (all enforced in the vector):

| id | outcome |
|---|---|
| `tampered_terms` | raising the coverage limit after signing breaks the signature |
| `wrong_action` | a reference for action A is refused against action B (`subject_binding`) |
| `authorization_mismatch` | a reference that doesn't bind the presented receipt is refused |
| `expired_window` | an action outside the coverage window is not accepted (terms verify, coverage isn't live) |
| `untrusted_issuer` | a non-pinned responsible party verifies but is never accepted |

Revocation or expiry observed before Gate issues the protected effect claim can
make the reference unacceptable and prevent that technical path from advancing.
Revocation learned after claim or execution is late: it changes future reliance
and may become evidence in a dispute, but it does not erase the signed reference
or reverse the original external effect.

## Composition

The Recourse Reference is a profile over the authorization receipt, composed **by
digest, not containment** — like the evidence chain (EP-AEC) and the capsule seam.
It references the receipt's `receipt_payload_digest` and the action's
`subject_digest`; it embeds neither. It slots into the four-leg SCITT picture as a
fifth, optional leg carried alongside the WHO receipt: *permit (CAN) → EMILIA
(WHO) → Capsule (WHAT) → GAR (audit) → recourse (WHO'S ON THE HOOK)*.

The Recourse Reference does not own the effect claim. Gate is the policy and
enforcement controller; Receipt Program or Action Escrow is the selected
downstream effect-claim owner. A claim token between Gate and that owner is a
bearer capability and is not recourse evidence. See
[Lifecycle and Remedy Kernel](./architecture/LIFECYCLE-REMEDY-KERNEL.md).

## Honest boundary (what a claimant still needs beyond EMILIA)

EMILIA makes the commitment and its binding **verifiable**. It does not make the
responsible party **solvent**, does not decide whether the loss falls inside the
`exclusions_digest` document, and does not enforce payment. Those are the
responsible party's and the external dispute process's. A dispute filing and a
decision are separate artifacts: the filing records a bounded challenge; the
decision records what an authorized external decision-maker concluded. EMILIA
may verify their signatures and bindings under a pinned profile, but it does not
render the decision.

A comparison verdict is not an execution outcome. An overturned receipt
assessment means only that a later assessment superseded an earlier assessment;
it does not rewrite the receipt, reverse an external effect, or itself authorize
a remedy. Every remedy remains a fresh compensating action with its own
authorization, operation, effect owner, outcome evidence, and legal analysis.

## Commercial shape (why this is the business, not just a schema)

The Recourse Reference is what an insurer/surety/facilitator can issue and price
against. The revenue is theirs (premiums, bps, dispute fees); EMILIA's revenue is
the **operated rail** — issuing/verifying references, retaining the evidence a
claim needs, and the status/revocation service — plus being the artifact a
carrier's product can be built on. The go-to-market is not "sell verification";
it is **land one underwriter willing to evaluate coverage against EMILIA-bound
evidence.** That reliance event is the wedge (see the underwriter design-partner
brief), but this repository does not claim that such coverage is deployed,
approved, standardized, or legally enforceable.
