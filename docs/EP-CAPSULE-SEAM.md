<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA ↔ Agent Action Capsule — the who → what seam

A shared, byte-reproducible interop vector that threads **one action's digest**
through the seam between an EMILIA authorization receipt (**WHO** approved) and
Steven Mih's Agent Action Capsule (**WHAT** was done). The linkage is
composed **by digest, not containment**: the Capsule commits to the approval
without restating it; the approval evidence lives in the EMILIA receipt.

- Generator + verifier: [`examples/scitt/capsule-seam-vector.mjs`](../examples/scitt/capsule-seam-vector.mjs) — `node examples/scitt/capsule-seam-vector.mjs`
- Frozen vector: [`examples/scitt/capsule-seam-vector.json`](../examples/scitt/capsule-seam-vector.json)
- EP receipt as a SCITT Signed Statement: [`EP-RECEIPT-SCITT-PROFILE.md`](./EP-RECEIPT-SCITT-PROFILE.md)

## The chain
`permit / agentroa (CAN)` → **EMILIA receipt (WHO approved)** → `Capsule (WHAT was done)` → `GAR (audit log)` — complementary SCITT statement profiles over one transparency service, each independently verifiable, composed by shared digest.

## Two digests — keep them distinct
Everything is **RFC 8785 (JCS)** canonical + **SHA-256**, so both are recomputable in any language.

1. **`subject_digest` — the exact action both statements are ABOUT.**
   `subject_digest = SHA-256( JCS(action) )`.
   The Capsule's subject and the EMILIA receipt's claim are over the **same** action; matching this digest proves both refer to the same operation.

2. **`authority_reference_digest` — the WHO evidence the Capsule points at.**
   The Capsule embeds this in its **opaque authority reference** to commit to the approval:
   - `receipt_payload_digest = SHA-256( JCS(receipt.payload) )` — offline composition.
   - `statement_digest = SHA-256( COSE_Sign1 bytes )` — when the receipt is registered as a SCITT Signed Statement (recommended in a transparency deployment).

   Pin **one** of these per deployment so both implementations bind identical bytes. The vector supplies both.

## Verdict-complete (the case auditors care about)
A **denied / absent** human approval is itself a signed EP event. The vector ships an `approved` and a `denied` receipt; a Capsule can commit to a denied receipt's digest exactly as it commits to an approved one, so the who → what linkage holds for refusals too.

## What the vector gives the Capsule side
From `capsule-seam-vector.json`:
- `issuer.spki_der_b64` + `issuer.kid_hex` — verify the EP Ed25519 signature offline.
- `action` + `subject_digest` — the shared subject.
- `approved` / `denied`: `payload_canonical` (exact JCS bytes), `native_signature_b64`, `cose_sign1_b64`, `receipt_payload_digest`, `statement_digest`.

**Capsule-side test:** build a Capsule over the same `subject_digest`, put the chosen `authority_reference_digest` in the opaque authority reference, and confirm a verifier can (a) recompute `subject_digest` from the action, (b) resolve the authority reference to this EP receipt, and (c) verify the EP signature over `payload_canonical`. That closes who → what **testably**, not by assertion.

## Negative cases (MUST-reject) — the WHO-leg contract
Per Songbo Bu: a decomposition is only an interop surface if each leg ships its own verifier contract *and negative cases*. The vector's `must_reject` array carries the WHO-leg rejects a composed verifier MUST enforce (all `ENFORCED` by the generator):

| id | verdict | reason |
|---|---|---|
| `wrong_action` | reject | `who_subject_mismatch` — receipt binds action A; Capsule records action B |
| `approval_contradiction` | reject | `disposition_contradicts_receipt` — Capsule says approved, referenced receipt is a denial |
| `untrusted_issuer` | reject | `issuer_not_pinned` — receipt signed by a non-pinned key (no trust laundering) |
| `replay_across_subject` | reject | `receipt_action_bound` — an action-A receipt reused for a Capsule over action B |
| `missing_who_when_required` | policy_reject | `who_required_but_absent` — policy requires WHO, chain has no resolvable receipt digest |

These are the WHO analogues of Songbo's negative list (producer-log mismatch, permit/audience mismatch, superseded-without-predecessor, concealed-required-field), composed by cross-reference, not containment.

## Three questions "authorization" blurs
Agent identity/discovery ("which agent, where") ≠ machine/scope permission (permit/agentroa, **CAN**) ≠ accountable-human approval of the exact action (**EMILIA, WHO**). This seam is only the WHO → WHAT edge.

## Notes
- The vector's issuer key is derived from a **fixed seed** for reproducibility — a demo/interop key, **not** a production issuer.
- Standards context: SCITT (COSE_Sign1 Signed Statements, SCRAPI), RFC 8785 (JCS), RFC 9162 / RFC 6962 (transparency).
