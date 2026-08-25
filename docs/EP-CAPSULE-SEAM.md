<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA ↔ Agent Action Capsule — the who → what seam

## Runnable CAID → AEC → AEB → Capsule profile

The original seam below proves the byte binding between WHO and WHAT. The
candidate composition profile now executes the larger consequence path:

- [runner](../examples/composition/caid-aec-aeb-capsule-v1/run.mjs)
- [frozen bundle](../examples/composition/caid-aec-aeb-capsule-v1/bundle.json)
- [EMILIA run report](../examples/composition/caid-aec-aeb-capsule-v1/report.emilia-js.json)
- [independent report template](../examples/composition/caid-aec-aeb-capsule-v1/external-report.template.json)

It preserves the Capsule's native result, recomputes CAID, evaluates AEC,
runs AEB admission and consequence handling, and emits separate action,
principal, sufficiency, decision, admission, and outcome axes. Eight cases
cover the positive path, splice, stale evidence, consumed replay, both timeout
sides of dispatch, observer contradiction, and a verifier-level structured
refusal. The vector remains a candidate until a second independent
implementation reproduces the frozen bytes.

The profile is exercised inside the broader
[cross-slot Composition conformance mechanism](./COMPOSITION-CONFORMANCE-MECHANISM.md),
which supplies one four-slot positive vector and thirteen paired
negative/condition-removed controls without absorbing native slot
conformance.

A shared, byte-reproducible interop vector that threads **one action's digest**
through the seam between an EMILIA authorization receipt (**WHO** approved) and
Steven Mih's Agent Action Capsule (**WHAT** was done). The linkage is
composed **by digest, not containment**: the Capsule commits to the approval
without restating it; the approval evidence lives in the EMILIA receipt.

- Current generator + verifier: [`examples/scitt/capsule-seam-vector-v2.mjs`](../examples/scitt/capsule-seam-vector-v2.mjs) — `npm run conformance:composition:scitt-capsule-seam`
- Current frozen vector: [`examples/scitt/capsule-seam-vector-v2.json`](../examples/scitt/capsule-seam-vector-v2.json)
- Immutable legacy v1: [`examples/scitt/capsule-seam-vector.json`](../examples/scitt/capsule-seam-vector.json). Its hand-built COSE envelope predates `EP-SCITT-STATEMENT-v1`, uses the legacy media type, omits protected CWT Claims, and is retained byte-for-byte for compatibility only. It is not profile-valid SCITT evidence.
- EP receipt as a SCITT Signed Statement: [`EP-RECEIPT-SCITT-PROFILE.md`](./EP-RECEIPT-SCITT-PROFILE.md)

## The chain
`permit / agentroa (CAN)` → **EMILIA receipt (WHO approved)** → `Capsule (WHAT was done)` → `GAR (audit log)` — complementary SCITT statement profiles over one transparency service, each independently verifiable, composed by shared digest.

## Three digests — one binding, pinned per profile
Everything is **RFC 8785 (JCS)** canonical + **SHA-256**, so all are recomputable in any language. Per Songbo Bu's byte-binding review (SCITT list, 2026-07-02), the WHO seam carries **three** distinct digests, and the authority-reference binding is **pinned per deployment profile** — never left ambiguous:

1. **`subject_digest` — the exact action both statements are ABOUT.**
   `subject_digest = SHA-256( JCS(action) )`.
   The Capsule's subject and the EMILIA receipt's claim are over the **same** action; matching this digest proves both refer to the same operation.

2. **`authority_reference_digest` identifies the WHO evidence the Capsule (and GAR's HEM_APPROVE ALE) commits to** in its **opaque authority reference**, composing by digest not containment:
   - `authority_reference_digest = SHA-256(JCS(receipt.payload))`, named `authorization_payload_digest` in v2.
   - A transparency-enabled profile MAY also carry `statement_entry_digest = SHA-256(exact COSE_Sign1 bytes)` as a locator for the exact logged envelope.

   These fields have different jobs. The entry locator never substitutes for
   the authorization reference. The relying party resolves the receipt,
   verifies its issuer and signature, recomputes the authorization digest, and
   separately verifies any SCITT inclusion evidence. The
   [`EP-SCITT-STATEMENT-IDENTITY-v0.1`](../conformance/composition/scitt-statement-identity-v0.1/README.md)
   profile proves why this separation is necessary.

3. **`signing_input_digest` and `statement_entry_digest` remain statement identities, not authority.**
   `signing_input_digest` names the RFC 9052 `Sig_structure`;
   `statement_entry_digest` names the exact tagged `COSE_Sign1` bytes. V2 also
   carries `statement_payload_digest` for the complete canonical receipt
   document. None can substitute for the verified
   `authorization_payload_digest` over the inner receipt payload.

## Verdict-complete (the case auditors care about)
A **denied / absent** human approval is itself a signed EP event. The vector ships an `approved` and a `denied` receipt; a Capsule can commit to a denied receipt's digest exactly as it commits to an approved one, so the who → what linkage holds for refusals too.

## What the vector gives the Capsule side
From `capsule-seam-vector-v2.json`:
- separate pinned statement-issuer and receipt-issuer SPKI keys plus the protected `kid`;
- a versioned `payment.release.1` action, its CAID, and a `sha256:`-prefixed subject digest;
- approved and denied complete `EP-RECEIPT-v1` documents, profile-valid `COSE_Sign1` bytes, verifier checks, and separately named authorization-payload, signing-input, statement-payload, and exact-entry digests.

**Capsule-side test:** build a Capsule over the same `subject_digest`, put the chosen `authority_reference_digest` in the opaque authority reference, and confirm a verifier can (a) recompute `subject_digest` from the action, (b) resolve the authority reference to this EP receipt, and (c) verify the EP signature over `payload_canonical`. That closes who → what **testably**, not by assertion.

## Negative cases (MUST-reject) — the WHO-leg contract
Per Songbo Bu: a decomposition is only an interop surface if each leg ships its own verifier contract *and negative cases*. The vector's `must_reject` array carries the WHO-leg rejects a composed verifier MUST enforce (all `ENFORCED` by the generator):

| id | verdict | reason |
|---|---|---|
| `wrong_action` | reject | `who_subject_mismatch` — receipt binds action A; Capsule records action B |
| `approval_contradiction` | reject | `disposition_contradicts_receipt` — Capsule says approved, referenced receipt is a denial |
| `untrusted_receipt_issuer` | reject | `receipt_invalid` — the statement leg is valid but the carried receipt fails under the pinned receipt-issuer key |
| `replay_across_subject` | reject | `receipt_action_bound` — an action-A receipt reused for a Capsule over action B |
| `missing_who_when_required` | policy_reject | `who_required_but_absent` — policy requires WHO, chain has no resolvable receipt digest |

These are the WHO analogues of Songbo's negative list (producer-log mismatch, permit/audience mismatch, superseded-without-predecessor, concealed-required-field), composed by cross-reference, not containment.

## Three questions "authorization" blurs
Agent identity/discovery ("which agent, where") ≠ machine/scope permission (permit/agentroa, **CAN**) ≠ accountable-human approval of the exact action (**EMILIA, WHO**). This seam is only the WHO → WHAT edge.

## Notes
- The vector's issuer key is derived from a **fixed seed** for reproducibility — a demo/interop key, **not** a production issuer.
- Standards context: SCITT (COSE_Sign1 Signed Statements, SCRAPI), RFC 8785 (JCS), RFC 9162 / RFC 6962 (transparency).
