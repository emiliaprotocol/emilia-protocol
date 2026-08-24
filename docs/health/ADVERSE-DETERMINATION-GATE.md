<!-- SPDX-License-Identifier: Apache-2.0 -->
# Adverse determination gate

**Status:** Candidate, PHI-free reference profile

**Runnable demo:** `examples/adverse-determination.mjs` (`FAST=1` skips the pauses)

**Binding:** `lib/health/davinci-pas-binding.ts`

**Profile:** `profiles/health/davinci-pas-review-binding.v1.json`

**Reliance rule:** `public/schemas/reliance-profiles/cms-prior-auth.v1.json`

**Action type:** `health.medical-prior-authorization-review.1`

This shows how a payer can require exact-action, named-licensed-reviewer
authorization evidence before an adverse medical-necessity determination is
issued, and can hand a third party a packet that proves it. It is a reference
composition of existing EMILIA primitives. It is not legal advice, not a
compliance determination, and not a DHCS, CMS, California, HL7, Da Vinci, or
NCPDP standard or endorsement. Running the demo makes no one compliant.

## 1. What the law requires

California SB 1120 is in force. In this repository's own words, carried in
`profiles/health/davinci-pas-review-binding.v1.json`:

> SB 1120 makes licensed-professional review of adverse medical-necessity
> decisions an auditable operational event; it does not mandate EMILIA, CAIDs,
> signatures, or cryptographic receipts.

The same profile records the federal analogue:

> CMS WISeR requires appropriately licensed human clinical review for
> non-affirmations, creating an auditable licensed-review event; it does not
> mandate EMILIA, CAIDs, signatures, or cryptographic receipts.

Texas SB 815 and the NAIC model bulletin on insurer use of AI are moving in the
same direction. Read them yourself; this document does not paraphrase their
operative text and nothing here is a reading of any statute.

The common shape is what matters commercially. Licensed human review of an
adverse determination becomes an operational event that someone will later ask
you to evidence, in an appeal, an audit, an exam, or discovery.

## 2. The failure mode

Today that evidence is a row in the payer's own database.

```
determinations
  id                 88431
  outcome            denied
  reviewed_by        dr_smith
  reviewed_at        2026-07-21 18:34:12
  criteria_version   4.2
```

Every field there is mutable by the party with the most to lose from its
contents. The row does not establish that Dr. Smith saw this member's record
rather than a queue summary, that the rationale in the row is the rationale that
existed at signing time, that the criteria version cited is the criteria text
that was applied, or that the reviewer was licensed and authorized to issue an
adverse decision for this service on that date. It also cannot be checked by
anyone outside the database.

That gap is exactly what the nH Predict litigation went after: plaintiffs
alleged an algorithm drove the determinations while the human-review record was
nominal. Whatever the merits, the discovery posture is the lesson. A defendant
whose only artifact is its own editable table is arguing about its own
recordkeeping instead of about the medicine.

## 3. What the receipt proves instead

The determination is projected into a portable object whose identifier is a
content-addressed CAID over the material fields, and the licensed reviewer's
device-bound signature runs down a digest chain that terminates at that object.
Concretely, a third party holding only the packet can establish:

- **Which member reference.** A pairwise pseudonymous reference, never a direct
  patient identifier. The portable object carries digests only. In the demo the
  object is searched at runtime for the patient reference, the claim identifier,
  the procedure code, the diagnosis code, the clinical note and the rationale
  text, and none of them are present.
- **Which service and which criteria.** The service line, diagnosis and
  supporting information are covered by `service_request_digest`. The criteria
  document is covered by `policy_digest`, which is recomputable from the
  criteria text itself, so "criteria version 4.2" stops being a label and starts
  being a hash.
- **Which rationale.** The denial rationale lives inside the FHIR
  `ClaimResponse.item.adjudication`, which is covered by `decision_digest` and
  therefore by the CAID. Softening the rationale after the fact changes the
  determination's identifier. The demo edits it and the verifier refuses with
  `claim_response_digest_mismatch` and `action_projection_mismatch`.
- **Which reviewer.** `reviewer_ref`, the reviewer's FHIR identity digest, the
  credential digest and the scoped-authority digest are all inside the CAID.
  Swapping the reviewer of record after signing fails with
  `action_digest_mismatch`, `caid_mismatch` and `action_projection_mismatch`.
  The reviewer's name, NPI, license state and license number live in a
  credential object carried in the packet, bound by
  `reviewer_identity_evidence_digest`, so a regulator recomputes one digest and
  the license binding either holds or it does not.
- **That the gate refused without it.** An adverse outcome with no accepted
  reviewer identity and scoped authority does not build. The refusal reason is
  `adverse_reviewer_required`. An approval (X12 review action A1) builds with no
  reviewer, so the rule is scoped to adverse outcomes rather than taxing every
  determination. Missing evidence is never authority to withhold medically
  necessary care; it routes to lawful human review or a patient-protective
  fallback.
- **That it was used once.** The determination CAID is consumed at the issuance
  boundary. Resubmitting the same determination is refused with `replay_refused`
  at the binding verifier and `do_not_rely_already_consumed` at the reliance
  kernel.
- **What happened when the write was lost.** If the provider system drops the
  connection after the determination was written, the operation settles
  `indeterminate` and a blind retry is refused with
  `operation_already_committed`. An indeterminate operation is not proof that
  the provider effect succeeded or failed. It is a safety state that consumes
  replay authority until authenticated, action-bound provider evidence
  reconciles the outcome. A duplicate adverse determination on a patient record
  is its own harm, so the safe move is to hold, not to retry. Reconciliation
  records the authenticated outcome beside the original and never rewrites it.

The packet is an `EP-ASSURANCE-PACKAGE-v1`. An independent party re-performs
every reliance verdict from the packaged evidence alone, under its own pinned
keys, recomputing the package/profile digests and every verdict, and reports drift between what the
payer's runtime claimed and what the evidence supports. The re-performance
workpaper always emits a null conclusion. The tool supports the procedure. A
person concludes.

## 4. The trust anchors are yours, not ours

`cms-prior-auth.v1.json` ships with `accepted_issuer_keys`,
`accepted_policy_hashes` and `accepted_registry_keys` all empty. That is
deliberate. Cryptographic verification and acceptance are different questions.
A receipt whose signatures check out is VERIFIED. It is ACCEPTED only when the
relying party evaluates it under roots that relying party pinned itself. A payer
overlays its own credentialing registry key; a regulator overlays whichever
roots it is willing to stand behind; a plaintiff's expert overlays neither and
still gets to check the digest chain. Handing someone a profile with our keys
baked in would be selling them our trust decision as if it were theirs.

## 5. What this is not

- Not legal advice, and not a legal, regulatory, clinical, medical-necessity,
  privacy-compliance or payer-policy determination.
- Not a claim that running this makes any party compliant with SB 1120, Texas
  SB 815, the NAIC model bulletin, CMS rules, HIPAA, CMIA, or anything else.
  No statute is claimed to mandate EMILIA or cryptographic receipts.
- Not endorsed, approved, reviewed or certified by DHCS, CMS, the California
  Department of Managed Health Care, any state regulator, HL7, Da Vinci, X12 or
  NCPDP.
- Not a deployed system, not independently attested, not certified. It is a
  reference composition and a runnable demo. The in-memory capability store it
  uses is explicitly marked non-durable and is unsuitable for production.
- Not a replacement for utilization management, clinical review, claims
  adjudication, appeals, grievance processes, credentialing, or an EHR or payer
  platform. It answers a narrower question, at the moment of issuance: can the
  executor verify which licensed reviewer authorized this exact determination,
  under which criteria, consume that authorization once, and preserve what
  happened at the effect boundary?
- Not a statement that a digest proves source authenticity, or that a CAID
  proves authorization. The resources must come from the payer's own
  authenticated system of record, not from an agent or a patient-facing request
  body. The binding minimizes what leaves that boundary; it does not vouch for
  what entered it. That minimization is a deterministic control, not a HIPAA,
  CMIA, security or legal-compliance determination.
- Not the pharmacy rail. Specialty pharmacy prior authorization runs on NCPDP
  and is deliberately excluded from this binding.

## 6. Run it

```
node examples/adverse-determination.mjs          # paced, for screen recording
FAST=1 node examples/adverse-determination.mjs   # no pauses
```

Fully offline. No network, no API key, no account. Every printed line is the
result of a call that just executed in that process; the demo asserts its own
printed claims at the end and exits non-zero if any of them stopped being true.
