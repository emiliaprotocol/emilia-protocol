<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-CLINICAL-AUTHORIZATION-PROFILE — verifiable human authorization for high-risk healthcare actions

**Status:** Profile (spec-level). EXPERIMENTAL — governed by an Extension PIP.
Defines an OPTIONAL domain profile of [draft-schrock-ep-authorization-receipts]
and [draft-schrock-ep-quorum] for healthcare; implemented with the first
deploying customer. Not a production metric, regulatory certification, or
customer claim. **Not medical, legal, or compliance advice.**

## The gap this closes

Clinical and operational AI agents are beginning to *take actions*, not just
draft them: placing orders, releasing medications, submitting prior-auth
decisions, cutting purchase orders. "A clinician was in the loop" is the standard
assurance, but it is **unfalsifiable** — there is no artifact a surveyor,
malpractice court, payer, or internal auditor can independently check, *after the
fact*, that a specific accountable person authorized **this exact action** before
it happened.

EP closes exactly that gap, and healthcare is an unusually clean fit because the
core EP primitive — a **quorum of distinct, accountable humans** authorizing a
specific action — is **already mandated practice** in the clinical setting (the
independent double-check) and **already required control** in the financial one
(segregation of duties). This profile specifies how to express those existing
controls as EP authorization receipts.

## Scope — the high-risk healthcare actions in view

| Class | Example action | EP control |
|---|---|---|
| High-alert medication | heparin / insulin / opioid / chemotherapy administration | independent double-check (EP-QUORUM-v1, two distinct clinicians) |
| Controlled substance | dispense / waste | dual witness |
| Blood product | release / transfuse | two-person verification |
| Protected disclosure | bulk PHI export, records release | named authorizer + purpose binding |
| Capital procurement | equipment / implant / off-contract PO | dual control (department + finance) |
| Clinical override | break-glass on a blocked action | self-documenting authorization (see below) |

The profile is **horizontal across these** — it does not model clinical content;
it models *who authorized what action, when, under which policy*.

## PHI posture — receipts carry no PHI by construction

This is a defining design rule of the profile:

> An EP clinical authorization receipt MUST NOT embed PHI. Patient and encounter
> identifiers appear **only as one-way hashes** (e.g. `patient_ref:
> "sha256:<hash of MRN|encounter>"`), and the `action` object references the
> order by identifier, not by clinical narrative.

Consequences:

- The authorization **evidence** can be verified, retained, and shared with
  auditors, surveyors, payers, or a court **without constituting a PHI
  disclosure** — the receipt is not a designated record set entry and contains no
  identifiable health information.
- The hash still binds the receipt to a specific patient/encounter for anyone who
  *already* holds the identifier (re-deriving the hash), preserving evidentiary
  value, without exposing the identifier to anyone who does not.
- An EP issuer operating on PHI-adjacent systems is still expected to sit behind
  the covered entity's existing safeguards; the receipt itself is designed so
  that **the portable artifact is PHI-free**.

## Roles and separation of duties

The EP-QUORUM-v1 policy roster expresses the clinical/operational control
directly. Two worked examples (both runnable: `npx -y @emilia-protocol/crash-test
--scenario clinical|procurement`):

**High-alert medication — independent double-check**
```json
{
  "mode": "ordered", "required": 2, "distinct_humans": true, "window_sec": 600,
  "approvers": [
    { "role": "administering_nurse",        "approver": "ep:approver:rn_okafor" },
    { "role": "independent_verifier_nurse", "approver": "ep:approver:rn_delacruz" }
  ]
}
```
`distinct_humans` enforces that the verifier is genuinely a *second* clinician;
`action_binding` ensures both signed the same drug/concentration/rate; a forged
copy with the rate altered after the check fails verification.

**Capital procurement — dual control**
```json
{
  "mode": "ordered", "required": 2, "distinct_humans": true, "window_sec": 172800,
  "approvers": [
    { "role": "department_director", "approver": "ep:approver:dir_alvarez" },
    { "role": "cfo",                 "approver": "ep:approver:cfo_whitfield" }
  ]
}
```
Because the **payee account is inside the signed action**, the most common theft
vector — swapping the vendor's bank account after approval (payment-redirect /
BEC fraud) — breaks verification rather than passing silently.

## Break-glass — fail-closed without hard-blocking care

EP is fail-closed, which is correct for money but dangerous for time-critical
clinical actions: a verifier that hard-blocks a STAT order is a patient-safety
hazard. The profile resolves this **without weakening the guarantee**:

> An emergency override ("break-glass") is itself a high-risk action that emits
> its **own** authorization receipt — recording *who* invoked it, *when*, against
> *which* blocked action, under *what stated justification* — signed on the
> invoker's device.

The time-critical path is therefore **never hard-blocked**; instead the override
becomes **the most auditable event in the record** rather than the least. This
inverts the usual failure mode (overrides that no one can later reconstruct) and
maps directly to what accreditation bodies expect of emergency-access controls.

## Standards this expresses (informative, not a certification)

- **ISMP** independent-double-check guidance for high-alert medications, and
  **The Joint Commission** Medication Management standards / National Patient
  Safety Goals — the two-clinician ceremony rendered as tamper-evident, offline
  evidence.
- **HIPAA** — by the PHI-free construction above, the portable evidence avoids
  being a disclosure.
- **EU AI Act, Article 14 (human oversight)** — for medical AI classified
  high-risk, EP provides an *offline-verifiable artifact* that human oversight
  occurred for a specific action, owned by no single vendor. (See the EU
  sovereignty framing in the outreach materials.)
- **Internal control over financial reporting / segregation of duties** and, for
  tax-exempt systems, the governance represented on **IRS Form 990** — for the
  procurement class.

## What it deliberately does not claim (bounds)

- It does **not** assert clinical appropriateness — that the order was *right* for
  the patient remains the prescriber's and pharmacist's judgment.
- It does **not** establish the real-world identity behind an enrolled clinician
  key — that is the enrollment layer ([EP-IDENTITY-BINDING-PROFILE]).
- It is **not** Clinical Decision Support: EP does not recommend, rank, or
  influence the clinical decision; it records that the required humans authorized
  a specific action. This authorization-evidence role is intended to sit *outside*
  the function of CDS software, but classification is a regulatory determination
  for the deploying entity and its counsel, not a claim made here.
- It is **not** a substitute for the relying party's own risk assessment.

## How it composes

This profile is purely a *profile*: it adds no new artifact types and changes no
verifier behavior. A receipt produced under it verifies with the **stock**
JS / Python / Go verifiers and the same EP-QUORUM-v1 conformance vectors. It
references [EP-IDENTITY-BINDING-PROFILE] for clinician enrollment and the base
drafts for the receipt and quorum semantics.

[draft-schrock-ep-authorization-receipts]: https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/
[draft-schrock-ep-quorum]: https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/
[EP-IDENTITY-BINDING-PROFILE]: ./EP-IDENTITY-BINDING-PROFILE.md
