<!-- SPDX-License-Identifier: Apache-2.0 -->
# Da Vinci PAS medical-review binding

**Status:** reference binding / standards-engagement candidate
**Pinned source:** HL7 Da Vinci PAS FHIR IG `2.2.1`, FHIR R4
**Scope:** medical prior authorization only

This profile projects a server-observed PAS `Claim` and `ClaimResponse` into one
deterministic EMILIA material action. The portable result contains a pairwise
patient reference, exact projection digests, the policy and decision outcome,
accepted adverse-review evidence digests, and a CAID. It never contains the raw
FHIR resources or their raw clinical fields.

It is a reference boundary, not an EHR connector, a production deployment, a
clinical decision system, or a legal-compliance opinion.

## Where the binding sits

The existing PAS exchange remains authoritative for the medical prior-
authorization request and response. EMILIA is a portable sidecar over
server-owned observations:

1. An authenticated server adapter obtains the PAS 2.2.1 `Claim` and
   `ClaimResponse`, the relying party's pinned policy, a pairwise patient
   reference, and any accepted reviewer evidence.
2. The projector validates the Claim/ClaimResponse relationship and line-item
   correspondence before it creates any portable output.
3. Raw resources and clinical values are canonicalized and digested in the
   controlled server boundary. Only the digests leave that boundary.
4. The exact minimized action is assigned a CAID. A verifier later reprojects
   fresh server observations and must reproduce the same action, action digest,
   and CAID.
5. The caller supplies durable consumed-CAID state. A consumed CAID is refused;
   this pure reference verifier does not claim to provide the database or atomic
   consume operation.

“Server-owned” is an adapter obligation, not a string a request body can assert.
The module cannot establish source authenticity if an integration passes it
agent-controlled or patient-facing data.

## Exact material projection

| Portable action field | Server-owned source |
| --- | --- |
| `operation_id` | caller's single-use operation identifier |
| `rail` / `ig_version` | fixed to `hl7-davinci-pas-medical` / `2.2.1` |
| `pairwise_patient_ref` | server-side patient-to-pairwise mapping; direct `Patient/...` references are refused in portable output |
| `claim_digest` | entire PAS `Claim` |
| `claim_identifier_digest` | `Claim.identifier` |
| `claim_response_digest` | entire PAS `ClaimResponse` |
| `request_reference_digest` | `ClaimResponse.request` |
| `service_request_digest` | `Claim.careTeam`, `supportingInfo`, `diagnosis`, `procedure`, `insurance`, and `item` |
| `decision_digest` | `ClaimResponse.outcome` plus ordered item sequences, PAS review-action codes, and exact adjudication digests |
| `decision_outcome` | deterministic aggregate of the PAS line review-action codes |
| `fhir_outcome` | the ClaimResponse processing outcome; it is separate from the authorization decision |
| `policy_id` / `policy_version` / `policy_digest` | relying-party-pinned decision policy |

The projector requires the PAS 2.2.1 profile URLs, `use =
preauthorization`, matching patient and insurer references, an exact
`ClaimResponse.request = Claim/{id}` relationship, and the same unique line
sequence set on both resources. Each response line must expose exactly one
supported review-action code under the PAS review-action extension.

The current closed mapping is `A1` → `approved`, `A2` → `modified`, `A3` →
`denied`, and `A4` → `pended`. Distinct outcomes across lines produce `mixed`.
`modified`, `denied`, `pended`, and `mixed` are conservatively treated as
adverse. Unknown or ambiguous codes fail closed; the code does not guess their
meaning.

## Adverse decisions require accepted human-review evidence

An adverse projection is refused unless the `ClaimResponse` has exactly one PAS
reviewer extension with `wasHumanReviewedFlag = true` and a reviewer NPI
identifier. The NPI remains inside the server-owned response; the portable
action carries only the reviewer-extension digest and an accountable
`reviewer_ref`.

The caller must also supply two evidence records already accepted under the
relying party's own trust policy:

- identity evidence whose subject is the same `reviewer_ref` and whose
  `fhir_reviewer_digest` matches the exact PAS reviewer extension; and
- authority evidence for
  `medical_prior_authorization.adverse_decision`, bound to the same reviewer,
  policy digest, and exact ClaimResponse digest.

`accepted` is deliberately stronger than “a signature parsed.” The relying
party must perform its own issuer, credential, license, scope, expiry,
revocation, and policy checks before passing accepted evidence to this binding.
The reference code validates those bindings; it does not perform those external
checks and is not itself a trust registry.

## Portable privacy boundary

The portable schema is an exact allowlist. Unknown fields fail verification.
Raw `Claim`, `ClaimResponse`, `Patient`, diagnosis, procedure, service,
`supportingInfo`, and clinical-note fields are prohibited. Direct patient
references are prohibited; the only patient slot accepts a `pairwise:`
reference. Any altered source resource changes its digest, action digest, and
CAID.

Digesting a resource is minimization, not anonymization and not proof that its
source was authentic. Deployments still need their own access controls, keyed
pairwise mapping, retention rules, transport security, audit storage, and legal
review. This profile makes no HIPAA, CMIA, security-certification, or other
compliance claim.

## Medical PAS is not the pharmacy rail

This binding is for the HL7 Da Vinci PAS **medical** prior-authorization rail.
Drug prior authorization and pharmacy-benefit workflows remain on the
applicable **NCPDP** SCRIPT/ePA and related pharmacy standards. EMILIA does not
replace or tunnel those transactions through this profile. The existing
candidate NCPDP sidecar is documented separately in
[`NCPDP-RX-RELIANCE-COMPANION.md`](./NCPDP-RX-RELIANCE-COMPANION.md).

## SB 1120 and WISeR: the honest bridge

California SB 1120 and CMS WISeR create auditable licensed-review events in the
operational sense: adverse medical-necessity decisions must be attributable to
qualified or appropriately licensed human review. That makes reviewer identity,
authority, policy, request, and outcome useful evidence to preserve.

Neither SB 1120 nor WISeR mandates EMILIA, CAIDs, digital signatures, or
cryptographic receipts. This profile is one technical proposal for creating a
minimized deterministic content binding that a receipt or evidence chain can
authenticate; the unsigned binding alone is not tamper evidence. It is not an
assertion of statutory compliance, CMS approval, payer acceptance, or
production/EHR integration.

## Reference artifacts

- `lib/health/davinci-pas-binding.ts` — deterministic projector and verifier.
- `profiles/health/davinci-pas-review-binding.v1.json` — machine-readable
  profile and claim boundaries.
- `tests/davinci-pas-binding.test.ts` — action substitution,
  reviewer/authority omission, altered ClaimResponse, replay/CAID mismatch,
  patient mismatch, and PHI-leakage attacks.

## Primary sources

- HL7 Da Vinci PAS FHIR IG 2.2.1: https://hl7.org/fhir/us/davinci-pas/2.2.1/
- PAS Claim profile: https://hl7.org/fhir/us/davinci-pas/2.2.1/StructureDefinition-profile-claim.html
- PAS ClaimResponse profile: https://hl7.org/fhir/us/davinci-pas/2.2.1/StructureDefinition-profile-claimresponse.html
- PAS ClaimResponse Reviewer extension: https://hl7.org/fhir/us/davinci-pas/2.2.1/StructureDefinition-extension-claimResponseReviewer.html
- PAS Review Action Code extension: https://hl7.org/fhir/us/davinci-pas/2.2.1/StructureDefinition-extension-reviewActionCode.html
- California SB 1120 bill text: https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240SB1120
- CMS WISeR model: https://www.cms.gov/priorities/innovation/innovation-models/wiser
- CMS WISeR FAQ: https://www.cms.gov/priorities/innovation/files/document/wiser-model-frequently-asked-questions
- NCPDP standards access: https://standards.ncpdp.org/Access-to-Standards.aspx
