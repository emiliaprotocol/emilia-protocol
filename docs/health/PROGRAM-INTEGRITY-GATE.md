<!-- SPDX-License-Identifier: Apache-2.0 -->
# Medi-Cal hospice Program Integrity Gate

**Status:** Candidate, PHI-free reference profile

**Profile:** `public/schemas/reliance-profiles/medi-cal-hospice-integrity.v1.json`

**Action type:** `health.medi_cal.hospice_claim_payment.1`

This profile shows how an executor can require exact-action, named-human
authorization evidence before committing a synthetic Medi-Cal hospice claim
payment. It is a reference composition of existing EMILIA primitives. It is not
a DHCS, CMS, Medi-Cal, or regulatory standard or endorsement.

## Where this fits

California already uses program-integrity analytics, provider screening,
license and certification checks, audits and investigations, payment stops,
utilization management, and law-enforcement collaboration. DHCS also describes
automated payment safeguards that block a hospice claim unless a valid
authorization form is on file and verified.

This profile complements those controls. It asks a narrower execution question:

> Before this exact payment consequence is committed, can the executor verify
> which provider, pseudonymous member reference, service period, authorization
> artifact, amount, destination, reviewer authority, and policy were approved,
> consume that approval once, and preserve what happened at the effect boundary?

It does **not** replace fraud analytics, provider enrollment and screening,
clinical review, utilization management, claims adjudication, CA-MMIS, a managed
care plan's systems, audits, investigations, recovery, or law enforcement.

Official context:

- [DHCS Program Integrity](https://www.dhcs.ca.gov/program-integrity/)
- [DHCS: California Stops Major Identity Theft and Hospice Fraud Scheme (April 9, 2026)](https://www.dhcs.ca.gov/news/california-stops-major-identity-theft-and-hospice-fraud-scheme/)

## Why the JSON has two layers

The JSON remains a valid `EP-RELIANCE-PROFILE-v1`. Its base fields are the
portable rule evaluated by `evaluateReliance`: Class-A assurance, scoped
authority, revocation freshness, accepted policy and issuer roots, and one-time
consumption evidence.

The `x_emilia_program_integrity` extension is signed with the profile when a
registrar creates an `EP-RELIANCE-PROFILE-REGISTRY-v1` entry. It contains the
deployment contract that the generic reliance kernel does not evaluate:

1. an `EP-ACTION-CONTROL-MANIFEST-v0.2` action entry for executor-side field
   binding; and
2. capability, outcome, indeterminate, and reconciliation rules for the effect
   boundary.

Deployers must install and enforce the embedded action-control manifest (or an
equivalent stricter manifest) in Gate. Passing only the base profile to
`evaluateReliance` does not activate extension fields. Treating the extension as
automatically enforced would be an unsafe claim.

The published trust-anchor arrays are empty by design. A relying party overlays
its own accepted registry keys, issuer keys, and policy hashes. Verified is not
accepted.

## PHI-free reference discipline

The reference artifact contains no person, patient, claim, account, or payment
data. A synthetic demo using it must use synthetic values.

A live deployment should minimize the action to:

- a relying-party-scoped, pairwise `member_ref`;
- the service-period dates needed to distinguish the exact claim;
- a commitment to the authorization form, not the form;
- a keyed commitment to the payment destination, not account or routing data;
- a provider NPI and directory-anchored reviewer identifier; and
- policy, authority, and outcome commitments.

Do not place a name, date of birth, SSN, CIN, BIC, diagnosis, clinical note,
authorization form, bank account, or routing number in the action or portable
packet. Pairwise pseudonyms and service dates can still be regulated data in a
real deployment; this profile is a data-minimization pattern, not a
de-identification or legal-compliance determination.

## Exact action contract

Every field below is required in both the signed claim and the executor's
system-of-record observation. `EP-GATE-EXECUTION-BINDING-v1` compares canonical
values and refuses any missing, malformed, or mismatched field.

| Field | Bound meaning |
|---|---|
| `caid` | Canonical Action Identifier for this exact action and profile. |
| `action_type` | Exactly `health.medi_cal.hospice_claim_payment.1`. |
| `provider_npi` | Ten-digit provider NPI, represented as a string. |
| `member_ref` | Pairwise pseudonymous member reference scoped to the relying party. |
| `service_period_start` / `service_period_end` | Inclusive dates; end cannot precede start. |
| `authorization_form_digest` | SHA-256 commitment to the exact form retained in the controlled source system. |
| `amount` / `currency` | Canonical decimal claim-payment amount and `USD`. |
| `payment_destination_digest` | Domain-separated keyed SHA-256 commitment to the system-of-record destination. |
| `reviewer_id` | Directory-anchored named reviewer who completed the Class-A ceremony. |
| `authority_proof_digest` | Commitment to the accepted authority proof bound to reviewer, organization, scope, amount, policy, validity, and revocation. |
| `policy_id` / `policy_version` / `policy_hash` | Exact relying-party policy and version used for the decision. |

The field list is deliberately broad. Omitting a material field creates a
substitution gap: an approval for one provider, amount, destination, service
period, reviewer, or policy could otherwise be presented for another.

## Decision and execution sequence

1. **Resolve current source state.** Read provider standing, authorization-form
   status, payment destination, policy, and action values from controlled
   systems. Do not treat an agent or request body as the observation source.
2. **Build the canonical action.** Validate field grammar and compute the CAID
   and action digest over the complete material action.
3. **Evaluate reliance.** Require the pinned `EP-RELIANCE-PROFILE-v1`, a valid
   receipt, Class-A or stricter signoff, subject-bound scoped authority, fresh
   revocation state, accepted policy, and unconsumed state. Any unavailable,
   malformed, untrusted, stale, revoked, expired, or mismatched leg refuses.
4. **Compare execution binding.** Compare every required signed field with the
   executor's system-of-record observation. Any drift refuses before the effect.
5. **Reserve once.** Reserve a bounded capability scoped to the CAID, exact
   amount, currency, and expiry. A conflicting, expired, exhausted, or already
   used capability refuses.
6. **Invoke once.** Call the payment executor using an operation ID and
   idempotency key bound to the reserved operation.
7. **Commit the result.**
   - Authenticated success: commit `succeeded` and retain outcome evidence.
   - Authenticated failure before effect: commit `failed` and retain evidence.
   - Timeout, connection loss after invocation, or ambiguous provider response:
     commit `indeterminate`.
8. **Never blindly replay an indeterminate operation.** The authorization and
   capability remain consumed. Reconcile with authenticated provider or
   payment-executor evidence.
9. **Append reconciliation.** Verify the executor key and exact operation,
   CAID/action digest, amount, currency, destination commitment, and provider
   transaction-reference commitment. Append a digest-bound reconciliation
   record without rewriting the original indeterminate event.

## Fail-closed state model

| Condition | Required behavior |
|---|---|
| Missing profile, receipt, authority, freshness, policy, or consumption state | Refuse before execution. |
| Unknown, malformed, unpinned, stale, revoked, or expired evidence | Refuse before execution. |
| Signed action differs from system-of-record observation | Refuse before execution. |
| Capability expired, exhausted, consumed, or reserved by another operation | Refuse. |
| Executor not invoked | No consequence; record refusal/failure evidence. |
| Executor invoked and response authenticated | Commit the authenticated outcome once. |
| Executor invoked and response lost or ambiguous | Commit `indeterminate`; never auto-refund or auto-retry. |
| Reconciliation evidence unpinned, malformed, mismatched, or replayed | Refuse reconciliation; remain indeterminate. |
| Reconciliation evidence authentic and exact-action bound | Append final reconciliation; preserve original indeterminate event. |

Availability never becomes authorization. An unavailable verifier, registry,
state store, or reconciliation dependency cannot produce a pass.

## Expiry and single use

- The action-control entry sets a maximum receipt age of 300 seconds.
- The capability expires no later than the earliest receipt, authority, policy,
  or five-minute decision boundary.
- The capability is scoped to one CAID, one amount, one currency, and one use.
- Reservation occurs before the executor call.
- Invoking the executor consumes the operation even when the observed result is
  indeterminate.
- A second presentation, concurrent race, or retry must not create a second
  effect.

An operator may start a new action only after resolving the first operation and
creating a new CAID, fresh authorization, and new capability under the
deployment's policy. A new wrapper around the same unresolved effect is not a
safe retry.

## Outcome and reconciliation evidence

The normal executor result should be an `EP-OUTCOME-ATTESTATION-v1` under a
relying-party-pinned executor key. It binds:

- receipt ID and digest;
- action hash and consumption nonce;
- execution and executor IDs;
- execution time;
- observed-effects digest; and
- executor proof.

For an indeterminate operation, the reconciliation adapter must additionally
join the authenticated provider or payment-executor statement to the same
operation ID, CAID/action digest, amount, currency, destination commitment, and
provider transaction-reference commitment. Store only the minimum evidence
needed for verification and audit; retain source records in their controlled
systems.

## What a verified packet can prove

Subject to the relying party's pinned keys, policy, source observations, and
correct Gate deployment, the packet can establish:

- the exact material action the named reviewer approved;
- that the reviewer completed the required Class-A ceremony;
- that an accepted authority proof covered that reviewer, organization, scope,
  amount, policy, validity window, and fresh revocation state;
- that signed action fields matched the executor's system-of-record observation
  before the effect;
- that the authorization/capability was consumed once;
- whether execution was refused, succeeded, failed, or became indeterminate;
- that an indeterminate outcome was not blindly replayed; and
- whether later reconciliation evidence authenticated and matched the same
  operation.

## What it does not prove

The profile and packet do **not** establish:

- that a claim, service, provider, member, diagnosis, or authorization form is
  substantively legitimate;
- that hospice services were medically necessary, delivered, correctly coded,
  or payable;
- that the source systems, provider roster, license status, identity proofing,
  clinical record, or payment destination were accurate;
- that a reviewer was unbiased, competent, uncoerced, or correct;
- that fraud, collusion, identity theft, false records, or upstream compromise
  was absent;
- that an executor truthfully reported effects unless its evidence is accepted
  under an independently pinned key and corroborated as the relying party
  requires;
- HIPAA, CMIA, Medicaid, Medicare, Medi-Cal, CMS, DHCS, accessibility, security,
  records-retention, or procurement compliance;
- regulatory approval, certification, endorsement, or production deployment; or
- replacement of CA-MMIS, managed-care systems, fraud analytics, provider
  screening, utilization management, audits, investigations, recovery, or law
  enforcement.

This is consequence control and portable evidence, not a fraud verdict.

## Deployment minimums

Before enforcement, a deploying organization must:

1. define the authoritative system-of-record source for each bound field;
2. pin provider-standing, authority-registry, receipt/checkpoint, policy, and
   executor/reconciliation trust roots out of band;
3. define reviewer directory enrollment and revocation procedures;
4. install the embedded action-control entry in Gate and test every required
   field against executor-observed values;
5. configure a durable capability store and atomic reserve/commit/reconcile
   transitions;
6. verify payment-executor idempotency and authenticated status evidence;
7. define an operator queue and service-level objective for indeterminate
   reconciliation;
8. run synthetic positive, refusal, replay, timeout, mismatch, and
   reconciliation vectors;
9. validate logging, access control, retention, breach response, and privacy
   requirements with agency counsel and security teams; and
10. begin in observe mode or a non-production synthetic environment before any
    real claim or payment path is placed in enforcement.

## Validation

The base object must pass `validateRelianceProfile`. The embedded
`action_control_manifest` must pass `validateActionControlManifest`. JSON syntax
alone is not sufficient. A deployment must also run EG-1 execution-binding,
replay, tamper, outcome, timeout, and reconciliation tests against the actual
adapter and durable store.
