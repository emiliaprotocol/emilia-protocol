# Da Vinci PAS Consequence-Control Reference

Status: public, PHI-free synthetic reference. The implementation is executable
against injected sandbox systems of record. It is not a live payer, provider,
EHR, utilization-management, Medicare, or Medi-Cal deployment.

## What is complete

This reference composes the Da Vinci PAS 2.2.1 review binding with the existing
EMILIA Proposal-to-Effect controller. It closes the path from a server-observed
medical prior-authorization determination to one controlled consequence:

1. The relying party loads the exact PAS `Claim` and `ClaimResponse` from its
   authenticated system of record.
2. The PAS projector produces a closed, PHI-minimized action and CAID. An
   adverse decision also binds accepted reviewer identity and authority
   evidence.
3. Gate issues an exact approval challenge and verifies the returned receipt.
   AEB separately evaluates the relying party's pinned evidence requirements.
4. Proposal-to-Effect atomically reserves one evidence use and one provider
   attempt before entering the protected callback.
5. A completed callback commits `EXECUTED`. A lost or ambiguous response enters
   `INDETERMINATE`; the same authorization cannot invoke the callback again.
6. Only authenticated provider evidence bound to the same tenant, operation,
   attempt, request digest, provider context, CAID, and action digest can
   reconcile the attempt.
7. An authenticated export returns a signed, PHI-minimized reliance packet for
   offline verification.

The implementation reuses the existing custody state machine. It does not add
a second execution state machine or weaken the distinction between evidence,
qualification, authorization, and effect.

## HTTP trust boundary

`POST /api/v1/adapters/health/davinci-pas/review` accepts `prepare`, `execute`,
and `reconcile` operations. Prepare and execute accept a `pas_context_ref`, not
raw FHIR. After authentication and tenant binding, the deployment-supplied
loader retrieves the PAS resources server-side. Agent-supplied `Claim`,
`ClaimResponse`, patient, diagnosis, procedure, supporting-information, or
clinical-note fields are refused.

`GET /api/v1/adapters/health/davinci-pas/export` returns the signed reliance
packet only to an authenticated entity bound to the requested organization.

Production must inject:

- a configured Proposal-to-Effect controller;
- durable AEB consumption, consequence-attempt, evidence, and reconciliation
  stores;
- relying-party-pinned current-status and provider-evidence verifiers;
- a KMS/HSM-backed packet signer;
- a tenant-bound PAS context loader; and
- a protected system-of-record callback.

Tests use explicit in-memory stores and a synthetic callback only.

## Claim boundary

This implementation proves that the reference code can bind and control the
synthetic path described above. It does not prove source-system truth, medical
necessity, clinical correctness, statutory compliance, payer acceptance,
operational availability, or production deployment. California SB 1120 and CMS
WISeR create auditable human-review events; neither mandates EMILIA, CAIDs,
receipts, or this profile.

## Artifacts

- `lib/health/davinci-pas-binding.ts` — PAS 2.2.1 projector and verifier.
- `lib/health/davinci-pas-consequence-control.ts` — Proposal-to-Effect
  composition and signed reliance packet.
- `app/api/v1/adapters/health/davinci-pas/review/route.ts` — authenticated,
  tenant-bound command boundary with server-side PAS loading.
- `app/api/v1/adapters/health/davinci-pas/export/route.ts` — authenticated
  reliance-packet export.
- `conformance/vectors/davinci-pas-consequence-control.v1.json` — fixed action
  binding and lifecycle expectations.
- `tests/davinci-pas-consequence-control.test.ts` — source drift, replay,
  uncertainty, reconciliation, signature, PHI, authentication, and tenant
  boundary tests.

## Primary sources

- HL7 Da Vinci PAS FHIR IG 2.2.1: https://hl7.org/fhir/us/davinci-pas/2.2.1/
- California SB 1120: https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240SB1120
- CMS WISeR model: https://www.cms.gov/priorities/innovation/innovation-models/wiser
