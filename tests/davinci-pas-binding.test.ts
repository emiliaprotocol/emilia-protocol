import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  DAVINCI_PAS_ACTION_TYPE,
  buildDavinciPasReviewBinding,
  digestPasValue,
  verifyDavinciPasReviewBinding,
} from '../lib/health/davinci-pas-binding.js';

const CLAIM_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const RESPONSE_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const REVIEWER_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-claimResponseReviewer';
const REVIEW_ACTION_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewAction';
const REVIEW_ACTION_CODE_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewActionCode';
const X12_REVIEW_ACTION_SYSTEM = 'https://codesystem.x12.org/005010/306';

const POLICY = Object.freeze({
  policy_id: 'policy:medical-pa:2026-07',
  policy_version: '2026-07',
  policy_digest: `sha256:${'a'.repeat(64)}`,
});

function clone<T>(value: T): T {
  return structuredClone(value);
}

function claim() {
  return {
    resourceType: 'Claim',
    id: 'medical-pa-claim-001',
    meta: { profile: [CLAIM_PROFILE] },
    identifier: [{ system: 'https://payer.example.test/prior-auth', value: 'secret-pa-001' }],
    status: 'active',
    type: {
      coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }],
    },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-member-123' },
    created: '2026-07-21T18:30:00Z',
    insurer: { reference: 'Organization/payer-1' },
    provider: { reference: 'Organization/requesting-provider-1' },
    priority: {
      coding: [{ system: 'http://terminology.hl7.org/CodeSystem/processpriority', code: 'normal' }],
    },
    diagnosis: [{ sequence: 1, diagnosisCodeableConcept: { coding: [{ system: 'http://hl7.org/fhir/sid/icd-10-cm', code: 'M17.11' }] } }],
    supportingInfo: [{ sequence: 1, category: { text: 'clinical note' }, valueString: 'raw clinical rationale' }],
    item: [{
      sequence: 1,
      productOrService: {
        coding: [{ system: 'http://www.ama-assn.org/go/cpt', code: '27447' }],
      },
      servicedDate: '2026-08-15',
      locationCodeableConcept: {
        coding: [{ system: 'https://www.cms.gov/Medicare/Coding/place-of-service-codes', code: '22' }],
      },
      quantity: { value: 1 },
    }],
  };
}

function reviewerExtension() {
  return {
    url: REVIEWER_URL,
    extension: [
      { url: 'wasHumanReviewedFlag', valueBoolean: true },
      {
        url: 'reviewerNPI',
        valueIdentifier: {
          system: 'http://hl7.org/fhir/sid/us-npi',
          value: '1234567893',
        },
      },
      {
        url: 'reviewerSpecialty',
        valueCodeableConcept: {
          coding: [{ system: 'http://nucc.org/provider-taxonomy', code: '207X00000X' }],
        },
      },
    ],
  };
}

function claimResponse(reviewActionCode = 'A3') {
  return {
    resourceType: 'ClaimResponse',
    id: 'medical-pa-response-001',
    meta: { profile: [RESPONSE_PROFILE] },
    status: 'active',
    type: {
      coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }],
    },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-member-123' },
    created: '2026-07-21T18:31:00Z',
    insurer: { reference: 'Organization/payer-1' },
    request: { reference: 'Claim/medical-pa-claim-001' },
    outcome: 'complete',
    extension: reviewActionCode === 'A1' ? [] : [reviewerExtension()],
    item: [{
      itemSequence: 1,
      adjudication: [{
        category: {
          coding: [{ system: 'http://terminology.hl7.org/CodeSystem/adjudication', code: 'submitted' }],
        },
        extension: [{
          url: REVIEW_ACTION_URL,
          extension: [{
            url: REVIEW_ACTION_CODE_URL,
            valueCodeableConcept: {
              coding: [{ system: X12_REVIEW_ACTION_SYSTEM, code: reviewActionCode }],
            },
          }],
        }],
      }],
    }],
  };
}

function serverInput(reviewActionCode = 'A3') {
  const pasClaim = claim();
  const pasClaimResponse = claimResponse(reviewActionCode);
  const responseDigest = digestPasValue(pasClaimResponse);
  const reviewer = pasClaimResponse.extension[0];

  return {
    operation_id: 'medical-pa-review-op-001',
    pairwise_patient_ref: 'pairwise:medical-pa-member-7H3k9Q2p',
    claim: pasClaim,
    claim_response: pasClaimResponse,
    policy: POLICY,
    ...(reviewActionCode === 'A1' ? {} : {
      reviewer: {
        reviewer_ref: 'reviewer:utilization-reviewer-017',
        identity_evidence: {
          status: 'accepted',
          subject_ref: 'reviewer:utilization-reviewer-017',
          evidence_digest: `sha256:${'b'.repeat(64)}`,
          fhir_reviewer_digest: digestPasValue(reviewer),
        },
        authority_evidence: {
          status: 'accepted',
          subject_ref: 'reviewer:utilization-reviewer-017',
          evidence_digest: `sha256:${'c'.repeat(64)}`,
          scope: 'medical_prior_authorization.adverse_decision',
          policy_digest: POLICY.policy_digest,
          claim_response_digest: responseDigest,
        },
      },
    }),
  };
}

function requireBinding(input = serverInput()) {
  const result = buildDavinciPasReviewBinding(input);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.reasons.join(','));
  return result.binding;
}

describe('Da Vinci PAS medical-review binding', () => {
  it('deterministically projects server-owned PAS 2.2.1 resources without portable PHI', () => {
    const first = requireBinding();
    const second = requireBinding();

    expect(first).toEqual(second);
    expect(first.action).toMatchObject({
      action_type: DAVINCI_PAS_ACTION_TYPE,
      operation_id: 'medical-pa-review-op-001',
      rail: 'hl7-davinci-pas-medical',
      ig_version: '2.2.1',
      pairwise_patient_ref: 'pairwise:medical-pa-member-7H3k9Q2p',
      decision_outcome: 'denied',
      fhir_outcome: 'complete',
      policy_id: POLICY.policy_id,
      policy_version: POLICY.policy_version,
      policy_digest: POLICY.policy_digest,
      reviewer_ref: 'reviewer:utilization-reviewer-017',
    });
    expect(first.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(first.caid).toMatch(
      /^caid:1:health\.medical-prior-authorization-review\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/,
    );

    const portable = JSON.stringify(first);
    expect(portable).not.toContain('Patient/direct-member-123');
    expect(portable).not.toContain('secret-pa-001');
    expect(portable).not.toContain('27447');
    expect(portable).not.toContain('M17.11');
    expect(portable).not.toContain('raw clinical rationale');
  });

  it('verifies the exact server projection, policy, outcome, and CAID', () => {
    const input = serverInput();
    const binding = requireBinding(input);
    const result = verifyDavinciPasReviewBinding(binding, {
      ...input,
      expected_operation_id: input.operation_id,
      expected_caid: binding.caid,
      consumed_caids: new Set<string>(),
    });

    expect(result).toEqual({ valid: true, reasons: [] });
  });

  it('binds a complete A1 approval without inventing an adverse-review requirement', () => {
    const input = serverInput('A1');
    const binding = requireBinding(input);

    expect(binding.action.decision_outcome).toBe('approved');
    expect(binding.action).not.toHaveProperty('reviewer_ref');
    expect(verifyDavinciPasReviewBinding(binding, input)).toEqual({
      valid: true,
      reasons: [],
    });
  });

  it('rejects portable action substitution', () => {
    const input = serverInput();
    const substituted = clone(requireBinding(input));
    substituted.action.decision_outcome = 'approved';

    const result = verifyDavinciPasReviewBinding(substituted, input);
    expect(result.valid).toBe(false);
    expect(result.reasons).toEqual(expect.arrayContaining([
      'action_projection_mismatch',
      'action_digest_mismatch',
      'caid_mismatch',
    ]));
  });

  it('rejects an adverse decision without an accepted reviewer identity', () => {
    const input = serverInput();
    delete (input as { reviewer?: unknown }).reviewer;

    const result = buildDavinciPasReviewBinding(input);
    expect(result).toEqual({
      ok: false,
      reasons: expect.arrayContaining(['adverse_reviewer_required']),
    });
  });

  it('rejects omitted, unaccepted, or mis-bound reviewer authority', () => {
    const missing = serverInput();
    delete (missing.reviewer as { authority_evidence?: unknown }).authority_evidence;
    expect(buildDavinciPasReviewBinding(missing)).toEqual({
      ok: false,
      reasons: expect.arrayContaining(['reviewer_authority_evidence_required']),
    });

    const unaccepted = serverInput();
    unaccepted.reviewer.authority_evidence.status = 'verified';
    expect(buildDavinciPasReviewBinding(unaccepted)).toEqual({
      ok: false,
      reasons: expect.arrayContaining(['reviewer_authority_not_accepted']),
    });

    const misbound = serverInput();
    misbound.reviewer.authority_evidence.policy_digest = `sha256:${'d'.repeat(64)}`;
    expect(buildDavinciPasReviewBinding(misbound)).toEqual({
      ok: false,
      reasons: expect.arrayContaining(['reviewer_authority_policy_mismatch']),
    });
  });

  it('rejects an altered server-owned ClaimResponse', () => {
    const input = serverInput();
    const binding = requireBinding(input);
    const altered = clone(input);
    altered.claim_response.item[0].adjudication[0].extension[0]
      .extension[0].valueCodeableConcept.coding[0].code = 'A1';

    const result = verifyDavinciPasReviewBinding(binding, altered);
    expect(result.valid).toBe(false);
    expect(result.reasons).toEqual(expect.arrayContaining([
      'claim_response_digest_mismatch',
      'action_projection_mismatch',
    ]));
  });

  it('rejects a substituted policy even when the portable object is untouched', () => {
    const input = serverInput();
    const binding = requireBinding(input);
    const altered = clone(input);
    altered.policy = {
      ...altered.policy,
      policy_digest: `sha256:${'e'.repeat(64)}`,
    };

    const result = verifyDavinciPasReviewBinding(binding, altered);
    expect(result.valid).toBe(false);
    expect(result.reasons).toEqual(expect.arrayContaining([
      'policy_digest_mismatch',
      'action_projection_mismatch',
    ]));
  });

  it('rejects replay and an expected-CAID mismatch independently', () => {
    const input = serverInput();
    const binding = requireBinding(input);

    const replay = verifyDavinciPasReviewBinding(binding, {
      ...input,
      consumed_caids: new Set([binding.caid]),
    });
    expect(replay).toEqual({
      valid: false,
      reasons: expect.arrayContaining(['replay_refused']),
    });

    const wrongExpectedCaid = verifyDavinciPasReviewBinding(binding, {
      ...input,
      expected_caid: binding.caid.replace(/.$/, binding.caid.endsWith('A') ? 'B' : 'A'),
    });
    expect(wrongExpectedCaid).toEqual({
      valid: false,
      reasons: expect.arrayContaining(['expected_caid_mismatch']),
    });
  });

  it('rejects a response-to-Claim or patient mismatch', () => {
    const wrongRequest = serverInput();
    wrongRequest.claim_response.request.reference = 'Claim/another-request';
    expect(buildDavinciPasReviewBinding(wrongRequest)).toEqual({
      ok: false,
      reasons: expect.arrayContaining(['claim_response_request_mismatch']),
    });

    const wrongPatient = serverInput();
    wrongPatient.claim_response.patient.reference = 'Patient/another-member';
    expect(buildDavinciPasReviewBinding(wrongPatient)).toEqual({
      ok: false,
      reasons: expect.arrayContaining(['claim_response_patient_mismatch']),
    });
  });

  it('rejects PHI, patient-direct references, and raw clinical fields planted in portable output', () => {
    const input = serverInput();
    const binding = requireBinding(input);

    const phi = clone(binding) as typeof binding & { patient_name: string };
    phi.patient_name = 'Direct Patient Name';
    const phiResult = verifyDavinciPasReviewBinding(phi, input);
    expect(phiResult.reasons).toEqual(expect.arrayContaining([
      'portable_phi_field',
      'portable_output_unknown_field',
    ]));

    const rawClinical = clone(binding) as typeof binding & { raw_clinical_resource: unknown };
    rawClinical.raw_clinical_resource = { diagnosis: 'M17.11', note: 'secret' };
    const rawResult = verifyDavinciPasReviewBinding(rawClinical, input);
    expect(rawResult.reasons).toEqual(expect.arrayContaining([
      'portable_phi_field',
      'portable_output_unknown_field',
    ]));

    const direct = clone(binding);
    direct.action.pairwise_patient_ref = 'Patient/direct-member-123';
    const directResult = verifyDavinciPasReviewBinding(direct, input);
    expect(directResult.reasons).toEqual(expect.arrayContaining([
      'patient_reference_not_pairwise',
    ]));
  });

  it('keeps the NCPDP pharmacy pathway explicitly separate', () => {
    const profile = JSON.parse(readFileSync(
      new URL('../profiles/health/davinci-pas-review-binding.v1.json', import.meta.url),
      'utf8',
    ));

    expect(profile.rail).toBe('hl7-davinci-pas-medical');
    expect(profile.pharmacy_rail).toMatchObject({
      separate: true,
      owner: 'NCPDP',
      replacement: false,
    });
    expect(profile.pharmacy_rail.excluded_from_this_binding).toBe(true);
  });
});
