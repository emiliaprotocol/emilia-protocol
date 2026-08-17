import { describe, expect, it, vi } from 'vitest';

import {
  createDavinciPasCoverageSourceConnector,
} from '../lib/health/davinci-pas-coverage-connector.js';
import { digestPasValue } from '../lib/health/davinci-pas-binding.js';

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

function serverObservedPas() {
  const claim = {
    resourceType: 'Claim',
    id: 'medical-pa-claim-001',
    meta: { profile: [CLAIM_PROFILE] },
    identifier: [{ system: 'https://payer.example.test/prior-auth', value: 'secret-pa-001' }],
    status: 'active',
    type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }] },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-member-123' },
    created: '2026-07-21T18:30:00Z',
    insurer: { reference: 'Organization/payer-1' },
    provider: { reference: 'Organization/requesting-provider-1' },
    priority: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/processpriority', code: 'normal' }] },
    item: [{
      sequence: 1,
      productOrService: { coding: [{ system: 'http://www.ama-assn.org/go/cpt', code: '27447' }] },
      servicedDate: '2026-08-15',
      quantity: { value: 1 },
    }],
  };
  const reviewer = {
    url: REVIEWER_URL,
    extension: [
      { url: 'wasHumanReviewedFlag', valueBoolean: true },
      { url: 'reviewerNPI', valueIdentifier: { system: 'http://hl7.org/fhir/sid/us-npi', value: '1234567893' } },
      { url: 'reviewerSpecialty', valueCodeableConcept: { coding: [{ system: 'http://nucc.org/provider-taxonomy', code: '207X00000X' }] } },
    ],
  };
  const claimResponse = {
    resourceType: 'ClaimResponse',
    id: 'medical-pa-response-001',
    meta: { profile: [RESPONSE_PROFILE] },
    status: 'active',
    type: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/claim-type', code: 'professional' }] },
    use: 'preauthorization',
    patient: { reference: 'Patient/direct-member-123' },
    created: '2026-07-21T18:31:00Z',
    insurer: { reference: 'Organization/payer-1' },
    request: { reference: 'Claim/medical-pa-claim-001' },
    outcome: 'complete',
    extension: [reviewer],
    item: [{
      itemSequence: 1,
      adjudication: [{
        category: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/adjudication', code: 'submitted' }] },
        extension: [{
          url: REVIEW_ACTION_URL,
          extension: [{
            url: REVIEW_ACTION_CODE_URL,
            valueCodeableConcept: {
              coding: [{ system: 'https://codesystem.x12.org/005010/306', code: 'A3' }],
            },
          }],
        }],
      }],
    }],
  };
  const policy = {
    policy_id: 'policy:medical-pa:2026-07',
    policy_version: '2026-07',
    policy_digest: `sha256:${'a'.repeat(64)}`,
  };
  return {
    operation_id: 'medical-pa-review-op-001',
    pairwise_patient_ref: 'pairwise:medical-pa-member-7H3k9Q2p',
    claim,
    claim_response: claimResponse,
    policy,
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
        policy_digest: policy.policy_digest,
        claim_response_digest: digestPasValue(claimResponse),
      },
    },
  };
}

describe('Da Vinci PAS coverage source connector', () => {
  it('loads server-observed state by reference and projects only the minimized action pair', async () => {
    const load = vi.fn(async (reference: string) => {
      expect(reference).toBe('ClaimResponse/medical-pa-response-001');
      return serverObservedPas();
    });
    const connector = createDavinciPasCoverageSourceConnector({
      source_system_id: 'pas:payer-system-of-record',
      load,
    });

    const projected = await connector.project({
      record_id: 'pas:effect:medical-pa-response-001',
      source_record_ref: 'ClaimResponse/medical-pa-response-001',
      classification: 'effect',
    });

    expect(load).toHaveBeenCalledOnce();
    expect(projected.source_system_id).toBe('pas:payer-system-of-record');
    expect(projected.record).toEqual({
      record_id: 'pas:effect:medical-pa-response-001',
      caid: projected.binding.caid,
      action_digest: projected.binding.action_digest,
      classification: 'effect',
    });
    expect(JSON.stringify(projected.record)).not.toContain('direct-member-123');
    expect(JSON.stringify(projected.record)).not.toContain('secret-pa-001');
  });

  it('refuses an invalid server record instead of accepting a caller-computed action', async () => {
    const connector = createDavinciPasCoverageSourceConnector({
      source_system_id: 'pas:payer-system-of-record',
      load: async () => ({ ...serverObservedPas(), pairwise_patient_ref: 'not-pairwise' }),
    });
    await expect(connector.project({
      record_id: 'pas:effect:tampered',
      source_record_ref: 'ClaimResponse/tampered',
      classification: 'effect',
    })).rejects.toThrow(/server-observed PAS record refused/i);
  });

  it('requires a classification rule id for excluded and exception, and forbids it for effect', async () => {
    const load = vi.fn(async () => serverObservedPas());
    const connector = createDavinciPasCoverageSourceConnector({
      source_system_id: 'pas:payer-system-of-record',
      load,
    });
    await expect(connector.project({
      record_id: 'pas:excluded:medical-pa-response-001',
      source_record_ref: 'ClaimResponse/medical-pa-response-001',
      classification: 'excluded',
    })).rejects.toThrow(/request invalid/i);
    await expect(connector.project({
      record_id: 'pas:effect:medical-pa-response-001',
      source_record_ref: 'ClaimResponse/medical-pa-response-001',
      classification: 'effect',
      classification_rule_id: 'ep:coverage:excluded:out-of-scope-action-class:1',
    })).rejects.toThrow(/request invalid/i);
    const projected = await connector.project({
      record_id: 'pas:excluded:medical-pa-response-001',
      source_record_ref: 'ClaimResponse/medical-pa-response-001',
      classification: 'excluded',
      classification_rule_id: 'ep:coverage:excluded:out-of-scope-action-class:1',
    });
    expect(projected.record.classification_rule_id)
      .toBe('ep:coverage:excluded:out-of-scope-action-class:1');
  });

  it('rejects unsafe identifiers before calling the source loader', async () => {
    const load = vi.fn(async () => serverObservedPas());
    const connector = createDavinciPasCoverageSourceConnector({
      source_system_id: 'pas:payer-system-of-record',
      load,
    });
    await expect(connector.project({
      record_id: '../escape',
      source_record_ref: 'ClaimResponse/medical-pa-response-001',
      classification: 'effect',
    })).rejects.toThrow(/request invalid/i);
    expect(load).not.toHaveBeenCalled();
  });
});
