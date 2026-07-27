// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import {
  DAVINCI_PAS_ACTION_TYPE,
  DAVINCI_PAS_IG_VERSION,
  DAVINCI_PAS_MEDICAL_RAIL,
  canonicalizeDavinciPasMaterialAction,
} from '../lib/health/davinci-pas-binding.js';
import { createDavinciPasReviewHandler } from '../app/api/v1/adapters/health/davinci-pas/review/route.js';

const TENANT = 'org:pas-security-test';
const DIGEST = `sha256:${'a'.repeat(64)}`;

function materialAction(): Record<string, unknown> {
  return {
    action_type: DAVINCI_PAS_ACTION_TYPE,
    operation_id: 'operation:pas-security-test',
    rail: DAVINCI_PAS_MEDICAL_RAIL,
    ig_version: DAVINCI_PAS_IG_VERSION,
    pairwise_patient_ref: 'pairwise:pas-security-member-7H3k9Q2p',
    claim_digest: DIGEST,
    claim_identifier_digest: DIGEST,
    claim_response_digest: DIGEST,
    request_reference_digest: DIGEST,
    service_request_digest: DIGEST,
    decision_digest: DIGEST,
    decision_outcome: 'approved',
    fhir_outcome: 'complete',
    policy_id: 'policy:pas-security-test',
    policy_version: '2026-07',
    policy_digest: DIGEST,
  };
}

function request(body: unknown): Request {
  return new Request(
    'https://www.emiliaprotocol.ai/api/v1/adapters/health/davinci-pas/review',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

function prepareBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organization_id: TENANT,
    operation: 'prepare',
    proposal_id: 'proposal:pas-security-test',
    operation_id: 'operation:pas-security-test',
    pas_context_ref: 'pas-context:security-test',
    ...extra,
  };
}

describe('Da Vinci PAS hostile ingress regressions', () => {
  it.each([
    ['unknown material field', { debug: true }],
    ['raw Claim alias', { rawClaim: { resourceType: 'Claim' } }],
    ['direct patient alias', { patient_name: 'Alice Example' }],
  ])('fails closed when the material action contains %s', (_label, extra) => {
    expect(() => canonicalizeDavinciPasMaterialAction({
      ...materialAction(),
      ...extra,
    })).toThrow();
  });

  it('fails closed when a required portable material field is missing', () => {
    const action = materialAction();
    delete action.service_request_digest;

    expect(() => canonicalizeDavinciPasMaterialAction(action)).toThrow();
  });

  it.each([
    ['medical_record_snapshot', { subject_full_name: 'Alice Example', member_number: 'MRN-123' }],
    ['member_demographics', { legal_name: 'Alice Example', street_address: '1 Main St' }],
    ['debug_context', { trace: 'uncontracted input' }],
  ])('rejects uncontracted top-level request field %s before loading PAS context', async (field, value) => {
    const prepare = vi.fn(async () => ({ ok: true, decision: 'APPROVAL_REQUIRED' }));
    const resolveControl = vi.fn(async () => ({ prepare }) as any);
    const loadPasContext = vi.fn(async () => ({}));
    const handler = createDavinciPasReviewHandler({
      authenticate: async () => ({
        entity: { entity_id: 'actor:pas-security-test', organization_id: TENANT },
      }),
      resolve_control: resolveControl,
      load_pas_context: loadPasContext,
    });

    const response = await handler(request(prepareBody({ [field]: value })) as any);
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.type).toContain('unknown_request_field');
    expect(resolveControl).not.toHaveBeenCalled();
    expect(loadPasContext).not.toHaveBeenCalled();
    expect(prepare).not.toHaveBeenCalled();
  });
});
