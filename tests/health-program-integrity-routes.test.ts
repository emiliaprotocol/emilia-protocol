// SPDX-License-Identifier: Apache-2.0
/**
 * Focused HTTP contract for the PHI-free hospice program-integrity adapters.
 *
 * The engine is intentionally module-mocked here because the engine lands in
 * a parallel worktree. The mock follows the agreed exported interface:
 * createProgramIntegrityEngine({ prepare, precheck, reconcile }).
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  createProgramIntegrityEngine: vi.fn(),
  engine: {
    prepare: vi.fn(),
    precheck: vi.fn(),
    reconcile: vi.fn(),
  },
  logger: {
    warn: vi.fn(),
    info: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mocks.authenticateRequest(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: mocks.logger,
}));

vi.mock('../lib/health/program-integrity.js', () => ({
  createProgramIntegrityEngine: (...args) => mocks.createProgramIntegrityEngine(...args),
}));

import { POST as precheck } from '../app/api/v1/adapters/health/hospice-claim/precheck/route.ts';
import { POST as reconcile } from '../app/api/v1/adapters/health/hospice-claim/reconcile/route.ts';

const CAID = `caid:${'a'.repeat(64)}`;
const DIGEST = (digit) => `sha256:${digit.repeat(64)}`;

const ACTION = Object.freeze({
  '@version': 'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1',
  profile_id: 'medi-cal.hospice-integrity.v1',
  action_type: 'health.medi-cal.hospice-claim-payment.1',
  organization_id: 'org:one',
  provider_npi: '1234567890',
  member_ref: `member:sha256:${'1'.repeat(64)}`,
  service_period_start: '2026-07-01',
  service_period_end: '2026-07-15',
  authorization_form_digest: DIGEST('2'),
  amount: '1250.00',
  currency: 'USD',
  payment_destination_digest: DIGEST('3'),
  reviewer_id: 'reviewer:integrity-17',
  authority_proof_digest: DIGEST('4'),
  policy_id: 'policy:dhcs-hospice-payment',
  policy_version: 1,
  policy_hash: DIGEST('5'),
});

const AUTHORIZATION = Object.freeze({
  '@version': 'EP-HEALTH-PROGRAM-INTEGRITY-AUTHORIZATION-v1',
  reviewer_id: 'reviewer:integrity-17',
  organization_id: 'org:one',
  action_caid: CAID,
  authorization_evidence_digest: DIGEST('6'),
});

function providerEvidence(over = {}) {
  return {
    '@version': 'EP-HEALTH-PROGRAM-INTEGRITY-PROVIDER-EVIDENCE-v1',
    provider_id: 'medi-cal-claims-sandbox',
    environment: 'sandbox',
    operation_id: 'health-op-1',
    action_caid: CAID,
    idempotency_key: 'health-idem-1',
    outcome: 'executed',
    observed_at: '2026-07-19T22:00:00.000Z',
    signature: {
      algorithm: 'Ed25519',
      key_id: 'medi-cal-sandbox-2026-01',
      value: 'signed-provider-evidence',
    },
    ...over,
  };
}

function body(over = {}) {
  return {
    organization_id: 'org:one',
    action: structuredClone(ACTION),
    authorization: structuredClone(AUTHORIZATION),
    ...over,
  };
}

function reconcileBody(over = {}) {
  return {
    organization_id: 'org:one',
    operation_id: 'health-op-1',
    evidence: providerEvidence(),
    ...over,
  };
}

function request(path, payload, { authorization = 'Bearer ep_live_test' } = {}) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: {
      authorization,
      'content-type': 'application/json',
    },
    body: typeof payload === 'string' ? payload : JSON.stringify(payload),
  });
}

async function responseBody(response) {
  return response.json();
}

describe('health hospice claim program-integrity routes', () => {
  beforeEach(() => {
    mocks.authenticateRequest.mockReset();
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'caller-1', organization_id: 'org:one' },
    });

    mocks.createProgramIntegrityEngine.mockReset();
    mocks.createProgramIntegrityEngine.mockReturnValue(mocks.engine);
    mocks.engine.prepare.mockReset().mockResolvedValue({
      ok: true,
      action_caid: CAID,
      requirements: ['engine_requirement'],
      evidence_summary: {
        status: 'satisfied',
        patient_name: 'SHOULD NEVER LEAVE THE ENGINE',
        authorization_status: 'verified',
      },
    });
    mocks.engine.precheck.mockReset().mockResolvedValue({
      ok: true,
      decision: 'READY',
      action_caid: CAID,
      operation_id: 'health-op-1',
      idempotency_key: 'health-idem-1',
      evidence_summary: {
        status: 'satisfied',
        authority_status: 'verified',
      },
    });
    mocks.engine.reconcile.mockReset().mockResolvedValue({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      action_caid: CAID,
      idempotent: false,
      provider_effect_reference: 'must-not-be-reflected',
    });
  });

  it('rejects malformed JSON before calling the engine', async () => {
    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      '{not-json',
    ));

    expect(response.status).toBe(400);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await responseBody(response)).toMatchObject({ type: expect.stringContaining('invalid_json') });
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it('rejects malformed action input without weakening validation', async () => {
    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ action: {} }),
    ));

    expect(response.status).toBe(400);
    expect(await responseBody(response)).toMatchObject({
      type: expect.stringContaining('missing_action_profile_id'),
    });
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it.each([
    'health.medi_cal.hospice_claim_payment.1',
    'health.medi-cal.hospice-claim-payment',
  ])('rejects unsupported exact action type %s', async (actionType) => {
    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ action: { ...structuredClone(ACTION), action_type: actionType } }),
    ));

    expect(response.status).toBe(400);
    expect(await responseBody(response)).toMatchObject({
      type: expect.stringContaining('unsupported_action_profile'),
    });
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it('rejects an unauthenticated caller', async () => {
    mocks.authenticateRequest.mockResolvedValue({ error: 'invalid key', status: 401 });

    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body(),
    ));

    expect(response.status).toBe(401);
    expect(await responseBody(response)).toMatchObject({
      type: expect.stringContaining('unauthorized'),
      detail: 'Authentication is required',
    });
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it('rejects missing tenant binding and cross-tenant actions', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({ entity: { entity_id: 'unbound-caller' } });
    const missingTenant = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ organization_id: undefined }),
    ));
    expect(missingTenant.status).toBe(403);
    expect(await responseBody(missingTenant)).toMatchObject({
      type: expect.stringContaining('entity_not_org_bound'),
    });

    const crossTenant = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ action: { ...structuredClone(ACTION), organization_id: 'org:two' } }),
    ));
    expect(crossTenant.status).toBe(403);
    expect(await responseBody(crossTenant)).toMatchObject({
      type: expect.stringContaining('organization_mismatch'),
    });
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it('returns a CAID, requirements, and a safe evidence summary for an approved precheck', async () => {
    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body(),
    ));
    const result = await responseBody(response);

    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(result).toMatchObject({
      ok: true,
      decision: 'READY',
      caid: CAID,
      action_caid: CAID,
      operation_id: 'health-op-1',
      idempotency_key: 'health-idem-1',
      requirements: ['engine_requirement'],
      evidence_summary: {
        profile_id: 'medi-cal.hospice-integrity.v1',
        raw_evidence_included: false,
        phi_free_projection: true,
        authorization_present: true,
        authority_status: 'verified',
      },
    });
    expect(JSON.stringify(result)).not.toContain('SHOULD NEVER LEAVE THE ENGINE');
    expect(mocks.createProgramIntegrityEngine).toHaveBeenCalledWith(expect.objectContaining({
      profile_id: 'medi-cal.hospice-integrity.v1',
      action_type: 'health.medi-cal.hospice-claim-payment.1',
    }));
    expect(mocks.engine.prepare).toHaveBeenCalledWith(expect.objectContaining({
      action: expect.objectContaining({ organization_id: 'org:one' }),
    }));
  });

  it('returns a blocked decision without presenting it as authorization', async () => {
    mocks.engine.precheck.mockResolvedValue({
      ok: false,
      decision: 'REFUSED',
      reason: 'reviewer_authority_unsatisfied',
      action_caid: CAID,
      evidence_summary: { status: 'unsatisfied', authority_status: 'missing' },
    });

    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body(),
    ));
    const result = await responseBody(response);

    expect(response.status).toBe(422);
    expect(result).toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'reviewer_authority_unsatisfied',
      caid: CAID,
      reconciliation_required: false,
    });
    expect(result).not.toHaveProperty('authorization');
    expect(result).not.toHaveProperty('action');
  });

  it('rejects caller-side fail-open downgrade flags', async () => {
    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ action: { ...structuredClone(ACTION), fail_open: true } }),
    ));

    expect(response.status).toBe(422);
    expect(await responseBody(response)).toMatchObject({
      type: expect.stringContaining('runtime_downgrade_refused'),
    });
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it('requires authenticated provider evidence for reconciliation', async () => {
    const response = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({ evidence: undefined }),
    ));

    expect(response.status).toBe(400);
    expect(await responseBody(response)).toMatchObject({
      type: expect.stringContaining('missing_provider_evidence'),
    });
    expect(mocks.engine.reconcile).not.toHaveBeenCalled();
  });

  it('rejects unsigned or mismatched provider evidence before success can be returned', async () => {
    const unsigned = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({ evidence: providerEvidence({ signature: undefined }) }),
    ));
    expect(unsigned.status).toBe(400);

    const mismatched = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({ evidence: providerEvidence({ operation_id: 'health-op-other' }) }),
    ));
    expect(mismatched.status).toBe(400);
    expect(mocks.engine.reconcile).not.toHaveBeenCalled();
  });

  it('keeps replay and indeterminate refusal states non-successful', async () => {
    mocks.engine.reconcile.mockResolvedValue({
      ok: false,
      decision: 'REFUSED',
      reason: 'replay_refused',
      previous_decision: 'INDETERMINATE',
      action_caid: CAID,
    });

    const response = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody(),
    ));
    const result = await responseBody(response);

    expect(response.status).toBe(409);
    expect(result).toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'replay_refused',
      previous_decision: 'INDETERMINATE',
      reconciliation_required: true,
      provider_evidence_verified: false,
    });
    expect(result).not.toHaveProperty('provider_effect_reference');
  });

  it('returns authenticated reconciliation success without exposing provider response data', async () => {
    const response = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody(),
    ));
    const result = await responseBody(response);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(result).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      operation_id: 'health-op-1',
      action_caid: CAID,
      reconciliation_required: false,
      provider_evidence_verified: true,
      idempotent: false,
    });
    expect(JSON.stringify(result)).not.toContain('must-not-be-reflected');
  });

  it('returns reconciliation failure and never upgrades it to success', async () => {
    mocks.engine.reconcile.mockResolvedValue({
      ok: false,
      decision: 'REFUSED',
      reason: 'provider_evidence_invalid',
      previous_decision: 'INDETERMINATE',
      action_caid: CAID,
    });

    const response = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody(),
    ));
    const result = await responseBody(response);

    expect(response.status).toBe(422);
    expect(result).toMatchObject({
      ok: false,
      decision: 'REFUSED',
      reason: 'provider_evidence_invalid',
      provider_evidence_verified: false,
    });
    expect(result).not.toHaveProperty('success');
  });

  it('rejects missing or cross-tenant reconciliation context', async () => {
    const missing = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({ organization_id: undefined }),
    ));
    expect(missing.status).toBe(400);

    const crossTenant = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({ organization_id: 'org:two' }),
    ));
    expect(crossTenant.status).toBe(403);
    expect(await responseBody(crossTenant)).toMatchObject({
      type: expect.stringContaining('organization_mismatch'),
    });
    expect(mocks.engine.reconcile).not.toHaveBeenCalled();
  });

  it('refuses PHI fields and does not leak them through the route', async () => {
    const response = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ action: { ...structuredClone(ACTION), diagnosis: 'secret diagnosis' } }),
    ));
    const raw = await response.text();

    expect(response.status).toBe(400);
    expect(raw).not.toContain('secret diagnosis');
    expect(raw).toContain('prohibited_phi');
    expect(mocks.engine.prepare).not.toHaveBeenCalled();
  });

  it('refuses nested PHI fields in authorization and reconciliation evidence', async () => {
    const authorizationResponse = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({ authorization: { ...AUTHORIZATION, context: { diagnosis: 'secret diagnosis' } } }),
    ));
    const authorizationRaw = await authorizationResponse.text();
    expect(authorizationResponse.status).toBe(400);
    expect(authorizationRaw).toContain('prohibited_phi');
    expect(authorizationRaw).not.toContain('secret diagnosis');

    const evidenceResponse = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({ evidence: providerEvidence({ context: { clinical_note: 'secret note' } }) }),
    ));
    const evidenceRaw = await evidenceResponse.text();
    expect(evidenceResponse.status).toBe(400);
    expect(evidenceRaw).toContain('prohibited_phi');
    expect(evidenceRaw).not.toContain('secret note');
  });

  it('refuses PHI nested inside authorization and provider-evidence arrays', async () => {
    const authorizationResponse = await precheck(request(
      '/api/v1/adapters/health/hospice-claim/precheck',
      body({
        authorization: {
          ...AUTHORIZATION,
          context: [{ controls: [{ diagnosis: 'array diagnosis' }] }],
        },
      }),
    ));
    const authorizationRaw = await authorizationResponse.text();
    expect(authorizationResponse.status).toBe(400);
    expect(authorizationRaw).toContain('prohibited_phi');
    expect(authorizationRaw).not.toContain('array diagnosis');

    const evidenceResponse = await reconcile(request(
      '/api/v1/adapters/health/hospice-claim/reconcile',
      reconcileBody({
        evidence: providerEvidence({
          context: [{ controls: [{ clinical_note: 'array note' }] }],
        }),
      }),
    ));
    const evidenceRaw = await evidenceResponse.text();
    expect(evidenceResponse.status).toBe(400);
    expect(evidenceRaw).toContain('prohibited_phi');
    expect(evidenceRaw).not.toContain('array note');
    expect(mocks.engine.reconcile).not.toHaveBeenCalled();
  });
});
