// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockLoadSignoffForSigning = vi.fn();
const mockLoadApproverCredentials = vi.fn();
const mockGenerateAuthenticationOptions = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from: () => ({
      insert: vi.fn().mockResolvedValue({ error: null }),
    }),
  }),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/webauthn-signoff', () => ({
  loadSignoffForSigning: (...args) => mockLoadSignoffForSigning(...args),
  loadApproverCredentials: (...args) => mockLoadApproverCredentials(...args),
}));
vi.mock('@simplewebauthn/server', () => ({
  generateAuthenticationOptions: (...args) => mockGenerateAuthenticationOptions(...args),
}));

const { POST } = await import('../app/api/v1/signoffs/[signoffId]/webauthn-options/route.js');

const SIGNOFF_ID = `sig_${'a'.repeat(32)}`;

function req(body) {
  return { json: () => Promise.resolve(body ?? {}) };
}

function loaded(createdState) {
  return {
    requestEvent: { after_state: { approver_id: 'ap_controller' } },
    alreadyDecided: false,
    requestExpiresAt: '2999-01-01T00:00:00.000Z',
    initiatorId: 'ep:entity:init',
    actionHash: 'sha256:action',
    organizationId: createdState?.organization_id || createdState?.canonical_action?.organization_id || 'org_1',
    createdState,
  };
}

describe('POST /api/v1/signoffs/:id/webauthn-options — WYSIWYS fail-closed', () => {
  beforeEach(() => {
    mockLoadSignoffForSigning.mockReset();
    mockLoadApproverCredentials.mockReset();
    mockGenerateAuthenticationOptions.mockReset();
    mockLoadApproverCredentials.mockResolvedValue({
      credentials: [{ credential_id: 'cred_1', transports: ['internal'] }],
    });
    mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: 'mock-options' });
  });

  it('rejects a Class-A signoff when canonical_action is unavailable for display_hash binding', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loaded({
      policy_id: 'p1',
      policy_hash: 'sha256:policy',
      required_assurance: 'A',
      organization_id: 'org_1',
    }));

    const res = await POST(req({ approver_id: 'ap_controller' }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(409);
    expect((await res.json()).type).toContain('display_binding_required');
    expect(mockGenerateAuthenticationOptions).not.toHaveBeenCalled();
  });

  it('binds display_hash into the Class-A signing context when canonical_action renders', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loaded({
      policy_id: 'p1',
      policy_hash: 'sha256:policy',
      required_assurance: 'A',
      organization_id: 'org_1',
      canonical_action: {
        organization_id: 'org_1',
        actor_id: 'ep:entity:init',
        action_type: 'large_payment_release',
        target_resource_id: 'payment:123',
        policy_id: 'p1',
        amount: 82000,
        currency: 'USD',
        requested_at: '2026-06-23T12:00:00.000Z',
        risk_flags: ['amount_threshold'],
      },
    }));

    const res = await POST(req({ approver_id: 'ap_controller' }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.context.display_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(mockGenerateAuthenticationOptions).toHaveBeenCalled();
  });
});
