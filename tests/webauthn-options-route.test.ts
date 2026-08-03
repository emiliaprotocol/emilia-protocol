// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderAction } from '../lib/wysiwys/render.js';
import { signoffConfirmationPhrase } from '../lib/signoff/ceremony-policy.js';

const mockLoadSignoffForSigning = vi.fn();
const mockLoadApproverCredentials = vi.fn();
const mockGenerateAuthenticationOptions = vi.fn();
const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
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
const CANONICAL_ACTION = {
  organization_id: 'org_1',
  actor_id: 'ep:entity:init',
  action_type: 'large_payment_release',
  target_resource_id: 'payment:123',
  policy_id: 'p1',
  amount: 82000,
  currency: 'USD',
  requested_at: '2026-06-23T12:00:00.000Z',
  risk_flags: ['amount_threshold'],
};
const ACTION_HASH = renderAction(CANONICAL_ACTION).action_hash;
const CONFIRMATION = signoffConfirmationPhrase(CANONICAL_ACTION.action_type, ACTION_HASH);

function req(body) {
  return { json: () => Promise.resolve(body ?? {}) };
}

function oversizedReq(bytes) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/signoffs/sig_x/webauthn-options', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blob: 'x'.repeat(bytes) }),
  });
}

function loaded(createdState) {
  return {
    requestEvent: { after_state: { approver_id: 'ap_controller' } },
    alreadyDecided: false,
    requestExpiresAt: '2999-01-01T00:00:00.000Z',
    initiatorId: 'ep:entity:init',
    actionHash: ACTION_HASH,
    organizationId: createdState?.organization_id || createdState?.canonical_action?.organization_id || 'org_1',
    createdState,
  };
}

describe('POST /api/v1/signoffs/:id/webauthn-options — WYSIWYS fail-closed', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
    mockLoadSignoffForSigning.mockReset();
    mockLoadApproverCredentials.mockReset();
    mockGenerateAuthenticationOptions.mockReset();
    mockGetGuardedClient.mockReturnValue({
      from: (table) => {
        if (table === 'signoff_metrics') {
          const query = {
            select: () => query,
            eq: () => query,
            maybeSingle: vi.fn().mockResolvedValue({
              data: { rendered_at: new Date(Date.now() - 10_000).toISOString() },
              error: null,
            }),
          };
          return query;
        }
        return { insert: vi.fn().mockResolvedValue({ error: null }) };
      },
    });
    mockLoadApproverCredentials.mockResolvedValue({
      credentials: [{ credential_id: 'cred_1', transports: ['internal'] }],
    });
    mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: 'mock-options' });
  });

  it('rejects oversized option requests before DB work', async () => {
    const res = await POST(oversizedReq(33 * 1024), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
    expect(mockLoadSignoffForSigning).not.toHaveBeenCalled();
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

  it('rejects an unknown terminal decision before issuing a challenge', async () => {
    const res = await POST(req({ approver_id: 'ap_controller', decision: 'maybe' }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(400);
    expect((await res.json()).type).toContain('invalid_decision');
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('binds display_hash into the Class-A signing context when canonical_action renders', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loaded({
      policy_id: 'p1',
      policy_hash: 'sha256:policy',
      required_assurance: 'A',
      organization_id: 'org_1',
      action_type: CANONICAL_ACTION.action_type,
      canonical_action: CANONICAL_ACTION,
    }));

    const res = await POST(req({ approver_id: 'ap_controller', confirmation_phrase: CONFIRMATION }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.context.display_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(body.context.decision).toBe('approved');
    expect(body.context.ceremony).toMatchObject({
      profile: 'EP-SIGNOFF-CEREMONY-v1',
      max_approvals: 5,
      window_seconds: 3600,
    });
    expect(mockGenerateAuthenticationOptions).toHaveBeenCalled();
  });

  it('refuses a Class-A approval whose action-specific phrase is missing', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loaded({
      policy_id: 'p1',
      policy_hash: 'sha256:policy',
      required_assurance: 'A',
      organization_id: 'org_1',
      action_type: CANONICAL_ACTION.action_type,
      canonical_action: CANONICAL_ACTION,
    }));

    const res = await POST(req({ approver_id: 'ap_controller' }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(409);
    expect((await res.json()).type).toContain('confirmation_phrase_mismatch');
    expect(mockGenerateAuthenticationOptions).not.toHaveBeenCalled();
  });

  it('refuses Class-A approval before the server-measured review interval elapses', async () => {
    mockGetGuardedClient.mockReturnValue({
      from: (table) => {
        if (table === 'signoff_metrics') {
          const query = {
            select: () => query,
            eq: () => query,
            maybeSingle: vi.fn().mockResolvedValue({
              data: { rendered_at: new Date().toISOString() },
              error: null,
            }),
          };
          return query;
        }
        return { insert: vi.fn().mockResolvedValue({ error: null }) };
      },
    });
    mockLoadSignoffForSigning.mockResolvedValue(loaded({
      policy_id: 'p1',
      policy_hash: 'sha256:policy',
      required_assurance: 'A',
      organization_id: 'org_1',
      action_type: CANONICAL_ACTION.action_type,
      canonical_action: CANONICAL_ACTION,
    }));

    const res = await POST(req({ approver_id: 'ap_controller', confirmation_phrase: CONFIRMATION }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(429);
    expect((await res.json()).type).toContain('minimum_review_time_required');
  });

  it('binds a rejection as canonical decision denied before the authenticator signs', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loaded({
      policy_id: 'p1',
      policy_hash: 'sha256:policy',
      required_assurance: 'C',
      organization_id: 'org_1',
    }));

    const res = await POST(req({ approver_id: 'ap_controller', decision: 'rejected' }), {
      params: Promise.resolve({ signoffId: SIGNOFF_ID }),
    });

    expect(res.status).toBe(200);
    expect((await res.json()).context.decision).toBe('denied');
  });
});
