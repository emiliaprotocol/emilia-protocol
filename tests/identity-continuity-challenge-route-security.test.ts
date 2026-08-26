// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  challengeContinuity: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
}));

vi.mock('@/lib/ep-ix', () => ({
  challengeContinuity: mocks.challengeContinuity,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/identity/continuity/challenge/route.ts');

function request(body: unknown): Request {
  return new Request('https://www.emiliaprotocol.ai/api/identity/continuity/challenge', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_test',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

describe('POST /api/identity/continuity/challenge security boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'principal-self' },
      permissions: ['write'],
    });
    mocks.challengeContinuity.mockImplementation(async (input: any) => (
      input.challenger_id === 'principal-self'
        ? { error: 'Principal cannot challenge their own continuity claim', status: 403 }
        : { challenge: { challenge_id: 'should-not-be-issued' } }
    ));
  });

  it('STRIX-20: cannot launder a self-challenge through a body-supplied challenger identity', async () => {
    const response = await POST(request({
      continuity_id: 'ep_ix_self_claim',
      challenger_type: 'operator',
      challenger_id: 'unrelated-entity-from-body',
      reason: 'attempt to contest my own claim',
    }) as any);

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      error: 'Principal cannot challenge their own continuity claim',
    });
    expect(mocks.challengeContinuity).toHaveBeenCalledWith(expect.objectContaining({
      continuity_id: 'ep_ix_self_claim',
      challenger_id: 'principal-self',
    }));
    expect(mocks.challengeContinuity.mock.calls[0][0]).not.toHaveProperty('challenger_type');
  });

  it('does not require or forward a caller-asserted challenger_type', async () => {
    mocks.challengeContinuity.mockResolvedValueOnce({
      challenge: { challenge_id: 'derived-role-challenge' },
    });

    const response = await POST(request({
      continuity_id: 'ep_ix_other_claim',
      reason: 'verified counterparty evidence',
      evidence: { receipt_id: 'ep_rcpt_1' },
    }) as any);

    expect(response.status).toBe(201);
    expect(mocks.challengeContinuity).toHaveBeenCalledWith({
      continuity_id: 'ep_ix_other_claim',
      challenger_id: 'principal-self',
      reason: 'verified counterparty evidence',
      evidence: { receipt_id: 'ep_rcpt_1' },
      enterprise_admin_authorized: false,
    });
  });

  it('derives enterprise-admin authority only from authenticated key permissions', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      entity: { entity_id: 'tenant-admin' },
      permissions: ['admin'],
    });
    mocks.challengeContinuity.mockResolvedValueOnce({
      challenge: { challenge_id: 'enterprise-admin-challenge' },
    });

    const response = await POST(request({
      continuity_id: 'ep_ix_other_claim',
      challenger_type: 'operator',
      reason: 'tenant governance review',
    }) as any);

    expect(response.status).toBe(201);
    expect(mocks.challengeContinuity).toHaveBeenCalledWith(expect.objectContaining({
      challenger_id: 'tenant-admin',
      enterprise_admin_authorized: true,
    }));
    expect(mocks.challengeContinuity.mock.calls[0][0]).not.toHaveProperty('challenger_type');
  });

  it.each([
    { entity: undefined },
    { entity: null },
    { entity: '' },
    { entity: {} },
    { entity: { entity_id: '   ' } },
  ])('fails closed before challenge RPC when authenticated identity is absent', async (projection) => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      ...projection,
      permissions: ['write'],
    });

    const response = await POST(request({
      continuity_id: 'ep_ix_claim',
      reason: 'caller tries to supply identity',
      challenger_id: 'body-identity',
    }) as any);

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      detail: expect.stringMatching(/authenticated entity identity/i),
    });
    expect(mocks.challengeContinuity).not.toHaveBeenCalled();
  });
});
