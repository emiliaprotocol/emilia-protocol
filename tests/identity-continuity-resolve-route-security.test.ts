// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  resolveContinuity: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
}));

vi.mock('@/lib/ep-ix', () => ({
  resolveContinuity: mocks.resolveContinuity,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/identity/continuity/resolve/route.ts');

function request(body: unknown): Request {
  return new Request('https://www.emiliaprotocol.ai/api/identity/continuity/resolve', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_test',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

describe('POST /api/identity/continuity/resolve identity boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.resolveContinuity.mockResolvedValue({
      continuity_id: 'ep_ix_claim',
      decision: 'approved_full',
      resolved_at: '2026-08-26T12:00:00.000Z',
    });
  });

  it.each([
    { entity: undefined },
    { entity: null },
    { entity: '' },
    { entity: {} },
    { entity: { entity_id: '   ' } },
  ])('refuses dispute.review authority without a source-derived entity identity', async (projection) => {
    mocks.authenticateRequest.mockResolvedValue({
      ...projection,
      permissions: ['dispute.review'],
    });

    const response = await POST(request({
      continuity_id: 'ep_ix_claim',
      decision: 'approved_full',
      operator_id: 'caller-supplied-fallback',
    }) as any);

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      detail: expect.stringMatching(/authenticated entity identity/i),
    });
    expect(mocks.resolveContinuity).not.toHaveBeenCalled();
  });

  it('uses the authenticated entity identity and ignores a body-supplied operator', async () => {
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'reviewer-entity' },
      permissions: ['dispute.review'],
    });

    const response = await POST(request({
      continuity_id: 'ep_ix_claim',
      decision: 'approved_full',
      reasoning: ['verified'],
      operator_id: 'impersonated-operator',
    }) as any);

    expect(response.status).toBe(200);
    expect(mocks.resolveContinuity).toHaveBeenCalledWith(
      'ep_ix_claim',
      'approved_full',
      ['verified'],
      'reviewer-entity',
    );
  });
});
