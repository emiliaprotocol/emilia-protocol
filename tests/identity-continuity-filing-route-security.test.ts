// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  fileContinuityClaim: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
}));

vi.mock('@/lib/ep-ix', () => ({
  fileContinuityClaim: mocks.fileContinuityClaim,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/identity/continuity/route.ts');

function request(body: unknown): Request {
  return new Request('https://www.emiliaprotocol.ai/api/identity/continuity', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_test',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

const filing = {
  principal_id: 'subject-principal',
  old_entity_id: 'old-endpoint',
  new_entity_id: 'new-endpoint',
  reason: 'key_rotation',
};

describe('POST /api/identity/continuity actor binding', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.fileContinuityClaim.mockResolvedValue({
      continuity: { continuity_id: 'ep_ix_claim', status: 'pending' },
      challenge_deadline: '2026-09-02T00:00:00.000Z',
      expires_at: '2026-09-25T00:00:00.000Z',
    });
  });

  it.each([
    { entity: undefined },
    { entity: null },
    { entity: '' },
    { entity: {} },
    { entity: { entity_id: '   ' } },
  ])('refuses filing when authentication has no entity identity', async (projection) => {
    mocks.authenticateRequest.mockResolvedValue(projection);

    const response = await POST(request({ ...filing, actor_entity_id: 'body-actor' }) as any);

    expect(response.status).toBe(403);
    expect(mocks.fileContinuityClaim).not.toHaveBeenCalled();
  });

  it('passes actor and subject separately and never forwards a body actor', async () => {
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'authenticated-delegate' },
    });

    const response = await POST(request({
      ...filing,
      actor_entity_id: 'impersonated-actor',
      transfer_budget: 0.5,
    }) as any);

    expect(response.status).toBe(201);
    expect(mocks.fileContinuityClaim).toHaveBeenCalledWith({
      ...filing,
      continuity_mode: undefined,
      proofs: undefined,
      transfer_budget: 0.5,
    }, 'authenticated-delegate');
  });
});
