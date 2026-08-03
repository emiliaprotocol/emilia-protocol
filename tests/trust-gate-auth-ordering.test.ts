// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  readLimitedJson: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
  getServiceClient: vi.fn(),
}));

vi.mock('@/lib/http/body-limit', () => ({ readLimitedJson: mocks.readLimitedJson }));

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: async () => ({ allowed: true, remaining: 10, reset: 60 }),
  getClientIP: () => '203.0.113.9',
}));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.readLimitedJson.mockResolvedValue({ ok: true, value: {} });
});

function request(body: string): Request {
  return new Request('https://ep.test/api/trust/gate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
}

describe('POST /api/trust/gate authentication ordering', () => {
  it('rejects an unauthenticated caller without reading the body', async () => {
    mocks.authenticateRequest.mockResolvedValue({ error: 'unauthorized' });
    const { POST } = await import('../app/api/trust/gate/route.js');

    const response = await POST(request(JSON.stringify({ entity_id: 'x'.repeat(50_000) })) as never);

    expect(response.status).toBe(401);
    expect(mocks.readLimitedJson).not.toHaveBeenCalled();
  });

  it('reads the body exactly once after authentication succeeds', async () => {
    mocks.authenticateRequest.mockResolvedValue({ entity: { entity_id: 'ep_caller', id: 'ep_caller' } });
    const { POST } = await import('../app/api/trust/gate/route.js');

    await POST(request(JSON.stringify({ entity_id: 'ep_target', action: 'payment.release' })) as never);

    expect(mocks.readLimitedJson).toHaveBeenCalledTimes(1);
  });
});
