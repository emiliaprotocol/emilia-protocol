// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateOperator: vi.fn(),
  rpc: vi.fn(),
}));

vi.mock('@/lib/operator-auth', () => ({
  authenticateOperator: mocks.authenticateOperator,
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({ rpc: mocks.rpc }),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/commit-keys/revoke/route.js');

function request(body) {
  return new Request('https://www.emiliaprotocol.ai/api/commit-keys/revoke', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer operator' },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.authenticateOperator.mockReturnValue({ valid: true, operator_id: 'operator-1' });
  mocks.rpc.mockResolvedValue({
    data: [{ kid: 'old-kid', revoked_at: '2026-07-15T12:00:00.000Z' }],
    error: null,
  });
});

describe('POST /api/commit-keys/revoke', () => {
  it('uses the revocation RPC that serializes against gate consumption', async () => {
    const response = await POST(request({ kid: 'old-kid', reason: 'compromised' }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      revoked: true,
      kid: 'old-kid',
      revoked_at: '2026-07-15T12:00:00.000Z',
      revoked_by: 'operator-1',
    });
    expect(mocks.rpc).toHaveBeenCalledWith('revoke_commit_key_atomic', {
      p_kid: 'old-kid',
      p_reason: 'compromised',
      p_revoked_by: 'operator-1',
    });
  });

  it('fails closed when revocation cannot be persisted', async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { code: 'PGRST000', message: 'down' } });

    const response = await POST(request({ kid: 'old-kid' }));
    expect(response.status).toBe(503);
  });

  it('fails closed when the RPC returns no durable record', async () => {
    mocks.rpc.mockResolvedValue({ data: [], error: null });

    const response = await POST(request({ kid: 'old-kid' }));
    expect(response.status).toBe(503);
  });
});
