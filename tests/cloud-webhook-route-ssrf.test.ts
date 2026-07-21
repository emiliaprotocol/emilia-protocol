// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateCloudRequest = vi.fn();
const mockRequirePermission = vi.fn();
const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...args) => mockAuthenticateCloudRequest(...args),
}));

vi.mock('@/lib/cloud/authorize', () => ({
  requirePermission: (...args) => mockRequirePermission(...args),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { PUT } = await import('../app/api/cloud/webhooks/[endpointId]/route.js');

function req(body) {
  return new Request('https://cloud.example/api/cloud/webhooks/ep-1', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function makeClient() {
  const calls = { updates: [] };
  function builder() {
    const b = {
      select() { return b; },
      eq() { return b; },
      maybeSingle: vi.fn().mockResolvedValue({ data: { endpoint_id: 'ep-1' }, error: null }),
      update: vi.fn((payload) => {
        calls.updates.push(payload);
        return b;
      }),
      single: vi.fn().mockResolvedValue({ data: { endpoint_id: 'ep-1' }, error: null }),
    };
    return b;
  }
  return { client: { from: () => builder() }, calls };
}

describe('PUT /api/cloud/webhooks/:endpointId — SSRF hardening', () => {
  beforeEach(() => {
    mockAuthenticateCloudRequest.mockReset();
    mockRequirePermission.mockReset();
    mockGetGuardedClient.mockReset();
    mockAuthenticateCloudRequest.mockResolvedValue({ tenantId: 'tenant-1', permissions: ['write'] });
  });

  it('rejects private webhook URLs on update before storing them', async () => {
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await PUT(req({ url: 'http://127.0.0.1/internal', events: ['receipt.created'] }), {
      params: Promise.resolve({ endpointId: 'ep-1' }),
    });
    const body = await res.json();

    expect(res.status).toBe(422);
    expect(body.type).toContain('invalid_webhook_url');
    expect(calls.updates).toHaveLength(0);
  });
});
