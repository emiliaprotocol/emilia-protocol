// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ authenticateRequest: vi.fn() }));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mocks.authenticateRequest(...args),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from: () => ({
      insert: () => ({
        select: () => ({
          single: async () => ({ data: { id: 'token-1', created_at: 'now' }, error: null }),
        }),
      }),
    }),
  }),
}));

const SsoConnections = await import('../app/api/sso/connections/route.js');
const ScimToken = await import('../app/api/scim/v2/provisioning-token/route.js');

function request(method, path, body = {}) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
  });
}

describe('control-plane permission floors', () => {
  beforeEach(() => {
    mocks.authenticateRequest.mockReset();
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'tenant-a', organization_id: 'tenant-a' },
      permissions: ['read', 'write'],
    });
  });

  it('rejects ordinary API keys from SSO writes and reads', async () => {
    const post = await SsoConnections.POST(request('POST', '/api/sso/connections', { protocol: 'oidc' }));
    const get = await SsoConnections.GET(request('GET', '/api/sso/connections'));
    expect(post.status).toBe(403);
    expect(get.status).toBe(403);
  });

  it('rejects ordinary API keys from SCIM provisioning-token mint/list', async () => {
    const post = await ScimToken.POST(request('POST', '/api/scim/v2/provisioning-token'));
    const get = await ScimToken.GET(request('GET', '/api/scim/v2/provisioning-token'));
    expect(post.status).toBe(403);
    expect(get.status).toBe(403);
  });

  it('accepts the explicit control-plane capabilities', async () => {
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'tenant-a', organization_id: 'tenant-a' },
      permissions: ['sso.manage', 'scim.manage'],
    });
    // The permission floor is the first gate; mocked downstream stores are not
    // needed to prove that a correctly-scoped key passes it.
    const sso = await SsoConnections.POST(request('POST', '/api/sso/connections', { protocol: 'invalid' }));
    const scim = await ScimToken.POST(request('POST', '/api/scim/v2/provisioning-token'));
    expect(sso.status).not.toBe(403);
    expect(scim.status).not.toBe(403);
  });
});
