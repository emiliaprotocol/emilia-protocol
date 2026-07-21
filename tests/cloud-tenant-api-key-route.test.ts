// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateRequest = vi.fn();
const mockCheckMemberRole = vi.fn();
const mockGenerateApiKey = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: vi.fn(),
}));

vi.mock('@/lib/cloud/tenant-manager.js', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    checkMemberRole: (...args) => mockCheckMemberRole(...args),
    generateApiKey: (...args) => mockGenerateApiKey(...args),
  };
});

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import(
  '../app/api/cloud/tenants/[tenantId]/api-keys/route.js'
);

function request(body) {
  return new Request('https://cloud.example/api/cloud/tenants/tenant-1/api-keys', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_owner',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function context(tenantId = 'tenant-1') {
  return { params: Promise.resolve({ tenantId }) };
}

describe('POST /api/cloud/tenants/:tenantId/api-keys', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthenticateRequest.mockResolvedValue({
      entity: { entity_id: 'user-1' },
      permissions: ['admin'],
    });
    mockCheckMemberRole.mockResolvedValue({ authorized: true, role: 'owner' });
    mockGenerateApiKey.mockResolvedValue({
      api_key: {
        key_id: 'key-1',
        key: `ept_live_${'a'.repeat(64)}`,
        permissions: ['policy_rollout'],
      },
    });
  });

  it.each(['owner', 'admin'])(
    'lets a tenant %s issue the default policy-rollout key',
    async (role) => {
      mockCheckMemberRole.mockResolvedValue({ authorized: true, role });

      const response = await POST(
        request({ name: 'Policy rollout orchestrator' }),
        context(),
      );
      const body = await response.json();

      expect(response.status).toBe(201);
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(body.api_key.key).toMatch(/^ept_live_/);
      expect(mockCheckMemberRole).toHaveBeenCalledWith('tenant-1', 'user-1', 'admin');
      expect(mockGenerateApiKey).toHaveBeenCalledWith(
        'tenant-1',
        'production',
        'Policy rollout orchestrator',
        ['policy_rollout'],
        expect.objectContaining({
          issuedBy: 'entity:user-1',
          expiresAt: expect.any(String),
        }),
      );
    },
  );

  it('allows an owner/admin to request a narrower validated grant', async () => {
    const response = await POST(
      request({
        name: 'Read-only audit',
        environment: 'staging',
        permissions: ['read', 'read'],
      }),
      context(),
    );

    expect(response.status).toBe(201);
    expect(mockGenerateApiKey).toHaveBeenCalledWith(
      'tenant-1',
      'staging',
      'Read-only audit',
      ['read'],
      expect.objectContaining({
        issuedBy: 'entity:user-1',
        expiresAt: expect.any(String),
      }),
    );
  });

  it('rejects a read/write EP key before it can mint tenant privilege', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { entity_id: 'user-1' },
      permissions: ['read', 'write'],
    });

    const response = await POST(
      request({ name: 'Escalated key', permissions: ['admin'] }),
      context(),
    );
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body.type).toContain('admin_permission_required');
    expect(mockCheckMemberRole).not.toHaveBeenCalled();
    expect(mockGenerateApiKey).not.toHaveBeenCalled();
  });

  it('rejects a non-admin tenant member even with an admin-capable EP key', async () => {
    mockCheckMemberRole.mockResolvedValue({ authorized: false, role: 'member' });

    const response = await POST(
      request({ name: 'Escalated key', permissions: ['admin'] }),
      context(),
    );
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body.type).toContain('tenant_admin_required');
    expect(mockGenerateApiKey).not.toHaveBeenCalled();
  });

  it('rejects unknown permissions without generating a key', async () => {
    const response = await POST(
      request({ name: 'Unknown grant', permissions: ['admin', 'superadmin'] }),
      context(),
    );
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.type).toContain('invalid_permissions');
    expect(mockGenerateApiKey).not.toHaveBeenCalled();
  });

  it('rejects unsupported environment scopes without generating a key', async () => {
    const response = await POST(
      request({ name: 'Wrong environment', environment: 'global' }),
      context(),
    );
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.type).toContain('invalid_environment');
    expect(mockGenerateApiKey).not.toHaveBeenCalled();
  });

  it('rejects permanent or overlong keys', async () => {
    for (const expires_in_days of [0, 91, null]) {
      const response = await POST(
        request({ name: 'Wrong expiry', expires_in_days }),
        context(),
      );
      expect(response.status).toBe(400);
    }
    expect(mockGenerateApiKey).not.toHaveBeenCalled();
  });
});
