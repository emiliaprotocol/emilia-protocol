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
vi.mock('@/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
}));

const { GET, POST } = await import('../app/api/cloud/authorities/policy-rollout/route.js');
const { POST: revoke } = await import(
  '../app/api/cloud/authorities/policy-rollout/[authorityId]/revoke/route.js'
);

const TENANT_ID = '33333333-3333-4333-8333-333333333333';
const AUTHORITY_ID = '55555555-5555-4555-8555-555555555555';

function request(body, token = 'ept_live_admin') {
  return new Request('https://example.test/api/cloud/authorities/policy-rollout', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function authed(permissions = ['admin']) {
  mockAuthenticateCloudRequest.mockResolvedValue({
    tenantId: TENANT_ID,
    environment: 'production',
    permissions,
    keyId: 'key-admin-1',
  });
}

function listClient(data = [], error = null) {
  const builder = {};
  for (const method of ['select', 'eq', 'is', 'lte', 'or', 'contains', 'in']) {
    builder[method] = vi.fn(() => builder);
  }
  builder.order = vi.fn(() => Promise.resolve({ data, error }));
  return { from: vi.fn(() => builder), builder };
}

describe('policy rollout authority administration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authed();
  });

  it('grants only through the tenant-bound audited RPC', async () => {
    const authority = {
      authority_id: AUTHORITY_ID,
      approver_id: 'approver-1',
      role: 'policy_admin',
      action_scopes: ['policy_rollout'],
      status: 'active',
    };
    const rpc = vi.fn(async () => ({ data: authority, error: null }));
    mockGetGuardedClient.mockReturnValue({ rpc });

    const res = await POST(request({
      approver_id: 'approver-1',
      role: 'policy_admin',
      valid_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      reason: 'Production change board delegation',
    }));

    expect(res.status).toBe(201);
    expect(rpc).toHaveBeenCalledWith('grant_policy_rollout_authority', expect.objectContaining({
      p_tenant_id: TENANT_ID,
      p_approver_id: 'approver-1',
      p_role: 'policy_admin',
      p_granted_by: 'key:key-admin-1',
      p_reason: 'Production change board delegation',
    }));
    expect((await res.json()).authority).toEqual(authority);
  });

  it('refuses unsupported roles and overlong grants before database work', async () => {
    mockGetGuardedClient.mockReturnValue({ rpc: vi.fn() });

    const role = await POST(request({
      approver_id: 'approver-1',
      role: 'super_admin',
      valid_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      reason: 'no',
    }));
    expect(role.status).toBe(400);

    const validity = await POST(request({
      approver_id: 'approver-1',
      role: 'policy_admin',
      valid_to: new Date(Date.now() + 400 * 24 * 60 * 60 * 1000).toISOString(),
      reason: 'no',
    }));
    expect(validity.status).toBe(400);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('maps missing Class-A enrollment and duplicate grants to safe conflicts', async () => {
    const validBody = {
      approver_id: 'approver-1',
      role: 'control_plane_approver',
      valid_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      reason: 'CAB delegation',
    };
    const rpc = vi.fn()
      .mockResolvedValueOnce({
        data: null,
        error: { code: '28000', message: 'policy_rollout_class_a_credential_required' },
      })
      .mockResolvedValueOnce({
        data: null,
        error: { code: '23505', message: 'policy_rollout_authority_already_active' },
      });
    mockGetGuardedClient.mockReturnValue({ rpc });

    expect((await POST(request(validBody))).status).toBe(409);
    expect((await POST(request(validBody))).status).toBe(409);
  });

  it('lists active tenant-scoped rollout authorities as a deployment preflight', async () => {
    const row = { authority_id: AUTHORITY_ID, subject_ref: 'approver-1' };
    const { from, builder } = listClient([row]);
    mockGetGuardedClient.mockReturnValue({ from });

    const res = await GET(new Request('https://example.test/api/cloud/authorities/policy-rollout', {
      headers: { authorization: 'Bearer ept_live_admin' },
    }));
    expect(res.status).toBe(200);
    expect(builder.eq).toHaveBeenCalledWith('organization_id', TENANT_ID);
    expect(builder.contains).toHaveBeenCalledWith('action_scopes', ['policy_rollout']);
    expect(await res.json()).toMatchObject({ ready: true, count: 1 });
  });

  it('revokes only the tenant authority through the audited RPC', async () => {
    const rpc = vi.fn(async () => ({
      data: { authority_id: AUTHORITY_ID, status: 'revoked' },
      error: null,
    }));
    mockGetGuardedClient.mockReturnValue({ rpc });

    const res = await revoke(request({ reason: 'Approver changed role' }), {
      params: Promise.resolve({ authorityId: AUTHORITY_ID }),
    });

    expect(res.status).toBe(200);
    expect(rpc).toHaveBeenCalledWith('revoke_policy_rollout_authority', {
      p_tenant_id: TENANT_ID,
      p_authority_id: AUTHORITY_ID,
      p_revoked_by: 'key:key-admin-1',
      p_reason: 'Approver changed role',
    });
  });

  it('requires admin permission for every authority operation', async () => {
    mockRequirePermission.mockImplementation(() => {
      const error = new Error('admin required');
      error.name = 'CloudAuthorizationError';
      throw error;
    });
    mockGetGuardedClient.mockReturnValue({});

    expect((await POST(request({}))).status).toBe(403);
    expect((await GET(new Request('https://example.test'))).status).toBe(403);
    expect((await revoke(request({ reason: 'x' }), {
      params: Promise.resolve({ authorityId: AUTHORITY_ID }),
    })).status).toBe(403);
  });

  it('rejects tenant-wide authority administration from a non-production key', async () => {
    mockAuthenticateCloudRequest.mockResolvedValue({
      tenantId: TENANT_ID,
      environment: 'staging',
      permissions: ['admin'],
      keyId: 'key-staging-1',
    });
    mockGetGuardedClient.mockReturnValue({ rpc: vi.fn() });

    expect((await POST(request({}))).status).toBe(403);
    expect((await GET(new Request('https://example.test'))).status).toBe(403);
    expect((await revoke(request({ reason: 'x' }), {
      params: Promise.resolve({ authorityId: AUTHORITY_ID }),
    })).status).toBe(403);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });
});
