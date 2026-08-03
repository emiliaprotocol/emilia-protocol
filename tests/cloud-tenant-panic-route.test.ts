// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateRequest = vi.fn();
const mockCheckMemberRole = vi.fn();
const mockPanicTenant = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: vi.fn(),
}));
vi.mock('@/lib/cloud/tenant-manager.js', () => ({
  checkMemberRole: (...args) => mockCheckMemberRole(...args),
  panicTenant: (...args) => mockPanicTenant(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/cloud/tenants/[tenantId]/panic/route.js');

const TENANT = '11111111-1111-4111-8111-111111111111';

function request(body: Record<string, any>) {
  return new Request(`https://cloud.example/api/cloud/tenants/${TENANT}/panic`, {
    method: 'POST',
    headers: { authorization: 'Bearer ep_live_owner', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const context = { params: Promise.resolve({ tenantId: TENANT }) };

describe('POST /api/cloud/tenants/:tenantId/panic', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthenticateRequest.mockResolvedValue({
      entity: { entity_id: 'user-1' },
      permissions: ['admin'],
    });
    mockCheckMemberRole.mockResolvedValue({ authorized: true, role: 'owner' });
    mockPanicTenant.mockResolvedValue({
      control: { tenant_id: TENANT, status: 'suspended', epoch: 3 },
    });
  });

  it('requires an exact typed confirmation and atomically suspends the tenant', async () => {
    const response = await POST(request({
      confirmation: `SUSPEND ${TENANT}`,
      reason: 'Suspected agent credential compromise',
    }), context);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toMatchObject({ status: 'suspended', epoch: 3 });
    expect(mockPanicTenant).toHaveBeenCalledWith(
      TENANT,
      'entity:user-1',
      'Suspected agent credential compromise',
    );
  });

  it('refuses a weak confirmation without touching control state', async () => {
    const response = await POST(request({ confirmation: 'SUSPEND', reason: 'compromise' }), context);
    expect(response.status).toBe(400);
    expect((await response.json()).type).toContain('panic_confirmation_required');
    expect(mockPanicTenant).not.toHaveBeenCalled();
  });

  it('requires both admin credential scope and tenant admin membership', async () => {
    mockAuthenticateRequest.mockResolvedValue({ entity: { entity_id: 'user-1' }, permissions: ['read'] });
    let response = await POST(request({ confirmation: `SUSPEND ${TENANT}`, reason: 'compromise' }), context);
    expect(response.status).toBe(403);
    mockAuthenticateRequest.mockResolvedValue({ entity: { entity_id: 'user-1' }, permissions: ['admin'] });
    mockCheckMemberRole.mockResolvedValue({ authorized: false, role: 'member' });
    response = await POST(request({ confirmation: `SUSPEND ${TENANT}`, reason: 'compromise' }), context);
    expect(response.status).toBe(403);
    expect(mockPanicTenant).not.toHaveBeenCalled();
  });
});
