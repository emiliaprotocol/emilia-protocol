// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ rpc: vi.fn() }));

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => ({ rpc: mocks.rpc })),
}));

vi.mock('../lib/env.js', () => ({
  getSupabaseConfig: () => ({
    url: 'https://test.supabase.co',
    serviceRoleKey: 'test-service-key',
  }),
  getSiemConfig: () => ({ webhookUrl: null, disabled: true, isProduction: false }),
}));

const { authenticateRequest } = await import('../lib/supabase.js');
const { GET: getFeed } = await import('../app/api/feed/route.ts');

function authenticatedRequest(
  path: string,
  method = 'POST',
): Request {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method,
    headers: { authorization: 'Bearer ep_live_permission_floor' },
  });
}

function authenticateAs(
  permissions: string[],
  entity: Record<string, unknown> = { entity_id: 'entity-1', organization_id: 'org-1' },
): void {
  mocks.rpc.mockResolvedValue({
    data: { entity, permissions, auth_strength: 'password' },
    error: null,
  });
}

describe('authenticateRequest protocol mutation permission floor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('refuses a read-only key before a generic mutating route can run', async () => {
    authenticateAs(['read']);

    const auth = await authenticateRequest(authenticatedRequest('/api/delegations/create'));

    expect(auth).toMatchObject({
      status: 403,
      code: 'insufficient_permissions',
    });
    expect(auth.entity).toBeUndefined();
  });

  it('fails closed when a mutating request has no usable path', async () => {
    authenticateAs(['read']);
    const request = {
      method: 'PATCH',
      headers: new Headers({ authorization: 'Bearer ep_live_permission_floor' }),
    };

    const auth = await authenticateRequest(request);

    expect(auth).toMatchObject({
      status: 403,
      code: 'insufficient_permissions',
    });
  });

  it('does not let a server-marked observe pilot use stale write or admin grants', async () => {
    authenticateAs(['observe', 'read', 'write', 'admin'], {
      entity_id: 'pilot-1',
      organization_id: 'pilot-1',
      metadata: { pilot_sandbox: true, scope: 'observe' },
    });

    const auth = await authenticateRequest(authenticatedRequest('/api/trust/gate'));

    expect(auth).toMatchObject({
      status: 403,
      code: 'insufficient_permissions',
    });
  });

  it('admits an exact named capability and an explicit read-only POST', async () => {
    authenticateAs(['keys.rotate']);
    const named = await authenticateRequest(authenticatedRequest('/api/keys/rotate'));
    expect(named.entity).toMatchObject({ entity_id: 'entity-1' });

    authenticateAs(['read']);
    const readOnly = await authenticateRequest(authenticatedRequest('/api/trust/evaluate'));
    expect(readOnly.entity).toMatchObject({ entity_id: 'entity-1' });
  });

  it('admits an explicit observe capability only on a marked pilot precheck', async () => {
    authenticateAs(['observe'], {
      entity_id: 'pilot-1',
      organization_id: 'pilot-1',
      metadata: { pilot_sandbox: true, scope: 'observe' },
    });

    const auth = await authenticateRequest(authenticatedRequest(
      '/api/v1/adapters/fin/payment-release/precheck',
    ));

    expect(auth.entity).toMatchObject({ entity_id: 'pilot-1' });
  });

  it('refuses a minted observe identity at an authenticated directory route before its query runs', async () => {
    authenticateAs(['observe', 'read', 'write', 'admin'], {
      entity_id: 'pilot-1',
      organization_id: 'pilot-1',
      metadata: { pilot_sandbox: true, scope: 'observe' },
    });

    const response = await getFeed(authenticatedRequest('/api/feed', 'GET') as any);
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body.type).toContain('insufficient_permissions');
  });

  it('admits the same minted observe identity only at its actor-scoped report read', async () => {
    authenticateAs(['observe'], {
      entity_id: 'pilot-1',
      organization_id: 'pilot-1',
      metadata: { pilot_sandbox: true, scope: 'observe' },
    });

    const auth = await authenticateRequest(authenticatedRequest(
      '/api/pilot/sandbox/report',
      'GET',
    ));

    expect(auth.entity).toMatchObject({ entity_id: 'pilot-1' });
  });
});
