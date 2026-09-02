// SPDX-License-Identifier: Apache-2.0
//
// GET /api/signoff/[challengeId] used to look a challenge up by challenge_id
// alone and then accept a global `operator` / `signoff.view` permission with no
// tenant comparison, even though signoff_challenges carries tenant_id
// (supabase/migrations/072_tenant_scoping_cloud_tables.sql).

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  authenticateCloudRequest: vi.fn(),
  getGuardedClient: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
}));

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: mocks.authenticateCloudRequest,
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: mocks.getGuardedClient,
}));

vi.mock('../lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { GET } = await import('../app/api/signoff/[challengeId]/route.ts');

const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';

const ROWS = [
  {
    challenge_id: 'challenge-tenant-b',
    tenant_id: TENANT_B,
    accountable_actor_ref: 'entity-bob',
    status: 'challenge_issued',
  },
  {
    challenge_id: 'challenge-protocol',
    tenant_id: null,
    accountable_actor_ref: 'entity-alice',
    status: 'challenge_issued',
  },
];

function stubClient() {
  const filters: Record<string, unknown> = {};
  const builder: any = {
    select: () => builder,
    eq: (column: string, value: unknown) => {
      filters[column] = value;
      return builder;
    },
    maybeSingle: async () => ({
      data:
        ROWS.find((row) =>
          Object.entries(filters).every(
            ([column, value]) => (row as any)[column] === value,
          ),
        ) ?? null,
      error: null,
    }),
  };
  return { client: { from: () => builder }, filters };
}

function request(challengeId: string): any {
  return new Request(
    `https://www.emiliaprotocol.ai/api/signoff/${challengeId}`,
    { headers: { authorization: 'Bearer ep_live_caller' } },
  );
}

function context(challengeId: string) {
  return { params: Promise.resolve({ challengeId }) };
}

describe('GET /api/signoff/[challengeId] tenant scoping', () => {
  let filters: Record<string, unknown>;

  beforeEach(() => {
    vi.clearAllMocks();
    const stub = stubClient();
    filters = stub.filters;
    mocks.getGuardedClient.mockReturnValue(stub.client);
    mocks.authenticateCloudRequest.mockResolvedValue(null);
  });

  it('refuses tenant B challenges to a tenant A cloud key', async () => {
    mocks.authenticateRequest.mockResolvedValue({ error: 'no protocol key', status: 401 });
    mocks.authenticateCloudRequest.mockResolvedValue({
      tenantId: TENANT_A,
      environment: 'live',
      permissions: ['read'],
      keyId: 'key-a',
    });

    const response = await GET(request('challenge-tenant-b'), context('challenge-tenant-b'));

    expect(response.status).toBe(404);
    expect(filters.tenant_id).toBe(TENANT_A);
  });

  it('serves a tenant its own challenge through the tenant-scoped lookup', async () => {
    mocks.authenticateRequest.mockResolvedValue({ error: 'no protocol key', status: 401 });
    mocks.authenticateCloudRequest.mockResolvedValue({
      tenantId: TENANT_B,
      environment: 'live',
      permissions: ['read'],
      keyId: 'key-b',
    });

    const response = await GET(request('challenge-tenant-b'), context('challenge-tenant-b'));

    expect(response.status).toBe(200);
    expect(filters.tenant_id).toBe(TENANT_B);
    expect(await response.json()).toMatchObject({ challenge_id: 'challenge-tenant-b' });
  });

  it('refuses a tenant-owned challenge to an untenanted protocol operator key', async () => {
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'entity-carol' },
      permissions: ['operator', 'signoff.view'],
    });

    const response = await GET(request('challenge-tenant-b'), context('challenge-tenant-b'));

    expect(response.status).toBe(404);
  });

  it('still serves an untenanted challenge to a protocol operator key', async () => {
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'entity-carol' },
      permissions: ['signoff.view'],
    });

    const response = await GET(request('challenge-protocol'), context('challenge-protocol'));

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ challenge_id: 'challenge-protocol' });
  });

  it('still serves the accountable actor their own tenant-owned challenge', async () => {
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'entity-bob' },
      permissions: [],
    });

    const response = await GET(request('challenge-tenant-b'), context('challenge-tenant-b'));

    expect(response.status).toBe(200);
  });

  it('refuses an unauthenticated caller on both planes', async () => {
    mocks.authenticateRequest.mockResolvedValue({ error: 'no protocol key', status: 401 });

    const response = await GET(request('challenge-protocol'), context('challenge-protocol'));

    expect(response.status).toBe(401);
  });

  it('refuses a cloud key without the read permission', async () => {
    mocks.authenticateRequest.mockResolvedValue({ error: 'no protocol key', status: 401 });
    mocks.authenticateCloudRequest.mockResolvedValue({
      tenantId: TENANT_B,
      environment: 'live',
      permissions: [],
      keyId: 'key-b',
    });

    const response = await GET(request('challenge-tenant-b'), context('challenge-tenant-b'));

    expect(response.status).toBe(403);
  });
});
