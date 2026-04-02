import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock @/lib/supabase before importing modules under test
vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(),
}));

import {
  createTenant,
  getTenant,
  updateTenant,
  archiveTenant,
  inviteMember,
  listMembers,
  createEnvironment,
  listEnvironments,
  generateApiKey,
  listApiKeys,
  revokeApiKey,
  resolveApiKey,
  listTenantsForUser,
  checkMemberRole,
} from '../lib/cloud/tenant-manager.js';
import { getServiceClient } from '@/lib/supabase';

// ── Mock builder helpers ──────────────────────────────────────────────────────

/**
 * Returns a chainable mock that resolves with { data, error } at the end.
 * Supports: .from().insert/update/select/eq/is/order/maybeSingle/single/in
 */
function makeChain(resolved) {
  // Use plain functions (not vi.fn()) for chain methods to avoid vi.fn()'s
  // built-in thenable behaviour interfering with Promise resolution.
  const chain = {};
  ['select', 'insert', 'update', 'eq', 'is', 'in', 'order', 'limit'].forEach((m) => {
    chain[m] = vi.fn(() => chain);
  });
  chain.single = vi.fn(() => Promise.resolve(resolved));
  chain.maybeSingle = vi.fn(() => Promise.resolve(resolved));
  // Make the chain itself awaitable for queries that don't call .single()
  chain.then = (resolve, reject) => Promise.resolve(resolved).then(resolve, reject);
  return chain;
}

/**
 * Build a table-aware supabase mock.
 * tableMap: { tableName: chain | { data, error, count } }
 */
function makeSupabase(tableMap) {
  return {
    from: vi.fn((table) => {
      const entry = tableMap[table];
      if (!entry) return makeChain({ data: null, error: null });
      // If it already looks like a chain (has .select fn), return as-is
      if (typeof entry.select === 'function') return entry;
      // Otherwise wrap in a chain
      return makeChain(entry);
    }),
  };
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

const TENANT = {
  tenant_id: 'tenant-1',
  name: 'Acme Corp',
  slug: 'acme',
  plan: 'free',
  settings: {},
  status: 'active',
  created_at: '2024-01-01T00:00:00Z',
};

// ── createTenant ─────────────────────────────────────────────────────────────

describe('createTenant', () => {
  beforeEach(() => vi.clearAllMocks());

  it('creates a tenant and returns it on success', async () => {
    const envChain = makeChain({ data: {}, error: null });
    const memberChain = makeChain({ data: {}, error: null });
    const tenantChain = makeChain({ data: TENANT, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenants') return tenantChain;
        if (table === 'tenant_environments') return envChain;
        if (table === 'tenant_members') return memberChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await createTenant({ name: 'Acme', slug: 'acme', userRef: 'user-1' });
    expect(result.tenant).toEqual(TENANT);
    expect(result.error).toBeUndefined();
  });

  it('returns 409 on duplicate slug (code 23505)', async () => {
    const tenantChain = makeChain({ data: null, error: { code: '23505', message: 'duplicate' } });
    const supabase = { from: vi.fn(() => tenantChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await createTenant({ name: 'Acme', slug: 'acme' });
    expect(result.status).toBe(409);
    expect(result.error).toMatch(/slug already exists/i);
  });

  it('returns 500 on generic DB error', async () => {
    const tenantChain = makeChain({ data: null, error: { code: '42000', message: 'db error' } });
    const supabase = { from: vi.fn(() => tenantChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await createTenant({ name: 'Acme', slug: 'acme' });
    expect(result.status).toBe(500);
  });

  it('still returns tenant when environment insert fails', async () => {
    const tenantChain = makeChain({ data: TENANT, error: null });
    const envChain = makeChain({ data: null, error: { message: 'env error' } });
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenants') return tenantChain;
        if (table === 'tenant_environments') return envChain;
        return makeChain({ data: {}, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await createTenant({ name: 'Acme', slug: 'acme' });
    expect(result.tenant).toEqual(TENANT);
  });

  it('skips member insert when userRef is not provided', async () => {
    const memberChain = makeChain({ data: {}, error: null });
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenants') return makeChain({ data: TENANT, error: null });
        if (table === 'tenant_environments') return makeChain({ data: {}, error: null });
        if (table === 'tenant_members') return memberChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    await createTenant({ name: 'Acme', slug: 'acme' }); // no userRef
    expect(memberChain.insert).not.toHaveBeenCalled();
  });

  it('uses free plan by default', async () => {
    const tenantChain = makeChain({ data: TENANT, error: null });
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenants') return tenantChain;
        return makeChain({ data: {}, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    await createTenant({ name: 'Acme', slug: 'acme' });
    expect(tenantChain.insert).toHaveBeenCalledWith(
      expect.objectContaining({ plan: 'free' }),
    );
  });
});

// ── getTenant ─────────────────────────────────────────────────────────────────

describe('getTenant', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns tenant with environments and member count on success', async () => {
    const tenantChain = makeChain({ data: TENANT, error: null });
    const envChain = makeChain({ data: [{ environment_id: 'env-1', name: 'production' }], error: null });
    // count query — chain resolves with { count: 3 }
    const countChain = makeChain({ count: 3, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenants') return tenantChain;
        if (table === 'tenant_environments') return envChain;
        if (table === 'tenant_members') return countChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await getTenant('tenant-1');
    expect(result.tenant_id).toBe('tenant-1');
    expect(Array.isArray(result.environments)).toBe(true);
    expect(result.member_count).toBe(3);
  });

  it('returns 404 when tenant is not found', async () => {
    const tenantChain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => tenantChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await getTenant('nonexistent');
    expect(result.status).toBe(404);
    expect(result.error).toMatch(/not found/i);
  });

  it('returns 500 on DB error', async () => {
    const tenantChain = makeChain({ data: null, error: { message: 'db err' } });
    const supabase = { from: vi.fn(() => tenantChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await getTenant('tenant-1');
    expect(result.status).toBe(500);
  });

  it('returns empty arrays when environments are null', async () => {
    const tenantChain = makeChain({ data: TENANT, error: null });
    const envChain = makeChain({ data: null, error: null });
    const countChain = makeChain({ count: 0, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenants') return tenantChain;
        if (table === 'tenant_environments') return envChain;
        if (table === 'tenant_members') return countChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await getTenant('tenant-1');
    expect(result.environments).toEqual([]);
    expect(result.member_count).toBe(0);
  });
});

// ── updateTenant ──────────────────────────────────────────────────────────────

describe('updateTenant', () => {
  beforeEach(() => vi.clearAllMocks());

  it('updates and returns the tenant', async () => {
    const chain = makeChain({ data: { ...TENANT, name: 'New Name' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await updateTenant('tenant-1', { name: 'New Name' });
    expect(result.tenant.name).toBe('New Name');
  });

  it('returns 400 when no valid fields are provided', async () => {
    getServiceClient.mockReturnValue({ from: vi.fn() });

    const result = await updateTenant('tenant-1', { invalid_field: 'x' });
    expect(result.status).toBe(400);
    expect(result.error).toMatch(/no valid fields/i);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'db error' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await updateTenant('tenant-1', { name: 'X' });
    expect(result.status).toBe(500);
  });

  it('returns 404 when tenant not found or not active', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await updateTenant('tenant-1', { name: 'X' });
    expect(result.status).toBe(404);
  });

  it('allows updating plan and settings', async () => {
    const chain = makeChain({ data: { ...TENANT, plan: 'pro' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await updateTenant('tenant-1', { plan: 'pro', settings: { theme: 'dark' } });
    expect(result.tenant.plan).toBe('pro');
    // Only allowed fields should be passed
    expect(chain.update).toHaveBeenCalledWith(expect.objectContaining({ plan: 'pro' }));
  });
});

// ── archiveTenant ─────────────────────────────────────────────────────────────

describe('archiveTenant', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns archived tenant on success', async () => {
    const chain = makeChain({ data: { ...TENANT, status: 'archived' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await archiveTenant('tenant-1');
    expect(result.tenant.status).toBe('archived');
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await archiveTenant('tenant-1');
    expect(result.status).toBe(500);
  });

  it('returns 404 when not found or already archived', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await archiveTenant('tenant-1');
    expect(result.status).toBe(404);
    expect(result.error).toMatch(/already archived/i);
  });
});

// ── inviteMember ──────────────────────────────────────────────────────────────

describe('inviteMember', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns member on success', async () => {
    const member = { member_id: 'm-1', tenant_id: 'tenant-1', user_ref: 'user-2', role: 'member' };
    const chain = makeChain({ data: member, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await inviteMember('tenant-1', 'user-2');
    expect(result.member).toEqual(member);
  });

  it('returns 409 on duplicate membership', async () => {
    const chain = makeChain({ data: null, error: { code: '23505' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await inviteMember('tenant-1', 'user-2');
    expect(result.status).toBe(409);
  });

  it('returns 500 on other DB error', async () => {
    const chain = makeChain({ data: null, error: { code: '42000', message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await inviteMember('tenant-1', 'user-2');
    expect(result.status).toBe(500);
  });

  it('defaults role to member', async () => {
    const chain = makeChain({ data: { role: 'member' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    await inviteMember('tenant-1', 'user-2');
    expect(chain.insert).toHaveBeenCalledWith(
      expect.objectContaining({ role: 'member' }),
    );
  });
});

// ── listMembers ───────────────────────────────────────────────────────────────

describe('listMembers', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns members list on success', async () => {
    const members = [{ member_id: 'm-1', user_ref: 'u-1', role: 'owner' }];
    const chain = makeChain({ data: members, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listMembers('tenant-1');
    expect(result.members).toEqual(members);
  });

  it('returns empty array when no members', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listMembers('tenant-1');
    expect(result.members).toEqual([]);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listMembers('tenant-1');
    expect(result.status).toBe(500);
  });
});

// ── createEnvironment ─────────────────────────────────────────────────────────

describe('createEnvironment', () => {
  beforeEach(() => vi.clearAllMocks());

  it('creates and returns environment', async () => {
    const env = { environment_id: 'env-1', name: 'staging', config: {} };
    const chain = makeChain({ data: env, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await createEnvironment('tenant-1', 'staging');
    expect(result.environment).toEqual(env);
  });

  it('returns 409 on duplicate environment name', async () => {
    const chain = makeChain({ data: null, error: { code: '23505' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await createEnvironment('tenant-1', 'staging');
    expect(result.status).toBe(409);
    expect(result.error).toContain('staging');
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { code: '42000', message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await createEnvironment('tenant-1', 'staging');
    expect(result.status).toBe(500);
  });
});

// ── listEnvironments ──────────────────────────────────────────────────────────

describe('listEnvironments', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns environments list', async () => {
    const envs = [{ environment_id: 'env-1', name: 'production' }];
    const chain = makeChain({ data: envs, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listEnvironments('tenant-1');
    expect(result.environments).toEqual(envs);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listEnvironments('tenant-1');
    expect(result.status).toBe(500);
  });
});

// ── generateApiKey ────────────────────────────────────────────────────────────

describe('generateApiKey', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns api_key with full key on success (production)', async () => {
    const apiKeyRow = {
      key_id: 'k-1',
      tenant_id: 'tenant-1',
      environment: 'production',
      key_prefix: 'ept_live',
      name: 'my-key',
      permissions: ['read'],
      created_at: '2024-01-01T00:00:00Z',
      expires_at: null,
    };
    const chain = makeChain({ data: apiKeyRow, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await generateApiKey('tenant-1', 'production', 'my-key');
    expect(result.api_key).toBeDefined();
    expect(result.api_key.key).toMatch(/^ept_live_/);
    expect(result.api_key.key_id).toBe('k-1');
  });

  it('uses test prefix for non-production environment', async () => {
    const apiKeyRow = { key_id: 'k-2', key_prefix: 'ept_test', environment: 'staging' };
    const chain = makeChain({ data: apiKeyRow, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await generateApiKey('tenant-1', 'staging', 'test-key');
    expect(result.api_key.key).toMatch(/^ept_test_/);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'insert failed' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await generateApiKey('tenant-1', 'production', 'key');
    expect(result.status).toBe(500);
  });

  it('generates unique keys on each call', async () => {
    const rows = [
      { key_id: 'k-1', environment: 'production', key_prefix: 'ept_live' },
      { key_id: 'k-2', environment: 'production', key_prefix: 'ept_live' },
    ];
    let call = 0;
    const supabase = {
      from: vi.fn(() => makeChain({ data: rows[call++] ?? rows[0], error: null })),
    };
    getServiceClient.mockReturnValue(supabase);

    const r1 = await generateApiKey('tenant-1', 'production', 'k1');
    getServiceClient.mockReturnValue({
      from: vi.fn(() => makeChain({ data: rows[1], error: null })),
    });
    const r2 = await generateApiKey('tenant-1', 'production', 'k2');

    expect(r1.api_key.key).not.toBe(r2.api_key.key);
  });
});

// ── listApiKeys ───────────────────────────────────────────────────────────────

describe('listApiKeys', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns active (non-revoked) api keys', async () => {
    const keys = [{ key_id: 'k-1', environment: 'production', key_prefix: 'ept_live' }];
    const chain = makeChain({ data: keys, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listApiKeys('tenant-1');
    expect(result.api_keys).toEqual(keys);
  });

  it('returns empty array when no keys', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listApiKeys('tenant-1');
    expect(result.api_keys).toEqual([]);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listApiKeys('tenant-1');
    expect(result.status).toBe(500);
  });
});

// ── revokeApiKey ──────────────────────────────────────────────────────────────

describe('revokeApiKey', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns revoked key on success', async () => {
    const key = { key_id: 'k-1', key_prefix: 'ept_live', revoked_at: new Date().toISOString() };
    const chain = makeChain({ data: key, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await revokeApiKey('k-1');
    expect(result.key.key_id).toBe('k-1');
    expect(result.key.revoked_at).toBeDefined();
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await revokeApiKey('k-1');
    expect(result.status).toBe(500);
  });

  it('returns 404 when key not found or already revoked', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await revokeApiKey('k-1');
    expect(result.status).toBe(404);
  });
});

// ── resolveApiKey ─────────────────────────────────────────────────────────────

describe('resolveApiKey', () => {
  beforeEach(() => vi.clearAllMocks());

  const KEY_ROW = {
    key_id: 'k-1',
    tenant_id: 'tenant-1',
    environment: 'production',
    permissions: ['read', 'write'],
    expires_at: null,
    revoked_at: null,
  };

  it('returns tenant + environment + permissions on success', async () => {
    const keyChain = makeChain({ data: KEY_ROW, error: null });
    const tenantChain = makeChain({ data: TENANT, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenant_api_keys') return keyChain;
        if (table === 'tenants') return tenantChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash-abc');
    expect(result.tenant).toBeDefined();
    expect(result.environment).toBe('production');
    expect(result.permissions).toEqual(['read', 'write']);
  });

  it('returns 401 when key hash not found', async () => {
    const keyChain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => keyChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('missing-hash');
    expect(result.status).toBe(401);
  });

  it('returns 500 on DB error during key lookup', async () => {
    const keyChain = makeChain({ data: null, error: { message: 'db err' } });
    const supabase = { from: vi.fn(() => keyChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash');
    expect(result.status).toBe(500);
  });

  it('returns 403 when key is revoked', async () => {
    const keyChain = makeChain({ data: { ...KEY_ROW, revoked_at: '2024-01-01T00:00:00Z' }, error: null });
    const supabase = { from: vi.fn(() => keyChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash');
    expect(result.status).toBe(403);
    expect(result.error).toMatch(/revoked/i);
  });

  it('returns 403 when key is expired', async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const keyChain = makeChain({ data: { ...KEY_ROW, expires_at: past }, error: null });
    const supabase = { from: vi.fn(() => keyChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash');
    expect(result.status).toBe(403);
    expect(result.error).toMatch(/expired/i);
  });

  it('accepts key with future expiry', async () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const keyChain = makeChain({ data: { ...KEY_ROW, expires_at: future }, error: null });
    const tenantChain = makeChain({ data: TENANT, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenant_api_keys') return keyChain;
        if (table === 'tenants') return tenantChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash');
    expect(result.tenant).toBeDefined();
  });

  it('returns 403 when tenant is not active', async () => {
    const keyChain = makeChain({ data: KEY_ROW, error: null });
    const tenantChain = makeChain({ data: { ...TENANT, status: 'suspended' }, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenant_api_keys') return keyChain;
        if (table === 'tenants') return tenantChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash');
    expect(result.status).toBe(403);
    expect(result.error).toMatch(/not active/i);
  });

  it('returns 403 when tenant row not found', async () => {
    const keyChain = makeChain({ data: KEY_ROW, error: null });
    const tenantChain = makeChain({ data: null, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'tenant_api_keys') return keyChain;
        if (table === 'tenants') return tenantChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await resolveApiKey('hash');
    expect(result.status).toBe(403);
  });
});

// ── listTenantsForUser ────────────────────────────────────────────────────────

describe('listTenantsForUser', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns tenants with role for a user', async () => {
    const memberships = [
      { role: 'owner', tenants: { tenant_id: 'tenant-1', name: 'Acme', slug: 'acme', status: 'active', plan: 'free' } },
    ];
    const chain = makeChain({ data: memberships, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listTenantsForUser('user-1');
    expect(result.tenants).toHaveLength(1);
    expect(result.tenants[0].role).toBe('owner');
    expect(result.tenants[0].tenant_id).toBe('tenant-1');
  });

  it('filters out memberships without tenant data', async () => {
    const memberships = [
      { role: 'member', tenants: null },
      { role: 'owner', tenants: { tenant_id: 't-2', name: 'B' } },
    ];
    const chain = makeChain({ data: memberships, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listTenantsForUser('user-1');
    expect(result.tenants).toHaveLength(1);
  });

  it('returns empty array when user has no memberships', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listTenantsForUser('user-1');
    expect(result.tenants).toEqual([]);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await listTenantsForUser('user-1');
    expect(result.status).toBe(500);
  });
});

// ── checkMemberRole ───────────────────────────────────────────────────────────

describe('checkMemberRole', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns authorized: true for exact role match', async () => {
    const chain = makeChain({ data: { role: 'member' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await checkMemberRole('tenant-1', 'user-1', 'member');
    expect(result.authorized).toBe(true);
    expect(result.role).toBe('member');
  });

  it('returns authorized: true for higher role (owner satisfies member)', async () => {
    const chain = makeChain({ data: { role: 'owner' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await checkMemberRole('tenant-1', 'user-1', 'member');
    expect(result.authorized).toBe(true);
  });

  it('returns authorized: false for lower role (viewer does not satisfy admin)', async () => {
    const chain = makeChain({ data: { role: 'viewer' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await checkMemberRole('tenant-1', 'user-1', 'admin');
    expect(result.authorized).toBe(false);
  });

  it('returns authorized: false when user is not a member', async () => {
    const chain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await checkMemberRole('tenant-1', 'user-1', 'member');
    expect(result.authorized).toBe(false);
    expect(result.error).toMatch(/not a member/i);
  });

  it('returns authorized: false on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'db err' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await checkMemberRole('tenant-1', 'user-1', 'member');
    expect(result.authorized).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('defaults required role to member', async () => {
    const chain = makeChain({ data: { role: 'member' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    // No third argument — defaults to 'member'
    const result = await checkMemberRole('tenant-1', 'user-1');
    expect(result.authorized).toBe(true);
  });

  it('admin role satisfies owner requirement: false', async () => {
    const chain = makeChain({ data: { role: 'admin' }, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await checkMemberRole('tenant-1', 'user-1', 'owner');
    expect(result.authorized).toBe(false);
  });
});
