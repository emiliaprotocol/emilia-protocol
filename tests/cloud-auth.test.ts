import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// Mock write-guard before importing the module under test
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: vi.fn(),
}));

import { authenticateCloudRequest } from '../lib/cloud/auth.js';
import { getGuardedClient } from '@/lib/write-guard';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a mock supabase client that supports chained queries on two tables:
 *   - tenant_api_keys (looked up by key_hash)
 *   - tenants         (looked up by tenant_id)
 */
function makeSupabaseMock({ keyRow = null, keyError = null, tenant = null, tenantError = null } = {}) {
  const keyQuery = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue({ data: keyRow, error: keyError }),
  };
  const tenantQuery = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue({ data: tenant, error: tenantError }),
  };

  return {
    from: vi.fn((table) => {
      if (table === 'tenant_api_keys') return keyQuery;
      if (table === 'tenants') return tenantQuery;
      return keyQuery; // fallback
    }),
  };
}

/** Create a minimal Request-like object with headers. */
function makeRequest(authHeader) {
  const headers = new Map();
  if (authHeader !== undefined) {
    headers.set('authorization', authHeader);
  }
  return { headers: { get: (name) => headers.get(name) ?? null } };
}

/** Hash a raw key the same way auth.js does. */
function hashKey(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Standard fixtures
const RAW_KEY = 'ep_test_abc123xyz';
const KEY_HASH = hashKey(RAW_KEY);

function defaultKeyRow(overrides = {}) {
  return {
    key_id: 'key-1',
    tenant_id: 'tenant-1',
    environment: 'production',
    permissions: ['read', 'write'],
    expires_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function defaultTenant(overrides = {}) {
  return {
    tenant_id: 'tenant-1',
    status: 'active',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('authenticateCloudRequest', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // === Missing / invalid Authorization header =============================

  it('returns null when Authorization header is missing', async () => {
    const req = makeRequest(undefined);
    const result = await authenticateCloudRequest(req);
    expect(result).toBeNull();
  });

  it('returns null for empty Authorization header', async () => {
    const req = makeRequest('');
    const result = await authenticateCloudRequest(req);
    expect(result).toBeNull();
  });

  it('returns null for non-Bearer scheme', async () => {
    const req = makeRequest('Basic dXNlcjpwYXNz');
    const result = await authenticateCloudRequest(req);
    expect(result).toBeNull();
  });

  it('returns null for Bearer with no key', async () => {
    const req = makeRequest('Bearer ');
    const result = await authenticateCloudRequest(req);
    expect(result).toBeNull();
  });

  it('returns null for invalid key prefix', async () => {
    const req = makeRequest('Bearer sk_invalid_key');
    const result = await authenticateCloudRequest(req);
    expect(result).toBeNull();
  });

  // === Valid key extraction ===============================================

  it('accepts ep_ prefixed keys', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow(),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest('Bearer ep_mykey123');
    const result = await authenticateCloudRequest(req);

    expect(result).not.toBeNull();
    expect(result.tenantId).toBe('tenant-1');
  });

  it('accepts ept_ prefixed keys (test keys)', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow(),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest('Bearer ept_testkey456');
    const result = await authenticateCloudRequest(req);

    expect(result).not.toBeNull();
    expect(result.tenantId).toBe('tenant-1');
  });

  it('is case-insensitive for Bearer prefix', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow(),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest('bearer ep_mykey123');
    const result = await authenticateCloudRequest(req);

    expect(result).not.toBeNull();
  });

  // === Successful authentication ==========================================

  it('returns full auth context for valid key with active tenant', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({
        key_id: 'key-42',
        tenant_id: 'tenant-7',
        environment: 'staging',
        permissions: ['read'],
      }),
      tenant: defaultTenant({ tenant_id: 'tenant-7' }),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toEqual({
      tenantId: 'tenant-7',
      environment: 'staging',
      permissions: ['read'],
      keyId: 'key-42',
    });
  });

  // === Key not found ======================================================

  it('returns null when key hash is not found in database', async () => {
    const mock = makeSupabaseMock({
      keyRow: null,
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });

  // === Key lookup error ===================================================

  it('returns null when key lookup has a database error', async () => {
    const mock = makeSupabaseMock({
      keyRow: null,
      keyError: { message: 'connection timeout' },
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });

  // === Expired key ========================================================

  it('returns null when key is expired', async () => {
    const pastDate = new Date(Date.now() - 60_000).toISOString(); // 1 minute ago
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({ expires_at: pastDate }),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });

  it('accepts key that has not yet expired', async () => {
    const futureDate = new Date(Date.now() + 86_400_000).toISOString(); // tomorrow
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({ expires_at: futureDate }),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).not.toBeNull();
    expect(result.tenantId).toBe('tenant-1');
  });

  it('accepts key with no expiry (expires_at is null)', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({ expires_at: null }),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).not.toBeNull();
  });

  // === Tenant checks ======================================================

  it('returns null when tenant is not found', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow(),
      tenant: null,
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });

  it('returns null when tenant is not active', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow(),
      tenant: defaultTenant({ status: 'suspended' }),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });

  it('returns null when tenant lookup errors', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow(),
      tenant: null,
      tenantError: { message: 'db error' },
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });

  // === Permissions ========================================================

  it('returns stored permissions array', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({ permissions: ['read', 'write', 'admin'] }),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result.permissions).toEqual(['read', 'write', 'admin']);
  });

  it('defaults to [] (no permissions) when permissions column is null', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({ permissions: null }),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result.permissions).toEqual([]);
  });

  it('defaults to [] (no permissions) when permissions is not an array', async () => {
    const mock = makeSupabaseMock({
      keyRow: defaultKeyRow({ permissions: 'read' }),
      tenant: defaultTenant(),
    });
    getGuardedClient.mockReturnValue(mock);

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result.permissions).toEqual([]);
  });

  // === Unexpected errors ==================================================

  it('returns null and does not throw on unexpected exceptions', async () => {
    getGuardedClient.mockImplementation(() => {
      throw new Error('module init failure');
    });

    const req = makeRequest(`Bearer ${RAW_KEY}`);
    const result = await authenticateCloudRequest(req);

    expect(result).toBeNull();
  });
});

describe('authenticateCloudRequest — bearer prefix filter', () => {
  // Audit #12 finding 4. The pattern was /^Bearer\s+(e?pt?_\S+)$/i, in which
  // only `p` was mandatory, so `p_…` and `pt_…` were admitted alongside the
  // `ep_` / `ept_` prefixes the issuer actually mints. The SHA-256 key lookup
  // was and is the real gate, so nothing authenticated that should not have —
  // but a prefix filter that admits prefixes that cannot exist is not filtering.
  //
  // The finding's own table also lists `Bearer t_abc123` and `Bearer _abc123`
  // as matches. Neither matched: `p` was never optional. Executed below so the
  // record is the regex's behaviour, not a reading of it.
  beforeEach(() => {
    // A key lookup that finds nothing, so any pass/fail here is the regex's.
    getGuardedClient.mockReturnValue(makeSupabaseMock({ keyRow: null }));
  });

  const reaches = async (header) => {
    getGuardedClient.mockClear();
    await authenticateCloudRequest(makeRequest(header));
    return getGuardedClient.mock.calls.length > 0;
  };

  it('admits only the ep_ and ept_ prefixes', async () => {
    expect(await reaches('Bearer ep_abc123')).toBe(true);
    expect(await reaches('Bearer ept_abc123')).toBe(true);
    expect(await reaches('Bearer EP_abc123')).toBe(true); // pattern is case-insensitive
  });

  it('no longer admits the p_ and pt_ prefixes the old pattern let through', async () => {
    expect(await reaches('Bearer p_abc123')).toBe(false);
    expect(await reaches('Bearer pt_abc123')).toBe(false);
  });

  it('rejects the prefixes the finding claimed matched but never did', async () => {
    expect(await reaches('Bearer t_abc123')).toBe(false);
    expect(await reaches('Bearer _abc123')).toBe(false);
  });

  it('rejects unrelated bearer shapes', async () => {
    expect(await reaches('Bearer x_abc123')).toBe(false);
    expect(await reaches('Bearer epx_abc123')).toBe(false);
    expect(await reaches('Bearer ep-abc123')).toBe(false);
  });
});
