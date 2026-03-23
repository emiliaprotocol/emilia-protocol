/**
 * EMILIA Protocol — authenticateRequest() Tests
 *
 * Validates that authenticateRequest returns distinct error codes for each
 * failure mode instead of collapsing them into a generic "invalid key" error.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks — intercept at the @supabase/supabase-js level so internal calls
// to getServiceClient() within supabase.js use our mock client.
// ---------------------------------------------------------------------------

const mockFrom = vi.fn();

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => ({ from: mockFrom })),
}));

vi.mock('../lib/env.js', () => ({
  getSupabaseConfig: () => ({ url: 'https://fake.supabase.co', serviceRoleKey: 'fake-key' }),
}));

const { authenticateRequest, hashApiKey } = await import('../lib/supabase.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_KEY = 'ep_live_abc123';

function makeRequest(authHeader) {
  return {
    headers: new Map(authHeader !== undefined ? [['authorization', authHeader]] : []),
  };
}

/**
 * Build a fluent Supabase query-chain mock that resolves to `value`.
 * Supports .select().eq() chains that resolve when awaited.
 */
function makeChain(value) {
  const p = Promise.resolve(value);
  const self = {};
  self.select = vi.fn().mockReturnValue(self);
  self.eq = vi.fn().mockReturnValue(self);
  self.is = vi.fn().mockReturnValue(self);
  self.maybeSingle = vi.fn().mockReturnValue(self);
  self.single = vi.fn().mockReturnValue(self);
  self.update = vi.fn().mockReturnValue(self);
  self.then = p.then.bind(p);
  self.catch = p.catch.bind(p);
  return self;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('authenticateRequest', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the entity for a valid API key', async () => {
    const activeKeyRow = { entity_id: 'ent-1', permissions: ['read'], revoked_at: null };
    const entityRow = { id: 'ent-1', status: 'active', name: 'TestEntity' };

    let callIndex = 0;
    mockFrom.mockImplementation((table) => {
      callIndex++;
      if (table === 'api_keys' && callIndex === 1) {
        return makeChain({ data: [activeKeyRow], error: null });
      }
      if (table === 'api_keys' && callIndex === 2) {
        return makeChain({ data: null, error: null });
      }
      if (table === 'entities') {
        return makeChain({ data: entityRow, error: null });
      }
      return makeChain({ data: null, error: null });
    });

    const result = await authenticateRequest(makeRequest(`Bearer ${TEST_KEY}`));
    expect(result.entity).toEqual(entityRow);
    expect(result.permissions).toEqual(['read']);
    expect(result.error).toBeUndefined();
  });

  it('returns 401 with auth_failed when key does not exist', async () => {
    mockFrom.mockImplementation(() => makeChain({ data: [], error: null }));

    const result = await authenticateRequest(makeRequest(`Bearer ${TEST_KEY}`));
    expect(result.status).toBe(401);
    expect(result.code).toBe('auth_failed');
    expect(result.error).toContain('Authentication failed');
  });

  it('returns 401 with auth_failed when key is revoked', async () => {
    const revokedRow = { entity_id: 'ent-1', permissions: ['read'], revoked_at: '2025-01-01T00:00:00Z' };
    mockFrom.mockImplementation(() => makeChain({ data: [revokedRow], error: null }));

    const result = await authenticateRequest(makeRequest(`Bearer ${TEST_KEY}`));
    expect(result.status).toBe(401);
    expect(result.code).toBe('auth_failed');
    expect(result.error).toContain('Authentication failed');
  });

  it('returns 503 on database error, NOT "invalid key"', async () => {
    mockFrom.mockImplementation(() =>
      makeChain({ data: null, error: { message: 'connection refused' } }),
    );

    const result = await authenticateRequest(makeRequest(`Bearer ${TEST_KEY}`));
    expect(result.status).toBe(503);
    expect(result.code).toBe('auth_service_unavailable');
    expect(result.error).not.toContain('invalid');
    expect(result.error).not.toContain('Invalid');
    expect(result.error).toContain('unavailable');
  });

  it('returns 401 with missing_key when Authorization header is absent', async () => {
    const result = await authenticateRequest(makeRequest(undefined));
    expect(result.status).toBe(401);
    expect(result.code).toBe('missing_key');
  });

  it('returns 401 with missing_key for malformed bearer token', async () => {
    const result = await authenticateRequest(makeRequest('Bearer sk_live_notvalid'));
    expect(result.status).toBe(401);
    expect(result.code).toBe('missing_key');
  });
});
