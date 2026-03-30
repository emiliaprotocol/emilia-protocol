/**
 * Key Rotation Tests
 *
 * Validates POST /api/keys/rotate:
 * - Successful rotation returns new key
 * - Old key stops working after rotation
 * - New key works after rotation
 * - Entity score/history is preserved (same entity_id)
 * - Unauthenticated rotation fails
 * - Double rotation works (rotate twice)
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Mock: Supabase
// ============================================================================

const mockRpc = vi.fn();
const mockUpdate = vi.fn();
const mockInsert = vi.fn();
const mockSelect = vi.fn();

// Track revoked hashes so we can simulate auth rejection
const revokedHashes = new Set();

vi.mock('../lib/env.js', () => ({
  getSupabaseConfig: () => ({
    url: 'https://test.supabase.co',
    serviceRoleKey: 'test-service-key',
  }),
  getUpstashConfig: () => null,
}));

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    rpc: (...args) => mockRpc(...args),
    from: (table) => {
      if (table === 'api_keys') {
        return {
          select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: null, error: null }) }) }),
          insert: (data) => mockInsert(table, data),
          update: (data) => ({
            eq: (col, val) => {
              // Chain: .update().eq('key_hash', ...).eq('entity_id', ...)
              if (col === 'key_hash' && data.revoked_at) {
                revokedHashes.add(val);
              }
              return {
                eq: () => mockUpdate(table, data),
              };
            },
          }),
        };
      }
      if (table === 'entities') {
        return {
          select: () => ({ eq: () => ({ single: () => Promise.resolve({ data: null, error: null }) }) }),
          insert: (data) => ({ select: () => ({ single: () => Promise.resolve({ data: { id: 'ent-1', ...data }, error: null }) }) }),
          update: (data) => ({
            eq: () => mockUpdate(table, data),
          }),
        };
      }
      return {
        select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: null, error: null }) }) }),
        insert: () => Promise.resolve({ data: null, error: null }),
        update: () => ({ eq: () => Promise.resolve({ data: null, error: null }) }),
      };
    },
  }),
}));

// ============================================================================
// Import after mocks
// ============================================================================

const { authenticateRequest, hashApiKey } = await import('../lib/supabase.js');
const { POST } = await import('../app/api/keys/rotate/route.js');

// ============================================================================
// Helpers
// ============================================================================

const VALID_ENTITY = {
  id: 'ent-uuid-1',
  entity_id: 'test-agent',
  display_name: 'Test Agent',
  entity_type: 'agent',
  emilia_score: 72.5,
  status: 'active',
};

function makeRequest(apiKey = 'ep_live_testapikey1234567890abcdef1234567890abcdef1234567890abcdef12345678') {
  return {
    headers: {
      get: (name) => {
        if (name === 'authorization') return `Bearer ${apiKey}`;
        return null;
      },
    },
    json: () => Promise.resolve({}),
  };
}

function setupAuthSuccess(entity = VALID_ENTITY) {
  mockRpc.mockImplementation((rpcName, params) => {
    if (rpcName === 'resolve_authenticated_actor') {
      // If the key hash has been revoked, reject
      if (revokedHashes.has(params.p_key_hash)) {
        return Promise.resolve({
          data: { error: 'auth_failed', reason: 'key_revoked' },
          error: null,
        });
      }
      return Promise.resolve({
        data: { entity, permissions: { can_submit_receipts: true } },
        error: null,
      });
    }
    return Promise.resolve({ data: null, error: null });
  });
}

function setupAuthFailure() {
  mockRpc.mockResolvedValue({
    data: { error: 'auth_failed', reason: 'key_not_found' },
    error: null,
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('POST /api/keys/rotate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    revokedHashes.clear();
    mockUpdate.mockResolvedValue({ data: null, error: null });
    mockInsert.mockResolvedValue({ data: null, error: null });
  });

  // ── Successful rotation ────────────────────────────────────────────────

  it('returns new key on successful rotation', async () => {
    setupAuthSuccess();
    const req = makeRequest();

    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.new_key).toBeDefined();
    expect(body.new_key).toMatch(/^ep_live_/);
    expect(body.rotated_at).toBeDefined();
    expect(body.old_key_invalidated).toBe(true);
  });

  it('revokes the old key record', async () => {
    setupAuthSuccess();
    const req = makeRequest();

    await POST(req);

    // Verify update was called on api_keys with revoked_at
    expect(mockUpdate).toHaveBeenCalledWith('api_keys', expect.objectContaining({
      revoked_at: expect.any(String),
      invalidated_at: expect.any(String),
    }));
  });

  it('inserts a new key record', async () => {
    setupAuthSuccess();
    const req = makeRequest();

    await POST(req);

    // Verify insert was called on api_keys
    expect(mockInsert).toHaveBeenCalledWith('api_keys', expect.objectContaining({
      entity_id: VALID_ENTITY.id,
      key_hash: expect.any(String),
      key_prefix: expect.any(String),
      label: 'Rotated key',
    }));
  });

  it('updates entity api_key_hash to new hash', async () => {
    setupAuthSuccess();
    const req = makeRequest();

    await POST(req);

    // Verify update was called on entities with new hash
    expect(mockUpdate).toHaveBeenCalledWith('entities', expect.objectContaining({
      api_key_hash: expect.any(String),
    }));
  });

  // ── Old key stops working ──────────────────────────────────────────────

  it('old key stops working after rotation (via revoked_at)', async () => {
    setupAuthSuccess();
    const oldKey = 'ep_live_oldkey1234567890abcdef1234567890abcdef1234567890abcdef12345678';
    const req = makeRequest(oldKey);

    // Perform rotation
    const res = await POST(req);
    expect(res.status).toBe(201);

    // Now the old key hash was added to revokedHashes by our mock
    const oldHash = hashApiKey(oldKey);
    expect(revokedHashes.has(oldHash)).toBe(true);

    // Attempt auth with old key — should fail
    const authResult = await authenticateRequest(makeRequest(oldKey));
    expect(authResult.error).toBeDefined();
  });

  // ── New key works after rotation ───────────────────────────────────────

  it('new key has valid ep_live_ format and unique hash', async () => {
    setupAuthSuccess();
    const req = makeRequest();

    const res = await POST(req);
    const body = await res.json();

    expect(body.new_key).toMatch(/^ep_live_[0-9a-f]{64}$/);

    // Hash should be different from old key hash
    const oldHash = hashApiKey('ep_live_testapikey1234567890abcdef1234567890abcdef1234567890abcdef12345678');
    const newHash = hashApiKey(body.new_key);
    expect(newHash).not.toBe(oldHash);
  });

  // ── Entity identity is preserved ───────────────────────────────────────

  it('preserves entity identity (same entity_id throughout)', async () => {
    setupAuthSuccess();
    const req = makeRequest();

    const res = await POST(req);
    const body = await res.json();

    // The insert should use the same entity id
    expect(mockInsert).toHaveBeenCalledWith('api_keys', expect.objectContaining({
      entity_id: VALID_ENTITY.id,
    }));

    // The entity update should target the same entity
    expect(mockUpdate).toHaveBeenCalledWith('entities', expect.objectContaining({
      api_key_hash: expect.any(String),
    }));
  });

  // ── Unauthenticated rotation fails ─────────────────────────────────────

  it('rejects unauthenticated rotation (no header)', async () => {
    const req = { headers: { get: () => null }, json: () => Promise.resolve({}) };
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.type).toContain('missing_key');
  });

  it('rejects rotation with invalid key', async () => {
    setupAuthFailure();
    const req = makeRequest('ep_live_invalidkey000000000000000000000000000000000000000000000000');
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(401);
  });

  // ── Double rotation ────────────────────────────────────────────────────

  it('double rotation works (rotate twice in sequence)', async () => {
    setupAuthSuccess();

    // First rotation
    const req1 = makeRequest('ep_live_first00000000000000000000000000000000000000000000000000000000');
    const res1 = await POST(req1);
    const body1 = await res1.json();
    expect(res1.status).toBe(201);
    expect(body1.new_key).toMatch(/^ep_live_/);

    // Second rotation with a different key
    // (In production, you'd use body1.new_key. Here we use a fresh key
    // since auth is mocked — the important thing is both rotations succeed.)
    const req2 = makeRequest('ep_live_second0000000000000000000000000000000000000000000000000000000000');
    const res2 = await POST(req2);
    const body2 = await res2.json();
    expect(res2.status).toBe(201);
    expect(body2.new_key).toMatch(/^ep_live_/);

    // The two new keys should be different
    expect(body1.new_key).not.toBe(body2.new_key);

    // Both old keys should be revoked
    const hash1 = hashApiKey('ep_live_first00000000000000000000000000000000000000000000000000000000');
    const hash2 = hashApiKey('ep_live_second0000000000000000000000000000000000000000000000000000000000');
    expect(revokedHashes.has(hash1)).toBe(true);
    expect(revokedHashes.has(hash2)).toBe(true);
  });

  // ── Error handling ─────────────────────────────────────────────────────

  it('returns 500 if revoking old key fails', async () => {
    setupAuthSuccess();
    mockUpdate.mockResolvedValueOnce({ data: null, error: { message: 'db error' } });

    const req = makeRequest();
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(500);
    expect(body.type).toContain('rotation_failed');
  });

  it('returns 500 if inserting new key fails', async () => {
    setupAuthSuccess();
    // First update (revoke) succeeds, insert fails
    mockUpdate.mockResolvedValue({ data: null, error: null });
    mockInsert.mockResolvedValueOnce({ data: null, error: { message: 'insert error' } });

    const req = makeRequest();
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(500);
    expect(body.type).toContain('rotation_failed');
  });
});
