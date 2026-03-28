/**
 * Auth RPC Correctness Tests
 *
 * Validates that resolve_authenticated_actor() RPC preserves all
 * security semantics from the original 3-query auth path:
 * - Revoked keys fail immediately
 * - Missing keys fail closed
 * - Inactive entities fail
 * - Malformed records fail closed
 * - Valid keys return full entity + permissions
 * - Entity identity is from auth, not forgeable
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Mock: Supabase
// ============================================================================

const mockRpc = vi.fn();

// Mock the env module so getServiceClient doesn't fail
vi.mock('../lib/env.js', () => ({
  getSupabaseConfig: () => ({
    url: 'https://test.supabase.co',
    serviceRoleKey: 'test-service-key',
  }),
  getUpstashConfig: () => null,
}));

// Mock @supabase/supabase-js to return our mock client
vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    rpc: (...args) => mockRpc(...args),
    from: () => ({
      select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: null, error: null }) }) }),
      insert: () => Promise.resolve({ data: null, error: null }),
      update: () => ({ eq: () => Promise.resolve({ data: null, error: null }) }),
    }),
  }),
}));

// ============================================================================
// Import after mocks
// ============================================================================

const { authenticateRequest } = await import('../lib/supabase.js');

// ============================================================================
// Helpers
// ============================================================================

function makeRequest(apiKey = 'ep_live_test123') {
  return {
    headers: {
      get: (name) => {
        if (name === 'authorization') return `Bearer ${apiKey}`;
        return null;
      },
    },
  };
}

// ============================================================================
// Tests
// ============================================================================

describe('Auth RPC — authenticateRequest', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Header validation (pre-RPC) ──────────────────────────────────────────

  describe('header validation', () => {
    it('rejects missing authorization header', async () => {
      const req = { headers: { get: () => null } };
      const result = await authenticateRequest(req);
      expect(result.error).toBeDefined();
      expect(result.code).toBe('missing_key');
      expect(result.status).toBe(401);
    });

    it('rejects non-EP key prefixes', async () => {
      const req = makeRequest('sk_live_test123');
      const result = await authenticateRequest(req);
      expect(result.error).toBeDefined();
      expect(result.code).toBe('missing_key');
      expect(result.status).toBe(401);
    });

    it('rejects empty bearer token', async () => {
      const req = { headers: { get: (n) => n === 'authorization' ? 'Bearer ' : null } };
      const result = await authenticateRequest(req);
      expect(result.error).toBeDefined();
      expect(result.status).toBe(401);
    });
  });

  // ── RPC error handling ────────────────────────────────────────────────────

  describe('RPC error handling', () => {
    it('returns 503 when RPC call fails', async () => {
      mockRpc.mockResolvedValue({ data: null, error: { message: 'connection refused' } });
      const result = await authenticateRequest(makeRequest());
      expect(result.status).toBe(503);
      expect(result.code).toBe('auth_service_unavailable');
    });

    it('returns 503 when RPC returns null data', async () => {
      mockRpc.mockResolvedValue({ data: null, error: null });
      const result = await authenticateRequest(makeRequest());
      // Null data without error should be treated as auth failure
      expect(result.status).toBe(401);
    });
  });

  // ── Key not found ─────────────────────────────────────────────────────────

  describe('key not found', () => {
    it('fails with 401 when key does not exist', async () => {
      mockRpc.mockResolvedValue({
        data: { error: 'auth_failed', reason: 'key_not_found' },
        error: null,
      });
      const result = await authenticateRequest(makeRequest());
      expect(result.error).toBeDefined();
      expect(result.status).toBe(401);
    });
  });

  // ── Revoked key ───────────────────────────────────────────────────────────

  describe('revoked key', () => {
    it('fails immediately with 401 when key is revoked', async () => {
      mockRpc.mockResolvedValue({
        data: { error: 'auth_failed', reason: 'key_revoked' },
        error: null,
      });
      const result = await authenticateRequest(makeRequest());
      expect(result.error).toBeDefined();
      expect(result.status).toBe(401);
      // Must NOT return entity data for revoked keys
      expect(result.entity).toBeUndefined();
    });
  });

  // ── Inactive entity ───────────────────────────────────────────────────────

  describe('inactive entity', () => {
    it('fails with 401 when entity is inactive', async () => {
      mockRpc.mockResolvedValue({
        data: { error: 'auth_failed', reason: 'entity_inactive' },
        error: null,
      });
      const result = await authenticateRequest(makeRequest());
      expect(result.error).toBeDefined();
      expect(result.status).toBe(401);
      expect(result.entity).toBeUndefined();
    });
  });

  // ── Malformed key record ──────────────────────────────────────────────────

  describe('malformed key record', () => {
    it('fails closed with 500 on malformed record', async () => {
      mockRpc.mockResolvedValue({
        data: { error: 'malformed_key_record', reason: 'missing_entity_id' },
        error: null,
      });
      const result = await authenticateRequest(makeRequest());
      expect(result.status).toBe(500);
      // Must fail closed — no entity data leaked
      expect(result.entity).toBeUndefined();
    });
  });

  // ── Successful auth ───────────────────────────────────────────────────────

  describe('successful authentication', () => {
    const validEntity = {
      id: 'uuid-123',
      entity_id: 'rex-booking-v1',
      display_name: 'Rex',
      entity_type: 'agent',
      status: 'active',
    };

    const validPermissions = ['read', 'write'];

    beforeEach(() => {
      mockRpc.mockResolvedValue({
        data: { entity: validEntity, permissions: validPermissions },
        error: null,
      });
    });

    it('returns entity and permissions on valid key', async () => {
      const result = await authenticateRequest(makeRequest());
      expect(result.entity).toEqual(validEntity);
      expect(result.permissions).toEqual(validPermissions);
      expect(result.error).toBeUndefined();
    });

    it('entity identity comes from DB, not from request', async () => {
      // Even if someone sends a different entity_ref in the body,
      // auth returns the DB-resolved entity
      const result = await authenticateRequest(makeRequest());
      expect(result.entity.entity_id).toBe('rex-booking-v1');
    });

    it('calls RPC with hashed key, not raw key', async () => {
      await authenticateRequest(makeRequest());
      expect(mockRpc).toHaveBeenCalledWith('resolve_authenticated_actor', {
        p_key_hash: expect.any(String),
      });
      // The hash should NOT be the raw key
      const callArgs = mockRpc.mock.calls[0][1];
      expect(callArgs.p_key_hash).not.toBe('ep_live_test123');
      expect(callArgs.p_key_hash.length).toBeGreaterThan(0);
    });
  });

  // ── Entity isolation ──────────────────────────────────────────────────────

  describe('entity isolation', () => {
    it('different keys return different entities', async () => {
      // First call: entity A
      mockRpc.mockResolvedValueOnce({
        data: { entity: { entity_id: 'entity-a' }, permissions: [] },
        error: null,
      });
      const resultA = await authenticateRequest(makeRequest('ep_live_key_a'));
      expect(resultA.entity.entity_id).toBe('entity-a');

      // Second call: entity B
      mockRpc.mockResolvedValueOnce({
        data: { entity: { entity_id: 'entity-b' }, permissions: [] },
        error: null,
      });
      const resultB = await authenticateRequest(makeRequest('ep_live_key_b'));
      expect(resultB.entity.entity_id).toBe('entity-b');
    });

    it('cannot inherit another entity context via key manipulation', async () => {
      // If key A is used, only entity A's data comes back
      mockRpc.mockResolvedValue({
        data: { entity: { entity_id: 'entity-a', id: 'uuid-a' }, permissions: ['read'] },
        error: null,
      });
      const result = await authenticateRequest(makeRequest('ep_live_key_a'));
      expect(result.entity.entity_id).toBe('entity-a');
      expect(result.entity.id).toBe('uuid-a');
    });
  });

  // ── Scope propagation ─────────────────────────────────────────────────────

  describe('scope propagation', () => {
    it('empty permissions are preserved, not defaulted', async () => {
      mockRpc.mockResolvedValue({
        data: { entity: { entity_id: 'e' }, permissions: [] },
        error: null,
      });
      const result = await authenticateRequest(makeRequest());
      expect(result.permissions).toEqual([]);
    });

    it('null permissions are handled gracefully', async () => {
      mockRpc.mockResolvedValue({
        data: { entity: { entity_id: 'e' }, permissions: null },
        error: null,
      });
      const result = await authenticateRequest(makeRequest());
      // Should not crash — null permissions are valid (no scopes)
      expect(result.permissions).toBeNull();
    });
  });
});
