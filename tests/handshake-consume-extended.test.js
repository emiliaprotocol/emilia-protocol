/**
 * Extended tests for lib/handshake/consume.js
 *
 * Audit-fix C1 (commit ebd1d72) + 085 (commit 004bb3d):
 *   consume.js now goes through `consume_handshake_atomic` RPC instead of
 *   doing serial select + insert + update via `supabase.from(...)`. The
 *   RPC enforces:
 *     - status check (P0001 INVALID_STATE_FOR_CONSUMPTION)
 *     - row not found (P0002 HANDSHAKE_NOT_FOUND or BINDING_NOT_FOUND)
 *     - binding_hash mismatch (P0003 BINDING_HASH_MISMATCH, migration 080)
 *     - one-time-use (23505 unique violation)
 *
 *   Tests now mock `supabase.rpc(...)` instead of `supabase.from(...)`.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/siem.js', () => ({
  siemEvent: vi.fn(),
}));

import { consumeHandshake } from '../lib/handshake/consume.js';

beforeEach(() => {
  vi.clearAllMocks();
});

// Helper: build a supabase mock whose `rpc` returns a fixed result.
function rpcMock({ data = null, error = null } = {}) {
  return {
    rpc: vi.fn().mockResolvedValue({ data, error }),
    // The post-080 RPC owns the binding-mark too, so consume.js no longer
    // makes a separate `from('handshake_bindings').update(...)` call. We keep
    // a no-op `from` for any other code paths that still touch it.
    from: vi.fn(() => ({
      update: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      is: vi.fn().mockReturnThis(),
    })),
  };
}

// ── INVALID_STATE_FOR_CONSUMPTION (P0001) ─────────────────────────────────────

describe('consumeHandshake — invalid state (RPC raises P0001)', () => {
  it('throws INVALID_STATE_FOR_CONSUMPTION when handshake is not in verified state', async () => {
    mockGetServiceClient.mockReturnValue(rpcMock({
      error: { code: 'P0001', message: 'INVALID_STATE_FOR_CONSUMPTION current status: initiated' },
    }));

    await expect(
      consumeHandshake({ handshake_id: 'hs-1', binding_hash: 'abc', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'INVALID_STATE_FOR_CONSUMPTION' });
  });

  it('throws INVALID_STATE_FOR_CONSUMPTION when handshake is not found (P0002)', async () => {
    mockGetServiceClient.mockReturnValue(rpcMock({
      error: { code: 'P0002', message: 'HANDSHAKE_NOT_FOUND' },
    }));

    await expect(
      consumeHandshake({ handshake_id: 'hs-missing', binding_hash: 'abc', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'INVALID_STATE_FOR_CONSUMPTION' });
  });
});

// ── ALREADY_CONSUMED (23505 unique violation) ─────────────────────────────────

describe('consumeHandshake — double-consume guard', () => {
  it('throws ALREADY_CONSUMED on unique constraint violation', async () => {
    mockGetServiceClient.mockReturnValue(rpcMock({
      error: { code: '23505', message: 'duplicate key value violates unique constraint' },
    }));

    await expect(
      consumeHandshake({ handshake_id: 'hs-1', binding_hash: 'abc', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'ALREADY_CONSUMED' });
  });
});

// ── BINDING_HASH_MISMATCH (P0003, migration 080) ──────────────────────────────

describe('consumeHandshake — binding_hash integrity guard (migration 080)', () => {
  it('throws BINDING_HASH_MISMATCH when caller binding_hash differs from server truth', async () => {
    mockGetServiceClient.mockReturnValue(rpcMock({
      error: { code: 'P0003', message: 'BINDING_HASH_MISMATCH expected server truth (length 64), got caller value (length 64)' },
    }));

    await expect(
      consumeHandshake({ handshake_id: 'hs-1', binding_hash: 'wrong', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'BINDING_HASH_MISMATCH' });
  });
});

// ── DB_ERROR (anything else) ──────────────────────────────────────────────────

describe('consumeHandshake — generic DB error', () => {
  it('throws DB_ERROR on non-classified RPC failure', async () => {
    mockGetServiceClient.mockReturnValue(rpcMock({
      error: { code: '50000', message: 'connection timeout' },
    }));

    await expect(
      consumeHandshake({
        handshake_id: 'hs-1',
        binding_hash: 'abc123',
        consumed_by_type: 'commit_issue',
        consumed_by_id: 'ci-1',
        actor: 'system',
      })
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });

  it('throws DB_ERROR when RPC returns no rows (consumption record missing)', async () => {
    mockGetServiceClient.mockReturnValue(rpcMock({
      data: [],          // RPC succeeded but returned an empty array
      error: null,
    }));

    await expect(
      consumeHandshake({
        handshake_id: 'hs-1',
        binding_hash: 'abc123',
        consumed_by_type: 'commit_issue',
        consumed_by_id: 'ci-1',
        actor: 'system',
      })
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

// ── Happy path ───────────────────────────────────────────────────────────────

describe('consumeHandshake — successful consumption', () => {
  it('returns the consumption record on success', async () => {
    const consumption = {
      id: 'cons-1',
      handshake_id: 'hs-1',
      binding_hash: 'abc123',
      consumed_by_type: 'commit_issue',
      consumed_by_id: 'ci-1',
      actor_entity_ref: 'system',
      consumed_by_action: null,
      created_at: new Date().toISOString(),
    };
    mockGetServiceClient.mockReturnValue(rpcMock({
      data: [consumption],
      error: null,
    }));

    const result = await consumeHandshake({
      handshake_id: 'hs-1',
      binding_hash: 'abc123',
      consumed_by_type: 'commit_issue',
      consumed_by_id: 'ci-1',
      actor: 'system',
    });
    expect(result).toMatchObject({ id: 'cons-1', handshake_id: 'hs-1' });
  });
});
