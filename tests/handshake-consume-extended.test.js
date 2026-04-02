/**
 * lib/handshake/consume.js — extended coverage for uncovered lines.
 *
 * Uncovered lines:
 *   54-57  consumeHandshake: missing required args → throws HandshakeError
 *   71     consumeHandshake: handshake not in verified state → INVALID_STATE_FOR_CONSUMPTION
 *   97     consumeHandshake: generic DB error (non-23505) → throws HandshakeError DB_ERROR
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('@/lib/supabase', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('@/lib/actor', () => ({
  resolveActorRef: (actor) => (typeof actor === 'string' ? actor : 'system'),
}));

import { consumeHandshake } from '../lib/handshake/consume.js';

beforeEach(() => {
  vi.clearAllMocks();
});

// ── Lines 54-57: missing required args ───────────────────────────────────────

describe('consumeHandshake — missing required args (lines 54-57)', () => {
  it('throws MISSING_HANDSHAKE_ID when handshake_id is absent', async () => {
    await expect(
      consumeHandshake({ binding_hash: 'abc', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'MISSING_HANDSHAKE_ID' });
  });

  it('throws MISSING_BINDING_HASH when binding_hash is absent', async () => {
    await expect(
      consumeHandshake({ handshake_id: 'hs-1', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'MISSING_BINDING_HASH' });
  });

  it('throws MISSING_CONSUMED_BY_TYPE when consumed_by_type is absent', async () => {
    await expect(
      consumeHandshake({ handshake_id: 'hs-1', binding_hash: 'abc', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'MISSING_CONSUMED_BY_TYPE' });
  });

  it('throws MISSING_CONSUMED_BY_ID when consumed_by_id is absent', async () => {
    await expect(
      consumeHandshake({ handshake_id: 'hs-1', binding_hash: 'abc', consumed_by_type: 't', actor: 'system' })
    ).rejects.toMatchObject({ code: 'MISSING_CONSUMED_BY_ID' });
  });
});

// ── Line 71: handshake not in verified state ──────────────────────────────────

describe('consumeHandshake — invalid state (line 71)', () => {
  it('throws INVALID_STATE_FOR_CONSUMPTION when handshake is not in verified state', async () => {
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({
              data: { status: 'initiated' },
              error: null,
            }),
          };
        }
        return { update: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(), is: vi.fn().mockReturnThis() };
      }),
    };
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(
      consumeHandshake({ handshake_id: 'hs-1', binding_hash: 'abc', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'INVALID_STATE_FOR_CONSUMPTION' });
  });

  it('throws INVALID_STATE_FOR_CONSUMPTION when handshake is not found (null)', async () => {
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: null, error: null }),
          };
        }
        return { update: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(), is: vi.fn().mockReturnThis() };
      }),
    };
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(
      consumeHandshake({ handshake_id: 'hs-missing', binding_hash: 'abc', consumed_by_type: 't', consumed_by_id: 'i', actor: 'system' })
    ).rejects.toMatchObject({ code: 'INVALID_STATE_FOR_CONSUMPTION' });
  });
});

// ── Line 97: generic DB error ─────────────────────────────────────────────────

describe('consumeHandshake — generic DB error', () => {
  it('throws HandshakeError with DB_ERROR code on non-unique insert failure — line 97', async () => {
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({
              data: { status: 'verified' },
              error: null,
            }),
          };
        }
        if (table === 'handshake_consumptions') {
          return {
            insert: vi.fn().mockReturnThis(),
            select: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({
              data: null,
              error: { code: '50000', message: 'connection timeout' },
            }),
          };
        }
        return {
          update: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          is: vi.fn().mockReturnThis(),
        };
      }),
    };
    mockGetServiceClient.mockReturnValue(supabase);

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
