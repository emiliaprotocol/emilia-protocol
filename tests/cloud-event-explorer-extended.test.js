/**
 * lib/cloud/event-explorer.js — extended coverage.
 *
 * Targets uncovered lines:
 *   144   getTimeline: tenant mismatch → throws 'Handshake does not belong to this tenant'
 *   252   searchEvents: textSearch error with NON-text-search error → returns []
 *   257-258 searchEvents: catch block in per-table search (console.warn + return [])
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: vi.fn(),
}));

import {
  getTimeline,
  searchEvents,
} from '../lib/cloud/event-explorer.js';
import { getGuardedClient } from '@/lib/write-guard';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeChain(resolved) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    lte: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    ilike: vi.fn().mockReturnThis(),
    textSearch: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolved),
    then: (resolve, reject) => Promise.resolve(resolved).then(resolve, reject),
  };
  return chain;
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ── getTimeline: tenant mismatch ─────────────────────────────────────────────

describe('getTimeline — tenant mismatch (line 144)', () => {
  it('throws when handshake binding has a different tenant_id', async () => {
    // handshake_bindings returns binding with a different tenant
    const bindingChain = makeChain({
      data: { tenant_id: 'tenant-other' },
      error: null,
    });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'handshake_bindings') return bindingChain;
        return makeChain({ data: [], error: null });
      }),
    };
    getGuardedClient.mockReturnValue(supabase);

    await expect(
      getTimeline('hs-1', 'tenant-mine')
    ).rejects.toThrow('Handshake does not belong to this tenant');
  });

  it('proceeds when binding has no tenant_id (no isolation check needed)', async () => {
    // binding.tenant_id is null — skip tenant check
    const bindingChain = makeChain({ data: { tenant_id: null }, error: null });
    const eventsChain = makeChain({ data: [], error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'handshake_bindings') return bindingChain;
        return eventsChain;
      }),
    };
    getGuardedClient.mockReturnValue(supabase);

    const result = await getTimeline('hs-1', 'tenant-mine');
    expect(Array.isArray(result)).toBe(true);
  });

  it('proceeds when binding row does not exist (data=null)', async () => {
    const bindingChain = makeChain({ data: null, error: null });
    const eventsChain = makeChain({ data: [], error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'handshake_bindings') return bindingChain;
        return eventsChain;
      }),
    };
    getGuardedClient.mockReturnValue(supabase);

    const result = await getTimeline('hs-1', 'tenant-x');
    expect(Array.isArray(result)).toBe(true);
  });
});

// ── searchEvents: textSearch error — non-text error returns [] (line 252) ────

describe('searchEvents — textSearch non-text-search error (line 252)', () => {
  it('returns [] for a table when textSearch errors with a non-text-search message', async () => {
    // The error message does NOT contain 'text search' or 'does not exist',
    // so neither the textSearch fallback nor the table-not-exist fallback is triggered.
    // The code returns [] for that table.
    const erroringChain = {
      select: vi.fn().mockReturnThis(),
      textSearch: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnThis(),
      lte: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      // When awaited returns an error with a non-text-search message
      then: (resolve) =>
        Promise.resolve({
          data: null,
          error: { message: 'permission denied for table' },
        }).then(resolve),
    };

    const supabase = {
      from: vi.fn(() => erroringChain),
    };
    getGuardedClient.mockReturnValue(supabase);

    const result = await searchEvents('some query');
    // Should not throw; just returns [] for each failing table
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(0);
  });
});

// ── searchEvents: catch block — table query throws synchronously (lines 257-258) ──

describe('searchEvents — catch block on table query throw (lines 257-258)', () => {
  it('handles a thrown error from a table query gracefully', async () => {
    // Force the query chain to throw (not just return an error)
    const throwingChain = {
      select: vi.fn().mockReturnThis(),
      textSearch: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnThis(),
      lte: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      // Throws when awaited
      then: (_resolve, reject) =>
        Promise.reject(new Error('network timeout')).then(_resolve, reject),
    };

    const supabase = {
      from: vi.fn(() => throwingChain),
    };
    getGuardedClient.mockReturnValue(supabase);

    const result = await searchEvents('search term');
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(0);
  });
});

// ── searchEvents: textSearch error triggers fallback (already partially tested)──

describe('searchEvents — textSearch error triggers ilike fallback', () => {
  it('falls back to ilike when textSearch fails with text search error', async () => {
    const fallbackData = [
      {
        event_id: 'evt-fallback',
        event_type: 'test',
        handshake_id: 'hs-1',
        created_at: new Date().toISOString(),
        detail: { note: 'fallback result' },
      },
    ];

    // We need two different resolutions: first textSearch fails, then ilike succeeds
    // The chain needs to detect which method was last called
    let usedTextSearch = false;

    const chain = {
      select: vi.fn().mockReturnThis(),
      textSearch: vi.fn().mockImplementation(() => {
        usedTextSearch = true;
        return chain;
      }),
      ilike: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnThis(),
      lte: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      then: (resolve) => {
        if (usedTextSearch) {
          usedTextSearch = false; // reset for next call
          return Promise.resolve({
            data: null,
            error: { message: 'text search not supported' },
          }).then(resolve);
        }
        return Promise.resolve({ data: fallbackData, error: null }).then(resolve);
      },
    };

    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const result = await searchEvents('fallback query');
    // At least the fallback path should have been tried
    expect(Array.isArray(result)).toBe(true);
  });
});
