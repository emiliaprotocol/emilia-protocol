/**
 * lib/handshake/events.js — extended coverage for uncovered lines.
 *
 * Uncovered lines:
 *   137    recordHandshakeEvent: insert DB error → throws HandshakeEventError
 *   156    getHandshakeEvents: missing handshake_id → throws
 *   166    getHandshakeEvents: DB query error → throws
 *   217    requireHandshakeEvent: insert DB error → throws
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/actor.js', () => ({
  resolveActorRef: (actor) => (typeof actor === 'string' ? actor : 'system'),
}));

vi.mock('@/lib/crypto', () => ({
  sha256: (s) => 'sha256:' + s,
}));

import {
  recordHandshakeEvent,
  getHandshakeEvents,
  requireHandshakeEvent,
} from '../lib/handshake/events.js';

function makeChain(resolved) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolved),
    single: vi.fn().mockResolvedValue(resolved),
    then: (resolve, reject) => Promise.resolve(resolved).then(resolve, reject),
  };
  return chain;
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ── recordHandshakeEvent: insert DB error (line 137) ─────────────────────────

describe('recordHandshakeEvent — insert DB error', () => {
  it('throws HandshakeEventError when insert fails — line 137', async () => {
    const supabase = {
      from: vi.fn().mockImplementation(() => {
        const chain = makeChain({ data: null, error: null }); // idempotency check: no existing
        chain.maybeSingle = vi.fn().mockResolvedValue({ data: null, error: null });
        chain.single = vi.fn().mockResolvedValue({
          data: null,
          error: { message: 'insert constraint violation' },
        });
        return chain;
      }),
    };

    await expect(
      recordHandshakeEvent(supabase, {
        handshake_id: 'hs-1',
        event_type: 'initiated',
        actor_id: 'system',
      })
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });

  it('returns existing record when idempotency key already exists', async () => {
    const existing = { event_id: 'evt-existing', handshake_id: 'hs-1' };
    const supabase = {
      from: vi.fn().mockImplementation(() => {
        const chain = makeChain({ data: existing, error: null });
        chain.maybeSingle = vi.fn().mockResolvedValue({ data: existing, error: null });
        return chain;
      }),
    };

    const result = await recordHandshakeEvent(supabase, {
      handshake_id: 'hs-1',
      event_type: 'initiated',
      actor_id: 'system',
    });

    expect(result).toEqual(existing);
  });
});

// ── getHandshakeEvents: missing handshake_id (line 156) ──────────────────────

describe('getHandshakeEvents — missing handshake_id', () => {
  it('throws when handshake_id is null — line 156', async () => {
    const supabase = { from: vi.fn() };
    await expect(getHandshakeEvents(supabase, null)).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });
  });

  it('throws when handshake_id is undefined', async () => {
    const supabase = { from: vi.fn() };
    await expect(getHandshakeEvents(supabase, undefined)).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });
  });
});

// ── getHandshakeEvents: DB query error (line 166) ────────────────────────────

describe('getHandshakeEvents — DB query error', () => {
  it('throws HandshakeEventError when query fails — line 166', async () => {
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockResolvedValue({ data: null, error: { message: 'connection refused' } }),
    };
    const supabase = { from: vi.fn(() => chain) };

    await expect(getHandshakeEvents(supabase, 'hs-1')).rejects.toMatchObject({
      code: 'DB_ERROR',
    });
  });
});

// ── requireHandshakeEvent: insert DB error (line 217) ────────────────────────

describe('requireHandshakeEvent — insert DB error', () => {
  it('throws Error when the mandatory event insert fails — line 217', async () => {
    const chain = {
      insert: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({
        data: null,
        error: { message: 'db write failed' },
      }),
    };
    const supabase = { from: vi.fn(() => chain) };
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(
      requireHandshakeEvent({
        handshake_id: 'hs-req-1',
        event_type: 'verified',
        actor: 'system',
        detail: { outcome: 'accepted' },
      })
    ).rejects.toThrow('EVENT_WRITE_REQUIRED');
  });
});
