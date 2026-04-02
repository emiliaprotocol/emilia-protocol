/**
 * lib/signoff/events.js — extended coverage for uncovered lines.
 *
 * Uncovered lines:
 *   88-90  emitSignoffEvent: non-table-missing error → console.warn
 *   154    requireSignoffEvent: DB error path → throws
 *   184    getSignoffEvents: DB error path → throws
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/actor.js', () => ({
  resolveActorRef: (actor) => (typeof actor === 'string' ? actor : 'system'),
}));

import {
  emitSignoffEvent,
  requireSignoffEvent,
  getSignoffEvents,
} from '../lib/signoff/events.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeChain(resolved) {
  const chain = {
    insert: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolved),
    then: (resolve, reject) => Promise.resolve(resolved).then(resolve, reject),
  };
  return chain;
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ── emitSignoffEvent: non-table-missing error console.warn (lines 88-90) ─────

describe('emitSignoffEvent — non-table-missing error', () => {
  it('logs console.warn when error is NOT a missing table error', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const supabase = {
      from: vi.fn(() => ({
        insert: vi.fn().mockRejectedValue(new Error('permission denied')),
      })),
    };
    mockGetServiceClient.mockReturnValue(supabase);

    // Should not throw even though insert fails
    await expect(
      emitSignoffEvent({
        challengeId: 'ch-1',
        eventType: 'challenge_issued',
        detail: {},
      })
    ).resolves.not.toThrow();

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[signoff-events]'),
      expect.stringContaining('permission denied')
    );
    warnSpy.mockRestore();
  });

  it('does NOT console.warn when error is a missing table error', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const supabase = {
      from: vi.fn(() => ({
        insert: vi.fn().mockRejectedValue(new Error('relation "signoff_events" does not exist')),
      })),
    };
    mockGetServiceClient.mockReturnValue(supabase);

    await emitSignoffEvent({
      challengeId: 'ch-2',
      eventType: 'challenge_issued',
    });

    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});

// ── requireSignoffEvent: DB error throws (line 154) ──────────────────────────

describe('requireSignoffEvent — DB error path', () => {
  it('throws when the DB insert returns an error — line 154', async () => {
    const chain = {
      insert: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({
        data: null,
        error: { message: 'unique constraint violation' },
      }),
    };
    const supabase = { from: vi.fn(() => chain) };
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(
      requireSignoffEvent({
        challengeId: 'ch-req-1',
        eventType: 'approved',
        detail: { method: 'biometric' },
      })
    ).rejects.toThrow('SIGNOFF_EVENT_WRITE_REQUIRED');
  });
});

// ── getSignoffEvents: DB error throws (line 184) ─────────────────────────────

describe('getSignoffEvents — DB error path', () => {
  it('throws SignoffEventError when DB query fails — line 184', async () => {
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockResolvedValue({ data: null, error: { message: 'timeout' } }),
    };
    const supabase = { from: vi.fn(() => chain) };
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(getSignoffEvents('ch-123')).rejects.toThrow('Failed to fetch events');
  });

  it('throws when challengeId is missing', async () => {
    await expect(getSignoffEvents(null)).rejects.toThrow('challengeId is required');
  });
});
