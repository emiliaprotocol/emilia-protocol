/**
 * Tests for lib/signoff/deny.js — denyChallenge()
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ── Mock: Supabase ────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// ── Mock: requireSignoffEvent ─────────────────────────────────────────────────

const mockRequireSignoffEvent = vi.fn().mockResolvedValue({ event_id: 'ev-deny-1' });

vi.mock('../lib/signoff/events.js', () => ({
  requireSignoffEvent: (...args) => mockRequireSignoffEvent(...args),
}));

// ── Import under test (after mocks) ──────────────────────────────────────────

import { denyChallenge } from '../lib/signoff/deny.js';

// ── Supabase mock factory ─────────────────────────────────────────────────────

function makeMockSupabase({
  challenge = null,
  challengeError = null,
  updatedChallenge = null,
  updateError = null,
} = {}) {
  const single = vi.fn().mockResolvedValue({ data: updatedChallenge, error: updateError });
  const selectAfterUpdate = vi.fn().mockReturnValue({ single });
  const eqUpdate = vi.fn().mockReturnValue({ select: selectAfterUpdate });
  const updateFn = vi.fn().mockReturnValue({ eq: eqUpdate });

  const maybeSingle = vi.fn().mockResolvedValue({ data: challenge, error: challengeError });
  const eqSelect = vi.fn().mockReturnThis();
  const selectFn = vi.fn().mockReturnThis();

  const from = vi.fn().mockImplementation((tableName) => {
    if (tableName === 'signoff_challenges') {
      return {
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            maybeSingle,
          }),
        }),
        update: updateFn,
      };
    }
    return { select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis() };
  });

  return { from };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const ACTOR = { entity_id: 'entity-alice' };

function validChallenge(overrides = {}) {
  return {
    challenge_id: 'ch-1',
    handshake_id: 'hs-1',
    accountable_actor_ref: 'entity-alice',
    status: 'challenge_issued',
    ...overrides,
  };
}

function validParams(overrides = {}) {
  return {
    challengeId: 'ch-1',
    reason: 'User declined the action',
    actor: ACTOR,
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('denyChallenge — input validation', () => {
  it('throws MISSING_CHALLENGE_ID when challengeId is absent', async () => {
    await expect(denyChallenge({ actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_CHALLENGE_ID', status: 400 });
  });

  it('throws MISSING_ACTOR when actor is absent', async () => {
    await expect(denyChallenge({ challengeId: 'ch-1' }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });

  it('throws MISSING_ACTOR when actor has no entity_id', async () => {
    await expect(denyChallenge({ challengeId: 'ch-1', actor: {} }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });
});

describe('denyChallenge — DB fetch errors', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when challenge fetch fails', async () => {
    const supabase = makeMockSupabase({ challengeError: { message: 'connection refused' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws CHALLENGE_NOT_FOUND when challenge is null', async () => {
    const supabase = makeMockSupabase({ challenge: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND', status: 404 });
  });
});

describe('denyChallenge — authorization and state guards', () => {
  beforeEach(() => { vi.clearAllMocks(); mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-1' }); });

  it('throws FORBIDDEN when actor does not match accountable_actor_ref', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ accountable_actor_ref: 'entity-alice' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams({ actor: { entity_id: 'entity-bob' } })))
      .rejects.toMatchObject({ code: 'FORBIDDEN', status: 403 });
  });

  it('throws INVALID_STATE_FOR_DENIAL when challenge is in terminal state (denied)', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'denied' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_DENIAL', status: 409 });
  });

  it('throws INVALID_STATE_FOR_DENIAL when challenge is in terminal state (consumed)', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'consumed' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_DENIAL', status: 409 });
  });

  it('throws INVALID_STATE_FOR_DENIAL when challenge is in terminal state (revoked)', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'revoked' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_DENIAL', status: 409 });
  });

  it('throws INVALID_STATE_FOR_DENIAL when challenge is in terminal state (expired)', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'expired' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_DENIAL', status: 409 });
  });

  it('throws INVALID_STATE_FOR_DENIAL when challenge is in approved state', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'approved' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_DENIAL', status: 409 });
  });
});

describe('denyChallenge — happy path', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-deny' });
  });

  it('denies a challenge in challenge_issued status', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const denied = { ...challenge, status: 'denied' };
    const supabase = makeMockSupabase({ challenge, updatedChallenge: denied });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await denyChallenge(validParams());
    expect(result.status).toBe('denied');
  });

  it('denies a challenge in challenge_viewed status', async () => {
    const challenge = validChallenge({ status: 'challenge_viewed' });
    const denied = { ...challenge, status: 'denied' };
    const supabase = makeMockSupabase({ challenge, updatedChallenge: denied });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await denyChallenge(validParams());
    expect(result.status).toBe('denied');
  });

  it('emits a denied event before updating the challenge (event-first)', async () => {
    const callOrder = [];
    mockRequireSignoffEvent.mockImplementation(async () => {
      callOrder.push('event');
      return { event_id: 'ev-deny' };
    });

    const challenge = validChallenge({ status: 'challenge_issued' });
    const denied = { ...challenge, status: 'denied' };

    let updateCalled = false;
    const from = vi.fn().mockImplementation(() => ({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({ maybeSingle: vi.fn().mockResolvedValue({ data: challenge, error: null }) }),
      }),
      update: vi.fn().mockImplementation(() => {
        callOrder.push('update');
        updateCalled = true;
        return {
          eq: vi.fn().mockReturnValue({
            select: vi.fn().mockReturnValue({
              single: vi.fn().mockResolvedValue({ data: denied, error: null }),
            }),
          }),
        };
      }),
    }));
    mockGetServiceClient.mockReturnValue({ from });

    await denyChallenge(validParams());

    expect(callOrder[0]).toBe('event');
    expect(callOrder[1]).toBe('update');
  });

  it('calls requireSignoffEvent with correct parameters', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const denied = { ...challenge, status: 'denied' };
    const supabase = makeMockSupabase({ challenge, updatedChallenge: denied });
    mockGetServiceClient.mockReturnValue(supabase);

    await denyChallenge(validParams({ reason: 'I refuse' }));

    expect(mockRequireSignoffEvent).toHaveBeenCalledWith(expect.objectContaining({
      handshakeId: 'hs-1',
      challengeId: 'ch-1',
      eventType: 'denied',
      detail: { reason: 'I refuse' },
      actorEntityRef: 'entity-alice',
    }));
  });

  it('uses default denial reason when reason is not provided', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const denied = { ...challenge, status: 'denied' };
    const supabase = makeMockSupabase({ challenge, updatedChallenge: denied });
    mockGetServiceClient.mockReturnValue(supabase);

    await denyChallenge({ challengeId: 'ch-1', actor: ACTOR });

    expect(mockRequireSignoffEvent).toHaveBeenCalledWith(expect.objectContaining({
      detail: { reason: 'Human denied the action' },
    }));
  });

  it('throws DB_ERROR when update fails', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const supabase = makeMockSupabase({ challenge, updateError: { message: 'write failed' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(denyChallenge(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });
});
