/**
 * Tests for lib/signoff/revoke.js — revokeChallenge() and revokeAttestation()
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

const mockRequireSignoffEvent = vi.fn().mockResolvedValue({ event_id: 'ev-rev-1' });

vi.mock('../lib/signoff/events.js', () => ({
  requireSignoffEvent: (...args) => mockRequireSignoffEvent(...args),
}));

// ── Import under test (after mocks) ──────────────────────────────────────────

import { revokeChallenge, revokeAttestation } from '../lib/signoff/revoke.js';

// ── Mock factory helpers ──────────────────────────────────────────────────────

function makeChallengeMock({ challenge = null, challengeError = null, updatedChallenge = null, updateError = null } = {}) {
  const single = vi.fn().mockResolvedValue({ data: updatedChallenge, error: updateError });
  const selectAfterUpdate = vi.fn().mockReturnValue({ single });
  const eqUpdate = vi.fn().mockReturnValue({ select: selectAfterUpdate });
  const updateFn = vi.fn().mockReturnValue({ eq: eqUpdate });

  const from = vi.fn().mockImplementation(() => ({
    select: vi.fn().mockReturnValue({
      eq: vi.fn().mockReturnValue({
        maybeSingle: vi.fn().mockResolvedValue({ data: challenge, error: challengeError }),
      }),
    }),
    update: updateFn,
  }));

  return { from };
}

function makeAttestationMock({ attestation = null, attestationError = null, updatedAttestation = null, updateError = null } = {}) {
  const single = vi.fn().mockResolvedValue({ data: updatedAttestation, error: updateError });
  const selectAfterUpdate = vi.fn().mockReturnValue({ single });
  const eqUpdate = vi.fn().mockReturnValue({ select: selectAfterUpdate });
  const updateFn = vi.fn().mockReturnValue({ eq: eqUpdate });

  const from = vi.fn().mockImplementation(() => ({
    select: vi.fn().mockReturnValue({
      eq: vi.fn().mockReturnValue({
        maybeSingle: vi.fn().mockResolvedValue({ data: attestation, error: attestationError }),
      }),
    }),
    update: updateFn,
  }));

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

function validAttestation(overrides = {}) {
  return {
    signoff_id: 'sig-1',
    challenge_id: 'ch-1',
    handshake_id: 'hs-1',
    human_entity_ref: 'entity-alice',
    status: 'approved',
    ...overrides,
  };
}

// ── revokeChallenge tests ─────────────────────────────────────────────────────

describe('revokeChallenge — input validation', () => {
  it('throws MISSING_CHALLENGE_ID when challengeId is absent', async () => {
    await expect(revokeChallenge({ reason: 'x', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_CHALLENGE_ID', status: 400 });
  });

  it('throws MISSING_REASON when reason is absent', async () => {
    await expect(revokeChallenge({ challengeId: 'ch-1', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_REASON', status: 400 });
  });

  it('throws MISSING_ACTOR when actor is absent', async () => {
    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'policy change' }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });

  it('throws MISSING_ACTOR when actor has no entity_id', async () => {
    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'x', actor: {} }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });
});

describe('revokeChallenge — DB fetch errors', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when challenge fetch fails', async () => {
    const supabase = makeChallengeMock({ challengeError: { message: 'db error' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws CHALLENGE_NOT_FOUND when challenge is null', async () => {
    const supabase = makeChallengeMock({ challenge: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND', status: 404 });
  });
});

describe('revokeChallenge — authorization and state guards', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-1' });
  });

  it('throws FORBIDDEN when actor is not the accountable actor', async () => {
    const supabase = makeChallengeMock({ challenge: validChallenge({ accountable_actor_ref: 'entity-alice' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'x', actor: { entity_id: 'entity-bob' } }))
      .rejects.toMatchObject({ code: 'FORBIDDEN', status: 403 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION when challenge is in terminal state (revoked)', async () => {
    const supabase = makeChallengeMock({ challenge: validChallenge({ status: 'revoked' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION when challenge is in terminal state (denied)', async () => {
    const supabase = makeChallengeMock({ challenge: validChallenge({ status: 'denied' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION when challenge is in terminal state (consumed)', async () => {
    const supabase = makeChallengeMock({ challenge: validChallenge({ status: 'consumed' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION when challenge is in approved state', async () => {
    const supabase = makeChallengeMock({ challenge: validChallenge({ status: 'approved' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });
});

describe('revokeChallenge — happy path', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-revoke' });
  });

  it('revokes a challenge in challenge_issued status', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const revoked = { ...challenge, status: 'revoked', revocation_reason: 'policy change' };
    const supabase = makeChallengeMock({ challenge, updatedChallenge: revoked });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await revokeChallenge({ challengeId: 'ch-1', reason: 'policy change', actor: ACTOR });
    expect(result.status).toBe('revoked');
    expect(result.revocation_reason).toBe('policy change');
  });

  it('revokes a challenge in challenge_viewed status', async () => {
    const challenge = validChallenge({ status: 'challenge_viewed' });
    const revoked = { ...challenge, status: 'revoked' };
    const supabase = makeChallengeMock({ challenge, updatedChallenge: revoked });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await revokeChallenge({ challengeId: 'ch-1', reason: 'timeout', actor: ACTOR });
    expect(result.status).toBe('revoked');
  });

  it('emits revoked event with system actor ref', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const revoked = { ...challenge, status: 'revoked' };
    const supabase = makeChallengeMock({ challenge, updatedChallenge: revoked });
    mockGetServiceClient.mockReturnValue(supabase);

    await revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR });

    expect(mockRequireSignoffEvent).toHaveBeenCalledWith(expect.objectContaining({
      eventType: 'revoked',
      actorEntityRef: 'system',
      detail: { reason: 'test' },
    }));
  });

  it('throws DB_ERROR when update fails', async () => {
    const challenge = validChallenge({ status: 'challenge_issued' });
    const supabase = makeChallengeMock({ challenge, updateError: { message: 'write failed' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeChallenge({ challengeId: 'ch-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });
});

// ── revokeAttestation tests ───────────────────────────────────────────────────

describe('revokeAttestation — input validation', () => {
  it('throws MISSING_SIGNOFF_ID when signoffId is absent', async () => {
    await expect(revokeAttestation({ reason: 'x', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_SIGNOFF_ID', status: 400 });
  });

  it('throws MISSING_REASON when reason is absent', async () => {
    await expect(revokeAttestation({ signoffId: 'sig-1', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_REASON', status: 400 });
  });

  it('throws MISSING_ACTOR when actor is absent', async () => {
    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'x' }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });
});

describe('revokeAttestation — DB fetch errors', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when attestation fetch fails', async () => {
    const supabase = makeAttestationMock({ attestationError: { message: 'connection error' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws ATTESTATION_NOT_FOUND when attestation is null', async () => {
    const supabase = makeAttestationMock({ attestation: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'ATTESTATION_NOT_FOUND', status: 404 });
  });
});

describe('revokeAttestation — authorization and state guards', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-1' });
  });

  it('throws FORBIDDEN when actor is not the accountable human entity', async () => {
    const supabase = makeAttestationMock({ attestation: validAttestation({ human_entity_ref: 'entity-alice' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'x', actor: { entity_id: 'entity-mallory' } }))
      .rejects.toMatchObject({ code: 'FORBIDDEN', status: 403 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION for consumed attestation', async () => {
    const supabase = makeAttestationMock({ attestation: validAttestation({ status: 'consumed' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION for already-revoked attestation', async () => {
    const supabase = makeAttestationMock({ attestation: validAttestation({ status: 'revoked' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION for expired attestation', async () => {
    const supabase = makeAttestationMock({ attestation: validAttestation({ status: 'expired' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });

  it('throws INVALID_STATE_FOR_REVOCATION when attestation is not in approved status', async () => {
    const supabase = makeAttestationMock({ attestation: validAttestation({ status: 'pending' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'INVALID_STATE_FOR_REVOCATION', status: 409 });
  });
});

describe('revokeAttestation — happy path', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-att-revoke' });
  });

  it('revokes an approved attestation', async () => {
    const attestation = validAttestation({ status: 'approved' });
    const revoked = { ...attestation, status: 'revoked', revocation_reason: 'fraud detected' };
    const supabase = makeAttestationMock({ attestation, updatedAttestation: revoked });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await revokeAttestation({ signoffId: 'sig-1', reason: 'fraud detected', actor: ACTOR });
    expect(result.status).toBe('revoked');
  });

  it('emits attestation_revoked event', async () => {
    const attestation = validAttestation({ status: 'approved' });
    const revoked = { ...attestation, status: 'revoked' };
    const supabase = makeAttestationMock({ attestation, updatedAttestation: revoked });
    mockGetServiceClient.mockReturnValue(supabase);

    await revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR });

    expect(mockRequireSignoffEvent).toHaveBeenCalledWith(expect.objectContaining({
      eventType: 'attestation_revoked',
      signoffId: 'sig-1',
      actorEntityRef: 'entity-alice',
    }));
  });

  it('throws DB_ERROR when attestation update fails', async () => {
    const attestation = validAttestation({ status: 'approved' });
    const supabase = makeAttestationMock({ attestation, updateError: { message: 'write error' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(revokeAttestation({ signoffId: 'sig-1', reason: 'test', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });
});
