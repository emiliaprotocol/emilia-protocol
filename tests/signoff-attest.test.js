/**
 * Tests for lib/signoff/attest.js — createAttestation()
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

// ── Import under test (after mocks) ──────────────────────────────────────────

import { createAttestation } from '../lib/signoff/attest.js';
import { SignoffError } from '../lib/signoff/errors.js';
import {
  VALID_ALLOWED_METHODS,
  VALID_ASSURANCE_LEVELS,
  SIGNOFF_ASSURANCE_RANK,
} from '../lib/signoff/invariants.js';

// ── Supabase mock factory ─────────────────────────────────────────────────────

function makeMockSupabase({ challenge = null, challengeError = null, rpcData = null, rpcError = null } = {}) {
  const rpc = vi.fn().mockResolvedValue({ data: rpcData, error: rpcError });

  const maybeSingle = vi.fn().mockResolvedValue({ data: challenge, error: challengeError });
  const eqFn = vi.fn().mockReturnThis();
  const selectFn = vi.fn().mockReturnThis();
  const fromFn = vi.fn().mockReturnValue({
    select: selectFn,
    eq: eqFn,
    maybeSingle,
  });

  return { from: fromFn, rpc };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_ACTOR = { entity_id: 'entity-alice' };

function validChallenge(overrides = {}) {
  return {
    challenge_id: 'ch-1',
    handshake_id: 'hs-1',
    binding_hash: 'sha256-binding-abc',
    accountable_actor_ref: 'entity-alice',
    required_assurance: 'substantial',
    allowed_methods: ['passkey', 'secure_app'],
    status: 'challenge_issued',
    ...overrides,
  };
}

function validParams(overrides = {}) {
  return {
    challengeId: 'ch-1',
    handshakeId: 'hs-1',
    bindingHash: 'sha256-binding-abc',
    humanEntityRef: 'entity-alice',
    authMethod: 'passkey',
    assuranceLevel: 'substantial',
    actor: VALID_ACTOR,
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('createAttestation — input validation', () => {
  it('throws MISSING_CHALLENGE_ID when challengeId is absent', async () => {
    await expect(createAttestation({ humanEntityRef: 'x', authMethod: 'passkey', assuranceLevel: 'substantial' }))
      .rejects.toMatchObject({ code: 'MISSING_CHALLENGE_ID', status: 400 });
  });

  it('throws MISSING_HUMAN_ENTITY_REF when humanEntityRef is absent', async () => {
    await expect(createAttestation({ challengeId: 'ch-1', authMethod: 'passkey', assuranceLevel: 'substantial' }))
      .rejects.toMatchObject({ code: 'MISSING_HUMAN_ENTITY_REF', status: 400 });
  });

  it('throws INVALID_AUTH_METHOD when authMethod is null', async () => {
    await expect(createAttestation({ challengeId: 'ch-1', humanEntityRef: 'x', authMethod: null, assuranceLevel: 'substantial' }))
      .rejects.toMatchObject({ code: 'INVALID_AUTH_METHOD', status: 400 });
  });

  it('throws INVALID_AUTH_METHOD when authMethod is unrecognized', async () => {
    await expect(createAttestation({ challengeId: 'ch-1', humanEntityRef: 'x', authMethod: 'sms_otp', assuranceLevel: 'substantial' }))
      .rejects.toMatchObject({ code: 'INVALID_AUTH_METHOD', status: 400 });
  });

  it('throws INVALID_ASSURANCE_LEVEL when assuranceLevel is unrecognized', async () => {
    await expect(createAttestation({ challengeId: 'ch-1', humanEntityRef: 'x', authMethod: 'passkey', assuranceLevel: 'ultra' }))
      .rejects.toMatchObject({ code: 'INVALID_ASSURANCE_LEVEL', status: 400 });
  });

  it('throws INVALID_ASSURANCE_LEVEL when assuranceLevel is null', async () => {
    await expect(createAttestation({ challengeId: 'ch-1', humanEntityRef: 'x', authMethod: 'passkey', assuranceLevel: null }))
      .rejects.toMatchObject({ code: 'INVALID_ASSURANCE_LEVEL', status: 400 });
  });
});

describe('createAttestation — DB fetch errors', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when challenge fetch fails', async () => {
    const supabase = makeMockSupabase({ challengeError: { message: 'connection timeout' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws CHALLENGE_NOT_FOUND when challenge is null', async () => {
    const supabase = makeMockSupabase({ challenge: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams()))
      .rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND', status: 404 });
  });
});

describe('createAttestation — authorization and state guards', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws SIGNOFF_ACTOR_MISMATCH when actor does not match accountable_actor_ref', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ accountable_actor_ref: 'entity-alice' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams({ actor: { entity_id: 'entity-bob' } })))
      .rejects.toMatchObject({ code: 'SIGNOFF_ACTOR_MISMATCH', status: 403 });
  });

  it('throws SIGNOFF_HANDSHAKE_MISMATCH when explicit handshakeId does not match challenge', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ handshake_id: 'hs-REAL' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams({ handshakeId: 'hs-DIFFERENT' })))
      .rejects.toMatchObject({ code: 'SIGNOFF_HANDSHAKE_MISMATCH', status: 400 });
  });

  it('throws INVALID_CHALLENGE_STATE when challenge is in terminal state (denied)', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'denied' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_CHALLENGE_STATE', status: 409 });
  });

  it('throws INVALID_CHALLENGE_STATE when challenge is already approved', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ status: 'approved' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_CHALLENGE_STATE', status: 409 });
  });

  it('accepts challenge in challenge_viewed status', async () => {
    const challenge = validChallenge({ status: 'challenge_viewed' });
    const rpcData = { signoff_id: crypto.randomUUID(), status: 'approved' };
    const supabase = makeMockSupabase({ challenge, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await createAttestation(validParams());
    expect(result._protocolEventWritten).toBe(true);
  });

  it('throws BINDING_HASH_MISMATCH when explicit bindingHash does not match challenge', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ binding_hash: 'sha256-real-hash' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams({ bindingHash: 'sha256-WRONG-hash' })))
      .rejects.toMatchObject({ code: 'BINDING_HASH_MISMATCH', status: 409 });
  });

  it('throws METHOD_NOT_ALLOWED when authMethod not in challenge allowed_methods', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ allowed_methods: ['passkey'] }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams({ authMethod: 'secure_app' })))
      .rejects.toMatchObject({ code: 'METHOD_NOT_ALLOWED', status: 403 });
  });

  it('throws ASSURANCE_BELOW_MINIMUM when assuranceLevel rank is below required', async () => {
    const supabase = makeMockSupabase({ challenge: validChallenge({ required_assurance: 'high' }) });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams({ assuranceLevel: 'low' })))
      .rejects.toMatchObject({ code: 'ASSURANCE_BELOW_MINIMUM', status: 403 });
  });
});

describe('createAttestation — RPC errors and happy path', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when RPC fails', async () => {
    const challenge = validChallenge();
    const supabase = makeMockSupabase({ challenge, rpcError: { message: 'rpc failed' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('returns attestation record with _protocolEventWritten flag on success', async () => {
    const challenge = validChallenge();
    const rpcData = { signoff_id: 'sig-001', status: 'approved', challenge_id: 'ch-1' };
    const supabase = makeMockSupabase({ challenge, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await createAttestation(validParams());
    expect(result.signoff_id).toBe('sig-001');
    expect(result._protocolEventWritten).toBe(true);
  });

  it('calls approve_attestation_atomic RPC with correct parameters', async () => {
    const challenge = validChallenge();
    const rpcData = { signoff_id: 'sig-002', status: 'approved' };
    const supabase = makeMockSupabase({ challenge, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    await createAttestation(validParams({ channel: 'web', expiresAt: '2099-01-01T00:00:00Z' }));

    expect(supabase.rpc).toHaveBeenCalledWith('approve_attestation_atomic', expect.objectContaining({
      p_challenge_id: 'ch-1',
      p_handshake_id: 'hs-1',
      p_auth_method: 'passkey',
      p_assurance_level: 'substantial',
      p_channel: 'web',
      p_expires_at: '2099-01-01T00:00:00Z',
    }));
  });

  it('derives handshakeId and bindingHash from challenge when not explicitly provided', async () => {
    const challenge = validChallenge({ handshake_id: 'hs-from-challenge', binding_hash: 'sha256-from-challenge' });
    const rpcData = { signoff_id: 'sig-003', status: 'approved' };
    const supabase = makeMockSupabase({ challenge, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const params = validParams();
    delete params.handshakeId;
    delete params.bindingHash;
    await createAttestation(params);

    expect(supabase.rpc).toHaveBeenCalledWith('approve_attestation_atomic', expect.objectContaining({
      p_handshake_id: 'hs-from-challenge',
      p_binding_hash: 'sha256-from-challenge',
    }));
  });

  it('higher assurance level (high > substantial) satisfies required substantial', async () => {
    const challenge = validChallenge({ required_assurance: 'substantial', allowed_methods: ['passkey', 'out_of_band'] });
    const rpcData = { signoff_id: 'sig-004', status: 'approved' };
    const supabase = makeMockSupabase({ challenge, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await createAttestation(validParams({ assuranceLevel: 'high', authMethod: 'out_of_band' }));
    expect(result._protocolEventWritten).toBe(true);
  });

  it('challenge with empty allowed_methods causes METHOD_NOT_ALLOWED', async () => {
    const challenge = validChallenge({ allowed_methods: [] });
    const supabase = makeMockSupabase({ challenge });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(createAttestation(validParams()))
      .rejects.toMatchObject({ code: 'METHOD_NOT_ALLOWED', status: 403 });
  });
});
