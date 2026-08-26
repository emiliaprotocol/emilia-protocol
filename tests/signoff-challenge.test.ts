/**
 * Tests for lib/signoff/challenge.js — issueChallenge()
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

import { issueChallenge } from '../lib/signoff/challenge.js';
import { SignoffError } from '../lib/signoff/errors.js';

// ── Supabase mock factory ─────────────────────────────────────────────────────

/**
 * Build a mock supabase client.
 * Supports two sequential .from() calls: handshakes then handshake_bindings.
 * Each call returns its own maybeSingle result.
 */
function makeMockSupabase({
  handshake = null,
  handshakeError = null,
  parties = [
    { entity_ref: 'entity-issuer', party_role: 'initiator' },
    { entity_ref: 'entity-alice', party_role: 'responder' },
  ],
  partyError = null,
  binding = null,
  bindingError = null,
  rpcData = null,
  rpcError = null,
} = {}) {
  let callCount = 0;
  const rpc = vi.fn().mockResolvedValue({ data: rpcData, error: rpcError });

  const from = vi.fn().mockImplementation((tableName) => {
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockImplementation(() => {
        if (tableName === 'handshakes') {
          return Promise.resolve({ data: handshake, error: handshakeError });
        }
        if (tableName === 'handshake_bindings') {
          return Promise.resolve({ data: binding, error: bindingError });
        }
        return Promise.resolve({ data: null, error: null });
      }),
      then: (resolve, reject) => {
        const value = tableName === 'handshake_parties'
          ? { data: parties, error: partyError }
          : { data: null, error: null };
        return Promise.resolve(value).then(resolve, reject);
      },
    };
    return chain;
  });

  return { from, rpc };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function validHandshake() {
  return { handshake_id: 'hs-1', status: 'verified' };
}

function validBinding() {
  return { handshake_id: 'hs-1', binding_hash: 'sha256-binding-abc' };
}

function validParams(overrides = {}) {
  return {
    handshakeId: 'hs-1',
    actor: { entity_id: 'entity-issuer' },
    bindingHash: 'sha256-binding-abc',
    expiresAt: '2099-01-01T00:00:00Z',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('issueChallenge — input validation', () => {
  it('throws MISSING_HANDSHAKE_ID when handshakeId is absent', async () => {
    await expect(issueChallenge({ bindingHash: 'x', expiresAt: '2099-01-01Z' }))
      .rejects.toMatchObject({ code: 'MISSING_HANDSHAKE_ID', status: 400 });
  });

  it('throws MISSING_BINDING_HASH when bindingHash is absent', async () => {
    await expect(issueChallenge({ handshakeId: 'hs-1', expiresAt: '2099-01-01Z' }))
      .rejects.toMatchObject({ code: 'MISSING_BINDING_HASH', status: 400 });
  });

  it('throws MISSING_EXPIRES_AT when expiresAt is absent', async () => {
    await expect(issueChallenge({ ...validParams(), expiresAt: null }))
      .rejects.toMatchObject({ code: 'MISSING_EXPIRES_AT', status: 400 });
  });

  it('requires an authenticated issuer actor', async () => {
    await expect(issueChallenge({ ...validParams(), actor: null }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 401 });
  });
});

describe('issueChallenge — handshake DB checks', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when handshake fetch fails', async () => {
    const supabase = makeMockSupabase({ handshakeError: { message: 'connection refused' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws HANDSHAKE_NOT_FOUND when handshake is null', async () => {
    const supabase = makeMockSupabase({ handshake: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'HANDSHAKE_NOT_FOUND', status: 404 });
  });

  it('throws INVALID_HANDSHAKE_STATE when handshake status is not verified', async () => {
    const supabase = makeMockSupabase({ handshake: { handshake_id: 'hs-1', status: 'pending' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_HANDSHAKE_STATE', status: 409 });
  });

  it('throws INVALID_HANDSHAKE_STATE for completed handshake', async () => {
    const supabase = makeMockSupabase({ handshake: { handshake_id: 'hs-1', status: 'completed' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_HANDSHAKE_STATE', status: 409 });
  });
});

describe('issueChallenge — binding DB checks', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws CALLER_NOT_HANDSHAKE_PARTY when actor is not on the handshake', async () => {
    const supabase = makeMockSupabase({
      handshake: validHandshake(),
      parties: [{ entity_ref: 'entity-alice', party_role: 'responder' }],
      binding: validBinding(),
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams({ actor: { entity_id: 'entity-outsider' } })))
      .rejects.toMatchObject({ code: 'CALLER_NOT_HANDSHAKE_PARTY', status: 403 });
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it('does not use a caller-supplied accountable actor', async () => {
    const supabase = makeMockSupabase({
      handshake: validHandshake(),
      parties: [{ entity_ref: 'entity-issuer', party_role: 'initiator' }],
      binding: validBinding(),
      rpcData: { challenge_id: 'ch-derived' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await issueChallenge(validParams({ accountableActorRef: 'entity-outsider' }));
    const [, args] = supabase.rpc.mock.calls[0];
    expect(args).not.toHaveProperty('p_accountable_actor_ref');
  });

  it('throws DB_ERROR when binding fetch fails', async () => {
    const supabase = makeMockSupabase({
      handshake: validHandshake(),
      bindingError: { message: 'query timeout' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws BINDING_NOT_FOUND when binding is null', async () => {
    const supabase = makeMockSupabase({ handshake: validHandshake(), binding: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'BINDING_NOT_FOUND', status: 404 });
  });

  it('throws BINDING_HASH_MISMATCH when binding_hash does not match', async () => {
    const supabase = makeMockSupabase({
      handshake: validHandshake(),
      binding: { binding_hash: 'sha256-DIFFERENT' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'BINDING_HASH_MISMATCH', status: 409 });
  });
});

describe('issueChallenge — RPC and happy path', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when RPC fails', async () => {
    const supabase = makeMockSupabase({
      handshake: validHandshake(),
      binding: validBinding(),
      rpcError: { message: 'rpc error' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it.each([
    ['SIGNOFF_BINDING_EXPIRED', 'BINDING_EXPIRED', 410],
    ['SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED', 'BINDING_NOT_VERIFICATION_FINALIZED', 409],
    ['SIGNOFF_AUTHORITY_ALREADY_CONSUMED', 'AUTHORITY_ALREADY_CONSUMED', 409],
    ['SIGNOFF_POLICY_HASH_MISMATCH', 'SIGNOFF_POLICY_HASH_MISMATCH', 409],
    ['SIGNOFF_POLICY_BLOCK_INVALID', 'SIGNOFF_POLICY_BLOCK_INVALID', 409],
    ['SIGNOFF_ACCOUNTABLE_AUTHORITY_UNAVAILABLE', 'SIGNOFF_ACCOUNTABLE_AUTHORITY_UNAVAILABLE', 403],
  ])('maps authority-window RPC error %s to %s/%s', async (message, code, status) => {
    const supabase = makeMockSupabase({
      handshake: validHandshake(),
      binding: validBinding(),
      rpcError: { message },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(issueChallenge(validParams()))
      .rejects.toMatchObject({ code, status });
  });

  it('returns challenge record with _protocolEventWritten on success', async () => {
    const rpcData = { challenge_id: 'ch-new', handshake_id: 'hs-1', status: 'challenge_issued' };
    const supabase = makeMockSupabase({ handshake: validHandshake(), binding: validBinding(), rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await issueChallenge(validParams());
    expect(result.challenge_id).toBe('ch-new');
    expect(result._protocolEventWritten).toBe(true);
  });

  it('calls issue_challenge_atomic RPC with correct parameters', async () => {
    const rpcData = { challenge_id: 'ch-new2', status: 'challenge_issued' };
    const supabase = makeMockSupabase({ handshake: validHandshake(), binding: validBinding(), rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    await issueChallenge(validParams({
      accountableActorRef: 'entity-outsider',
      signoffPolicyId: 'attacker-policy',
      signoffPolicyHash: 'attacker-hash',
      requiredAssurance: 'low',
      allowedMethods: ['out_of_band'],
    }));

    expect(supabase.rpc).toHaveBeenCalledWith('issue_challenge_atomic', expect.objectContaining({
      p_handshake_id: 'hs-1',
      p_binding_hash: 'sha256-binding-abc',
      p_actor_entity_ref: 'entity-issuer',
      p_requested_expires_at: '2099-01-01T00:00:00Z',
    }));
    const [, rpcArgs] = supabase.rpc.mock.calls[0];
    for (const forbidden of [
      'p_accountable_actor_ref',
      'p_signoff_policy_id',
      'p_signoff_policy_hash',
      'p_required_assurance',
      'p_allowed_methods',
    ]) {
      expect(rpcArgs).not.toHaveProperty(forbidden);
    }
  });

  it('passes optional metadata to RPC', async () => {
    const rpcData = { challenge_id: 'ch-meta', status: 'challenge_issued' };
    const supabase = makeMockSupabase({ handshake: validHandshake(), binding: validBinding(), rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const meta = { source: 'test-suite', priority: 'high' };
    await issueChallenge(validParams({ metadata: meta }));

    expect(supabase.rpc).toHaveBeenCalledWith('issue_challenge_atomic', expect.objectContaining({
      p_metadata_json: meta,
    }));
  });

  it('never sends client-defined policy semantics', async () => {
    const rpcData = { challenge_id: 'ch-nohash', status: 'challenge_issued' };
    const supabase = makeMockSupabase({ handshake: validHandshake(), binding: validBinding(), rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    await issueChallenge(validParams());

    const [, args] = supabase.rpc.mock.calls[0];
    expect(args).not.toHaveProperty('p_signoff_policy_hash');
    expect(args).not.toHaveProperty('p_signoff_policy_id');
  });
});
