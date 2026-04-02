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
    bindingHash: 'sha256-binding-abc',
    accountableActorRef: 'entity-alice',
    signoffPolicyId: 'policy-001',
    requiredAssurance: 'substantial',
    allowedMethods: ['passkey', 'secure_app'],
    expiresAt: '2099-01-01T00:00:00Z',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('issueChallenge — input validation', () => {
  it('throws MISSING_HANDSHAKE_ID when handshakeId is absent', async () => {
    await expect(issueChallenge({ bindingHash: 'x', accountableActorRef: 'a', signoffPolicyId: 'p', requiredAssurance: 'low', allowedMethods: ['passkey'], expiresAt: '2099-01-01Z' }))
      .rejects.toMatchObject({ code: 'MISSING_HANDSHAKE_ID', status: 400 });
  });

  it('throws MISSING_BINDING_HASH when bindingHash is absent', async () => {
    await expect(issueChallenge({ handshakeId: 'hs-1', accountableActorRef: 'a', signoffPolicyId: 'p', requiredAssurance: 'low', allowedMethods: ['passkey'], expiresAt: '2099-01-01Z' }))
      .rejects.toMatchObject({ code: 'MISSING_BINDING_HASH', status: 400 });
  });

  it('throws MISSING_ACTOR_REF when accountableActorRef is absent', async () => {
    await expect(issueChallenge({ handshakeId: 'hs-1', bindingHash: 'x', signoffPolicyId: 'p', requiredAssurance: 'low', allowedMethods: ['passkey'], expiresAt: '2099-01-01Z' }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR_REF', status: 400 });
  });

  it('throws MISSING_POLICY_ID when signoffPolicyId is absent', async () => {
    await expect(issueChallenge({ handshakeId: 'hs-1', bindingHash: 'x', accountableActorRef: 'a', requiredAssurance: 'low', allowedMethods: ['passkey'], expiresAt: '2099-01-01Z' }))
      .rejects.toMatchObject({ code: 'MISSING_POLICY_ID', status: 400 });
  });

  it('throws INVALID_ASSURANCE_LEVEL for unrecognized requiredAssurance', async () => {
    await expect(issueChallenge({ ...validParams(), requiredAssurance: 'ultra' }))
      .rejects.toMatchObject({ code: 'INVALID_ASSURANCE_LEVEL', status: 400 });
  });

  it('throws INVALID_ASSURANCE_LEVEL when requiredAssurance is null', async () => {
    await expect(issueChallenge({ ...validParams(), requiredAssurance: null }))
      .rejects.toMatchObject({ code: 'INVALID_ASSURANCE_LEVEL', status: 400 });
  });

  it('throws MISSING_ALLOWED_METHODS when allowedMethods is empty array', async () => {
    await expect(issueChallenge({ ...validParams(), allowedMethods: [] }))
      .rejects.toMatchObject({ code: 'MISSING_ALLOWED_METHODS', status: 400 });
  });

  it('throws MISSING_ALLOWED_METHODS when allowedMethods is not an array', async () => {
    await expect(issueChallenge({ ...validParams(), allowedMethods: 'passkey' }))
      .rejects.toMatchObject({ code: 'MISSING_ALLOWED_METHODS', status: 400 });
  });

  it('throws INVALID_METHOD when allowedMethods contains unrecognized method', async () => {
    await expect(issueChallenge({ ...validParams(), allowedMethods: ['passkey', 'sms_otp'] }))
      .rejects.toMatchObject({ code: 'INVALID_METHOD', status: 400 });
  });

  it('throws MISSING_EXPIRES_AT when expiresAt is absent', async () => {
    await expect(issueChallenge({ ...validParams(), expiresAt: null }))
      .rejects.toMatchObject({ code: 'MISSING_EXPIRES_AT', status: 400 });
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

    await issueChallenge(validParams({ signoffPolicyHash: 'sha256-policy-abc' }));

    expect(supabase.rpc).toHaveBeenCalledWith('issue_challenge_atomic', expect.objectContaining({
      p_handshake_id: 'hs-1',
      p_binding_hash: 'sha256-binding-abc',
      p_accountable_actor_ref: 'entity-alice',
      p_signoff_policy_id: 'policy-001',
      p_signoff_policy_hash: 'sha256-policy-abc',
      p_required_assurance: 'substantial',
      p_allowed_methods: ['passkey', 'secure_app'],
      p_expires_at: '2099-01-01T00:00:00Z',
    }));
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

  it('uses null signoffPolicyHash by default', async () => {
    const rpcData = { challenge_id: 'ch-nohash', status: 'challenge_issued' };
    const supabase = makeMockSupabase({ handshake: validHandshake(), binding: validBinding(), rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    await issueChallenge(validParams());

    expect(supabase.rpc).toHaveBeenCalledWith('issue_challenge_atomic', expect.objectContaining({
      p_signoff_policy_hash: null,
    }));
  });
});
