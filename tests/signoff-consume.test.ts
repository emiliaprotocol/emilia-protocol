/**
 * Tests for lib/signoff/consume.js — consumeSignoff() and isSignoffConsumed()
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

// requireSignoffEvent is NOT used by consume.js (uses RPC instead)
// No events mock needed.

// ── Import under test (after mocks) ──────────────────────────────────────────

import { consumeSignoff, isSignoffConsumed } from '../lib/signoff/consume.js';

// ── Supabase mock factory ─────────────────────────────────────────────────────

function makeMockSupabase({
  attestation = null,
  attestationError = null,
  rpcData = null,
  rpcError = null,
  consumptionRow = null,
} = {}) {
  const rpc = vi.fn().mockResolvedValue({ data: rpcData, error: rpcError });

  const from = vi.fn().mockImplementation((tableName) => {
    if (tableName === 'signoff_attestations') {
      return {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: attestation, error: attestationError }),
      };
    }
    if (tableName === 'signoff_consumptions') {
      return {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: consumptionRow, error: null }),
      };
    }
    return {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
    };
  });

  return { from, rpc };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const ACTOR = { entity_id: 'entity-alice' };

function validAttestation(overrides = {}) {
  return {
    signoff_id: 'sig-1',
    challenge_id: 'ch-1',
    handshake_id: 'hs-1',
    binding_hash: 'sha256-binding-abc',
    human_entity_ref: 'entity-alice',
    status: 'approved',
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    ...overrides,
  };
}

function validParams(overrides = {}) {
  return {
    signoffId: 'sig-1',
    bindingHash: 'sha256-binding-abc',
    executionRef: 'exec-action-1',
    actor: ACTOR,
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('consumeSignoff — input validation', () => {
  it('throws MISSING_SIGNOFF_ID when signoffId is absent', async () => {
    await expect(consumeSignoff({ executionRef: 'x', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_SIGNOFF_ID', status: 400 });
  });

  it('throws MISSING_EXECUTION_REF when executionRef is absent', async () => {
    await expect(consumeSignoff({ signoffId: 'sig-1', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_EXECUTION_REF', status: 400 });
  });

  it('throws MISSING_ACTOR when actor is absent', async () => {
    await expect(consumeSignoff({ signoffId: 'sig-1', executionRef: 'x' }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });

  it('throws MISSING_ACTOR when actor has no entity_id', async () => {
    await expect(consumeSignoff({ signoffId: 'sig-1', executionRef: 'x', actor: {} }))
      .rejects.toMatchObject({ code: 'MISSING_ACTOR', status: 400 });
  });
});

describe('consumeSignoff — attestation DB checks', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when attestation fetch fails', async () => {
    const supabase = makeMockSupabase({ attestationError: { message: 'db timeout' } });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws ATTESTATION_NOT_FOUND when attestation is null', async () => {
    const supabase = makeMockSupabase({ attestation: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'ATTESTATION_NOT_FOUND', status: 404 });
  });
});

describe('consumeSignoff — authorization and state guards', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws FORBIDDEN when actor entity_id does not match human_entity_ref', async () => {
    const attestation = validAttestation({ human_entity_ref: 'entity-alice' });
    const supabase = makeMockSupabase({ attestation });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams({ actor: { entity_id: 'entity-mallory' } })))
      .rejects.toMatchObject({ code: 'FORBIDDEN', status: 403 });
  });

  it('throws INVALID_ATTESTATION_STATE when attestation is not approved (revoked)', async () => {
    const attestation = validAttestation({ status: 'revoked' });
    const supabase = makeMockSupabase({ attestation });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_ATTESTATION_STATE', status: 409 });
  });

  it('throws INVALID_ATTESTATION_STATE when attestation is already consumed', async () => {
    const attestation = validAttestation({ status: 'consumed' });
    const supabase = makeMockSupabase({ attestation });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'INVALID_ATTESTATION_STATE', status: 409 });
  });

  it('throws SIGNOFF_ATTESTATION_EXPIRED when attestation has expired', async () => {
    const attestation = validAttestation({
      expires_at: new Date(Date.now() - 10_000).toISOString(),
    });
    const supabase = makeMockSupabase({ attestation });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'SIGNOFF_ATTESTATION_EXPIRED', status: 410 });
  });

  it('throws BINDING_HASH_MISMATCH when explicit bindingHash does not match attestation', async () => {
    const attestation = validAttestation({ binding_hash: 'sha256-REAL' });
    const supabase = makeMockSupabase({ attestation });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams({ bindingHash: 'sha256-WRONG' })))
      .rejects.toMatchObject({ code: 'BINDING_HASH_MISMATCH', status: 409 });
  });
});

describe('consumeSignoff — RPC and happy path', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('throws DB_ERROR when RPC fails with generic error', async () => {
    const attestation = validAttestation();
    const supabase = makeMockSupabase({
      attestation,
      rpcError: { message: 'internal error' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('throws ALREADY_CONSUMED when RPC returns unique constraint error (23505)', async () => {
    const attestation = validAttestation();
    const supabase = makeMockSupabase({
      attestation,
      rpcError: { message: 'duplicate key value violates unique constraint 23505' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'ALREADY_CONSUMED', status: 409 });
  });

  it('throws ALREADY_CONSUMED when RPC returns "unique" in error message', async () => {
    const attestation = validAttestation();
    const supabase = makeMockSupabase({
      attestation,
      rpcError: { message: 'violates unique constraint on signoff_consumptions' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await expect(consumeSignoff(validParams()))
      .rejects.toMatchObject({ code: 'ALREADY_CONSUMED', status: 409 });
  });

  it('returns consumption record on success', async () => {
    const attestation = validAttestation();
    const rpcData = { consumed_at: '2099-01-01T00:00:00Z', consumption_id: 'cons-001' };
    const supabase = makeMockSupabase({ attestation, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await consumeSignoff(validParams());
    expect(result.signoff_id).toBe('sig-1');
    expect(result.execution_ref).toBe('exec-action-1');
    expect(result.consumed_at).toBe('2099-01-01T00:00:00Z');
    expect(result.id).toBe('cons-001');
  });

  it('calls consume_signoff_atomic RPC with correct parameters', async () => {
    const attestation = validAttestation();
    const rpcData = { consumed_at: new Date().toISOString(), consumption_id: 'cons-002' };
    const supabase = makeMockSupabase({ attestation, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    await consumeSignoff(validParams());

    expect(supabase.rpc).toHaveBeenCalledWith('consume_signoff_atomic', expect.objectContaining({
      p_signoff_id: 'sig-1',
      p_execution_ref: 'exec-action-1',
      p_handshake_id: 'hs-1',
      p_challenge_id: 'ch-1',
      p_human_entity_ref: 'entity-alice',
    }));
  });

  it('derives bindingHash from attestation when not explicitly provided', async () => {
    const attestation = validAttestation({ binding_hash: 'sha256-from-attestation' });
    const rpcData = { consumed_at: new Date().toISOString(), consumption_id: 'cons-003' };
    const supabase = makeMockSupabase({ attestation, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const params = validParams();
    delete params.bindingHash;
    const result = await consumeSignoff(params);
    expect(result.signoff_id).toBe('sig-1');
  });

  it('allows consumption when expires_at is null (no expiry)', async () => {
    const attestation = validAttestation({ expires_at: null });
    const rpcData = { consumed_at: new Date().toISOString(), consumption_id: 'cons-004' };
    const supabase = makeMockSupabase({ attestation, rpcData });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await consumeSignoff(validParams());
    expect(result.signoff_id).toBe('sig-1');
  });
});

describe('isSignoffConsumed', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns true when consumption record exists', async () => {
    const supabase = makeMockSupabase({ consumptionRow: { signoff_id: 'sig-1' } });
    mockGetServiceClient.mockReturnValue(supabase);

    expect(await isSignoffConsumed('sig-1')).toBe(true);
  });

  it('returns false when no consumption record exists', async () => {
    const supabase = makeMockSupabase({ consumptionRow: null });
    mockGetServiceClient.mockReturnValue(supabase);

    expect(await isSignoffConsumed('sig-999')).toBe(false);
  });

  it('queries the signoff_consumptions table by signoff_id', async () => {
    const supabase = makeMockSupabase({ consumptionRow: null });
    mockGetServiceClient.mockReturnValue(supabase);

    await isSignoffConsumed('sig-abc');
    expect(supabase.from).toHaveBeenCalledWith('signoff_consumptions');
  });
});
