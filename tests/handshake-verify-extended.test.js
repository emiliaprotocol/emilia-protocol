/**
 * Extended tests for lib/handshake/verify.js
 *
 * Targets uncovered lines:
 *   118  — NOT_FOUND when handshake doesn't exist
 *   224-257 — policy load, claims checking, assurance checking per role
 *   340  — DB write error after verification
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/actor.js', () => ({
  resolveActorRef: vi.fn((actor) => (typeof actor === 'string' ? actor : actor?.entity_id || 'system')),
}));

vi.mock('../lib/protocol-write.js', () => ({
  COMMAND_TYPES: {
    VERIFY_HANDSHAKE: 'verify_handshake',
    INITIATE_HANDSHAKE: 'initiate_handshake',
    ADD_PRESENTATION: 'add_presentation',
    REVOKE_HANDSHAKE: 'revoke_handshake',
  },
  protocolWrite: vi.fn(async (command) => {
    if (command.type === 'verify_handshake') {
      const { _handleVerifyHandshake } = await import('../lib/handshake/verify.js');
      const res = await _handleVerifyHandshake(command);
      return res?.result ?? res;
    }
    throw new Error(`Unhandled command: ${command.type}`);
  }),
}));

vi.mock('./handshake/bind.js', () => ({
  checkBinding: vi.fn(() => []),
  checkDelegation: vi.fn(() => []),
}), { virtual: true });

vi.mock('../lib/handshake/bind.js', () => ({
  checkBinding: vi.fn(() => []),
  checkDelegation: vi.fn(() => []),
}));

vi.mock('../lib/handshake/policy.js', () => ({
  resolvePolicy: vi.fn(),
  checkClaimsAgainstPolicy: vi.fn(() => ({ satisfied: true, missing: [] })),
  getRequiredPartiesForMode: vi.fn(() => []),
}));

vi.mock('../lib/handshake/binding.js', () => ({
  computePolicyHash: vi.fn(() => 'mock-policy-hash'),
  hashBinding: vi.fn(() => 'mock-binding-hash'),
  canonicalizeBinding: vi.fn(() => ({})),
}));

vi.mock('../lib/handshake/invariants.js', () => ({
  ASSURANCE_RANK: { low: 1, medium: 2, substantial: 3, high: 4 },
  checkAssuranceLevel: vi.fn(() => ({ ok: true })),
}));

// Import after mocks
import { verifyHandshake, _handleVerifyHandshake } from '../lib/handshake/verify.js';
import { HandshakeError } from '../lib/handshake/errors.js';
import {
  resolvePolicy,
  checkClaimsAgainstPolicy,
  getRequiredPartiesForMode,
} from '../lib/handshake/policy.js';
import { checkBinding, checkDelegation } from '../lib/handshake/bind.js';
import { checkAssuranceLevel } from '../lib/handshake/invariants.js';
import { computePolicyHash } from '../lib/handshake/binding.js';

// ── Supabase builder ──────────────────────────────────────────────────────────

function makeChain(resolveValue) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
}

function buildSupabaseMock({
  existingBinding = null,
  handshake = null,
  handshakeError = null,
  parties = [],
  presentations = [],
  binding = null,
  rpcError = null,
} = {}) {
  const bindingCheckChain = makeChain({ data: existingBinding, error: null });
  const handshakeChain = makeChain({ data: handshake, error: handshakeError });
  const partiesChain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockResolvedValue({ data: parties, error: null }),
  };
  const presentationsChain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockResolvedValue({ data: presentations, error: null }),
  };
  const bindingFetchChain = makeChain({ data: binding, error: null });

  // Audit-fix (H8) compat: verify.js now calls `load_verify_context` RPC
  // instead of four parallel reads. Keep the legacy table mocks for tests
  // that still assert on them, but also respond to the new RPC using the
  // same fixture data.
  const rpcChain = vi.fn((fnName) => {
    if (fnName === 'load_verify_context') {
      if (handshakeError) {
        return Promise.resolve({ data: null, error: handshakeError });
      }
      if (!handshake) {
        return Promise.resolve({
          data: null,
          error: { code: 'P0002', message: 'HANDSHAKE_NOT_FOUND' },
        });
      }
      return Promise.resolve({
        data: { handshake, parties, presentations, binding },
        error: null,
      });
    }
    // verify_handshake_writes and other RPCs keep the prior behavior.
    return Promise.resolve({ data: null, error: rpcError });
  });

  let callCount = 0;
  return {
    from: vi.fn((table) => {
      if (table === 'handshake_bindings') {
        callCount++;
        if (callCount === 1) return bindingCheckChain;
        return bindingFetchChain;
      }
      if (table === 'handshakes') return handshakeChain;
      if (table === 'handshake_parties') return partiesChain;
      if (table === 'handshake_presentations') return presentationsChain;
      return makeChain({ data: null, error: null });
    }),
    rpc: rpcChain,
  };
}

// ── verifyHandshake (public API) ──────────────────────────────────────────────

describe('verifyHandshake — public API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws MISSING_HANDSHAKE_ID when no handshake_id provided', async () => {
    await expect(verifyHandshake('')).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });
  });

  it('throws MISSING_HANDSHAKE_ID when handshakeId is null', async () => {
    await expect(verifyHandshake(null)).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });
  });
});

// ── _handleVerifyHandshake ────────────────────────────────────────────────────

function makeCommand(input = {}) {
  return {
    actor: 'system',
    input: {
      handshake_id: 'hs-test-1',
      payload_hash: null,
      nonce: null,
      action_hash: null,
      policy_hash: null,
      ...input,
    },
  };
}

describe('_handleVerifyHandshake — binding already consumed (early exit)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns rejected outcome immediately when binding is already consumed', async () => {
    const db = buildSupabaseMock({
      existingBinding: { consumed_at: new Date().toISOString() },
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.outcome).toBe('rejected');
    expect(res.result.reason_codes).toContain('binding_already_consumed');
    expect(res.result.handshake_id).toBe('hs-test-1');
  });
});

describe('_handleVerifyHandshake — NOT_FOUND (line 118)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkBinding.mockReturnValue([]);
  });

  it('throws NOT_FOUND when handshake does not exist', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: null,
      handshakeError: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleVerifyHandshake(makeCommand())).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
  });

  it('throws DB_ERROR when handshake fetch fails', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: null,
      handshakeError: { message: 'connection refused' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleVerifyHandshake(makeCommand())).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });

  it('throws INVALID_STATE when handshake has non-verifiable status', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: { handshake_id: 'hs-test-1', status: 'revoked', mode: 'mutual', policy_id: null, policy_hash: null, action_hash: null, policy_version: null },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleVerifyHandshake(makeCommand())).rejects.toMatchObject({
      code: 'INVALID_STATE',
      status: 409,
    });
  });
});

describe('_handleVerifyHandshake — accepted outcome', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkBinding.mockReturnValue([]);
    resolvePolicy.mockResolvedValue(null);
    getRequiredPartiesForMode.mockReturnValue([]);
    checkClaimsAgainstPolicy.mockReturnValue({ satisfied: true, missing: [] });
  });

  it('returns accepted outcome when all checks pass', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: null,
        policy_version: 'v1',
      },
      parties: [
        { id: 'p1', party_role: 'initiator', assurance_level: 'medium', entity_ref: 'e1' },
      ],
      presentations: [
        { party_role: 'initiator', verified: true, revocation_status: null, normalized_claims: { email: 'a@b.com' } },
      ],
      binding: { binding_hash: 'hash1', expires_at: new Date(Date.now() + 60_000).toISOString() },
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.outcome).toBe('accepted');
    expect(res.result.handshake_id).toBe('hs-test-1');
    expect(Array.isArray(res.result.reason_codes)).toBe(true);
  });

  it('includes _protocolEventWritten: true on success', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'pending_verification',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res._protocolEventWritten).toBe(true);
  });
});

describe('_handleVerifyHandshake — action_hash and policy_hash checks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkBinding.mockReturnValue([]);
    resolvePolicy.mockResolvedValue(null);
    getRequiredPartiesForMode.mockReturnValue([]);
  });

  it('adds action_hash_required when handshake has action_hash but none provided', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: 'expected-hash',
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand({ action_hash: null }));
    expect(res.result.reason_codes).toContain('action_hash_required');
  });

  it('adds action_hash_mismatch when provided hash does not match', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: 'expected-hash',
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand({ action_hash: 'wrong-hash' }));
    expect(res.result.reason_codes).toContain('action_hash_mismatch');
  });

  it('adds policy_hash_required when handshake has policy_hash but none provided', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: 'stored-policy-hash',
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand({ policy_hash: null }));
    expect(res.result.reason_codes).toContain('policy_hash_required');
  });
});

describe('_handleVerifyHandshake — policy loading (lines 224-257)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkBinding.mockReturnValue([]);
  });

  it('adds policy_load_failed when resolvePolicy throws', async () => {
    resolvePolicy.mockRejectedValue(new Error('policy DB down'));
    getRequiredPartiesForMode.mockReturnValue([]);

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: 'pol-1',
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.reason_codes).toContain('policy_load_failed');
    expect(res.result.reason_codes).toContain('policy_not_found');
  });

  it('adds policy_not_found when policy resolves to null', async () => {
    resolvePolicy.mockResolvedValue(null);
    getRequiredPartiesForMode.mockReturnValue([]);

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: 'pol-1',
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.reason_codes).toContain('policy_not_found');
  });

  it('adds policy_hash_mismatch when policy hash changes after initiation', async () => {
    const policy = { rules: { required_parties: {} }, policy_id: 'pol-1' };
    resolvePolicy.mockResolvedValue(policy);
    computePolicyHash.mockReturnValue('new-different-hash');
    getRequiredPartiesForMode.mockReturnValue([]);

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: 'pol-1',
        policy_hash: 'original-hash',  // stored at initiation
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand({ policy_hash: 'original-hash' }));
    // policy_hash_mismatch deduplicated — should appear once
    const mismatches = res.result.reason_codes.filter(c => c === 'policy_hash_mismatch');
    expect(mismatches.length).toBeGreaterThanOrEqual(1);
  });

  it('checks required claims against policy for each role (line ~243)', async () => {
    const policy = {
      policy_id: 'pol-1',
      rules: {
        required_parties: {
          initiator: { required_claims: ['email', 'org_id'], minimum_assurance: 'medium' },
        },
      },
    };
    resolvePolicy.mockResolvedValue(policy);
    getRequiredPartiesForMode.mockReturnValue(['initiator']);
    checkClaimsAgainstPolicy.mockReturnValue({ satisfied: false, missing: ['org_id'] });

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: 'pol-1',
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [{ id: 'p1', party_role: 'initiator', assurance_level: 'medium', entity_ref: 'e1' }],
      presentations: [{ party_role: 'initiator', verified: true, revocation_status: null, normalized_claims: { email: 'a@b.com' } }],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.reason_codes).toContain('policy_claims_missing_initiator');
  });

  it('checks assurance level against policy minimum (lines ~250-257)', async () => {
    const policy = {
      policy_id: 'pol-1',
      rules: {
        required_parties: {
          initiator: { required_claims: [], minimum_assurance: 'high' },
        },
      },
    };
    resolvePolicy.mockResolvedValue(policy);
    getRequiredPartiesForMode.mockReturnValue(['initiator']);
    checkClaimsAgainstPolicy.mockReturnValue({ satisfied: true, missing: [] });
    checkAssuranceLevel.mockReturnValue({ ok: false });

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: 'pol-1',
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [{ id: 'p1', party_role: 'initiator', assurance_level: 'low', entity_ref: 'e1' }],
      presentations: [{ party_role: 'initiator', verified: true, revocation_status: null, normalized_claims: {} }],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.reason_codes).toContain('policy_assurance_below_minimum_initiator');
  });
});

describe('_handleVerifyHandshake — DB write error (line 340)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkBinding.mockReturnValue([]);
    resolvePolicy.mockResolvedValue(null);
    getRequiredPartiesForMode.mockReturnValue([]);
    checkClaimsAgainstPolicy.mockReturnValue({ satisfied: true, missing: [] });
  });

  it('throws DB_ERROR when verify_handshake_writes RPC fails', async () => {
    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
      rpcError: { message: 'transaction timeout' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleVerifyHandshake(makeCommand())).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });
});

describe('_handleVerifyHandshake — outcome determination', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resolvePolicy.mockResolvedValue(null);
    getRequiredPartiesForMode.mockReturnValue([]);
    checkClaimsAgainstPolicy.mockReturnValue({ satisfied: true, missing: [] });
  });

  it('outcome is expired when binding_expired reason code is present', async () => {
    checkBinding.mockReturnValue(['binding_expired']);

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.outcome).toBe('expired');
  });

  it('outcome is partial when only assurance reason codes present', async () => {
    checkBinding.mockReturnValue(['assurance_not_met_initiator']);

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: null,
        policy_hash: null,
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand());
    expect(res.result.outcome).toBe('partial');
  });

  it('deduplicates reason_codes', async () => {
    // policy_hash_mismatch can be pushed by two different checks
    checkBinding.mockReturnValue([]);
    computePolicyHash.mockReturnValue('new-hash');
    const policy = { rules: { required_parties: {} }, policy_id: 'pol-1' };
    resolvePolicy.mockResolvedValue(policy);

    const db = buildSupabaseMock({
      existingBinding: null,
      handshake: {
        handshake_id: 'hs-test-1',
        status: 'initiated',
        mode: 'unilateral',
        policy_id: 'pol-1',
        policy_hash: 'old-hash',
        action_hash: null,
        policy_version: null,
      },
      parties: [],
      presentations: [],
      binding: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleVerifyHandshake(makeCommand({ policy_hash: 'wrong-hash' }));
    const codes = res.result.reason_codes;
    const mismatches = codes.filter(c => c === 'policy_hash_mismatch');
    expect(mismatches.length).toBe(1); // deduplicated
  });
});
