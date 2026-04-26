/**
 * Extended tests for lib/handshake/create.js
 *
 * Targets uncovered lines:
 *   142  — INITIATOR_BINDING_VIOLATION (actor ≠ initiator in non-delegated mode)
 *   247-252 — idempotency hit: returns existing handshake with parties+binding
 *   363  — RPC error from create_handshake_atomic
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
  resolveActorRef: vi.fn((actor) => {
    if (typeof actor === 'string') return actor;
    if (actor && actor.entity_id) return actor.entity_id;
    return 'system';
  }),
}));

vi.mock('../lib/protocol-write.js', () => ({
  COMMAND_TYPES: {
    INITIATE_HANDSHAKE: 'initiate_handshake',
    ADD_PRESENTATION: 'add_presentation',
    VERIFY_HANDSHAKE: 'verify_handshake',
    REVOKE_HANDSHAKE: 'revoke_handshake',
  },
  protocolWrite: vi.fn(async (command) => {
    if (command.type === 'initiate_handshake') {
      const { _handleInitiateHandshake } = await import('../lib/handshake/create.js');
      const res = await _handleInitiateHandshake(command);
      return res?.result ?? res;
    }
    throw new Error(`Unhandled: ${command.type}`);
  }),
}));

vi.mock('../lib/handshake/policy.js', () => ({
  // Audit-fix C3 (commit ebd1d72): create.js now throws POLICY_NOT_FOUND when
  // resolvePolicy returns null, instead of silently catching and proceeding
  // with policy_hash=null. Default mock now returns a valid stub so tests
  // that target downstream failure modes (RPC errors, idempotency, etc.)
  // reach their actual assertion targets. Tests that specifically exercise
  // the policy-not-found path use `.mockResolvedValueOnce(null)` to override.
  resolvePolicy: vi.fn().mockResolvedValue({
    policy_id: 'pol-1',
    policy_key: 'default',
    policy_version: '1.0.0',
    version: 1,
    status: 'active',
    rules: {},
  }),
  checkClaimsAgainstPolicy: vi.fn(() => ({ satisfied: true, missing: [] })),
  getRequiredPartiesForMode: vi.fn(() => []),
}));

vi.mock('../lib/handshake/binding.js', () => ({
  buildBindingMaterial: vi.fn(() => ({})),
  hashBinding: vi.fn(() => 'mock-binding-hash'),
  computePartySetHash: vi.fn(() => 'mock-party-set-hash'),
  computeContextHash: vi.fn(() => 'mock-context-hash'),
  computePayloadHash: vi.fn(() => 'mock-payload-hash'),
  computePolicyHash: vi.fn(() => 'mock-policy-hash'),
}));

vi.mock('@/lib/actor.js', () => ({
  resolveActorRef: vi.fn((actor) => {
    if (typeof actor === 'string') return actor;
    if (actor && actor.entity_id) return actor.entity_id;
    return 'system';
  }),
}));

// Import after mocks
import { initiateHandshake, _handleInitiateHandshake } from '../lib/handshake/create.js';
import { HandshakeError } from '../lib/handshake/errors.js';

// ── DB mock builder ───────────────────────────────────────────────────────────

function makeChain(resolveValue) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
}

function buildSupabaseMock({
  idempotencyExisting = null,
  idempotencyError = null,
  partiesData = [],
  bindingData = null,
  rpcResult = { handshake_id: 'hs-new-1' },
  rpcError = null,
} = {}) {
  const idempChain = makeChain({ data: idempotencyExisting, error: idempotencyError });
  const partiesChain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockResolvedValue({ data: partiesData, error: null }),
  };
  const bindingChain = makeChain({ data: bindingData, error: null });
  const rpcFn = vi.fn().mockResolvedValue({ data: rpcResult, error: rpcError });

  return {
    from: vi.fn((table) => {
      if (table === 'handshakes') return idempChain;
      if (table === 'handshake_parties') return partiesChain;
      if (table === 'handshake_bindings') return bindingChain;
      return makeChain({ data: null, error: null });
    }),
    rpc: rpcFn,
  };
}

function defaultParties() {
  return [{ role: 'initiator', entity_ref: 'entity-abc' }];
}

// ── initiateHandshake — validation (line 142: INITIATOR_BINDING_VIOLATION) ───

describe('initiateHandshake — INITIATOR_BINDING_VIOLATION (line 142)', () => {
  it('throws INITIATOR_BINDING_VIOLATION when non-system actor does not match initiator entity_ref', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: 'entity-abc' }],
      actor: 'entity-xyz', // does not match initiator
    })).rejects.toMatchObject({
      code: 'INITIATOR_BINDING_VIOLATION',
      status: 403,
    });
  });

  it('does NOT throw INITIATOR_BINDING_VIOLATION when actor is "system"', async () => {
    const db = buildSupabaseMock();
    mockGetServiceClient.mockReturnValue(db);

    // Should not throw validation error — system bypasses the check
    const result = await initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: 'entity-abc' }],
      actor: 'system',
    });
    expect(result).toBeDefined();
  });

  it('does NOT throw when actor matches initiator entity_ref', async () => {
    const db = buildSupabaseMock();
    mockGetServiceClient.mockReturnValue(db);

    const result = await initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: 'entity-abc' }],
      actor: 'entity-abc', // matches
    });
    expect(result).toBeDefined();
  });

  it('does NOT throw INITIATOR_BINDING_VIOLATION in delegated mode (delegate is actor)', async () => {
    const db = buildSupabaseMock();
    mockGetServiceClient.mockReturnValue(db);

    const result = await initiateHandshake({
      mode: 'delegated',
      policy_id: 'pol-1',
      parties: [
        { role: 'initiator', entity_ref: 'entity-principal' },
        { role: 'delegate', entity_ref: 'entity-delegate' },
      ],
      actor: 'entity-delegate', // actor = delegate, not initiator — should not trigger violation
    });
    expect(result).toBeDefined();
  });
});

// ── initiateHandshake — other validation errors ───────────────────────────────

describe('initiateHandshake — validation errors', () => {
  it('throws INVALID_MODE for unrecognized mode', async () => {
    await expect(initiateHandshake({
      mode: 'quantum',
      policy_id: 'pol-1',
      parties: defaultParties(),
    })).rejects.toMatchObject({ code: 'INVALID_MODE', status: 400 });
  });

  it('throws MISSING_POLICY when policy_id absent', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: null,
      parties: defaultParties(),
    })).rejects.toMatchObject({ code: 'MISSING_POLICY', status: 400 });
  });

  it('throws MISSING_PARTIES when parties array is empty', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [],
    })).rejects.toMatchObject({ code: 'MISSING_PARTIES', status: 400 });
  });

  it('throws INVALID_PARTY_ROLE for unrecognized role', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'wizard', entity_ref: 'entity-1' }],
    })).rejects.toMatchObject({ code: 'INVALID_PARTY_ROLE' });
  });

  it('throws MISSING_ENTITY_REF when party has no entity_ref', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: '' }],
    })).rejects.toMatchObject({ code: 'MISSING_ENTITY_REF' });
  });

  it('throws NO_INITIATOR when no initiator party is present', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'responder', entity_ref: 'entity-1' }],
    })).rejects.toMatchObject({ code: 'NO_INITIATOR' });
  });

  it('throws MUTUAL_REQUIRES_RESPONDER in mutual mode without responder', async () => {
    await expect(initiateHandshake({
      mode: 'mutual',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: 'entity-1' }],
      actor: 'system',
    })).rejects.toMatchObject({ code: 'MUTUAL_REQUIRES_RESPONDER' });
  });

  it('throws DELEGATED_REQUIRES_DELEGATE in delegated mode without delegate', async () => {
    await expect(initiateHandshake({
      mode: 'delegated',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: 'entity-1' }],
      actor: 'system',
    })).rejects.toMatchObject({ code: 'DELEGATED_REQUIRES_DELEGATE' });
  });

  it('throws DELEGATE_BINDING_VIOLATION when actor does not match delegate in delegated mode', async () => {
    await expect(initiateHandshake({
      mode: 'delegated',
      policy_id: 'pol-1',
      parties: [
        { role: 'initiator', entity_ref: 'entity-principal' },
        { role: 'delegate', entity_ref: 'entity-delegate' },
      ],
      actor: 'entity-someone-else',
    })).rejects.toMatchObject({ code: 'DELEGATE_BINDING_VIOLATION', status: 403 });
  });

  it('throws INVALID_ASSURANCE_LEVEL for invalid assurance_level value', async () => {
    await expect(initiateHandshake({
      mode: 'basic',
      policy_id: 'pol-1',
      parties: [{ role: 'initiator', entity_ref: 'entity-1', assurance_level: 'ultra' }],
      actor: 'system',
    })).rejects.toMatchObject({ code: 'INVALID_ASSURANCE_LEVEL' });
  });
});

// ── _handleInitiateHandshake — idempotency hit (lines 247-252) ───────────────

describe('_handleInitiateHandshake — idempotency hit (lines 247-252)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns existing handshake with idempotent: true when idempotency key matches', async () => {
    const existingHandshake = {
      handshake_id: 'hs-existing-1',
      mode: 'basic',
      policy_id: 'pol-1',
      policy_version: 'v1',
      status: 'initiated',
    };
    const existingParties = [
      { id: 'p1', handshake_id: 'hs-existing-1', party_role: 'initiator', entity_ref: 'entity-abc' },
    ];
    const existingBinding = {
      handshake_id: 'hs-existing-1',
      binding_hash: 'abc123',
    };

    const db = buildSupabaseMock({
      idempotencyExisting: existingHandshake,
      partiesData: existingParties,
      bindingData: existingBinding,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleInitiateHandshake({
      actor: 'system',
      input: {
        mode: 'basic',
        policy_id: 'pol-1',
        policy_version: 'v1',
        interaction_id: null,
        parties: [{ role: 'initiator', entity_ref: 'entity-abc' }],
        payload_hash: 'hash1',
        nonce: 'nonce1',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        metadata: {},
        binding: null,
        idempotency_key: 'idem-key-1',
        action_type: null,
        resource_ref: null,
        intent_ref: null,
        action_hash: null,
      },
    });

    expect(res.result.handshake_id).toBe('hs-existing-1');
    expect(res.result.idempotent).toBe(true);
    expect(res.result.status).toBe('initiated');
    expect(res.aggregateId).toBe('hs-existing-1');
  });

  it('returns parties array from existing handshake on idempotency hit', async () => {
    const existing = {
      handshake_id: 'hs-existing-2',
      mode: 'mutual',
      policy_id: 'pol-2',
      policy_version: null,
      status: 'pending_verification',
    };
    const parties = [
      { id: 'p1', party_role: 'initiator', entity_ref: 'e1' },
      { id: 'p2', party_role: 'responder', entity_ref: 'e2' },
    ];

    const db = buildSupabaseMock({
      idempotencyExisting: existing,
      partiesData: parties,
      bindingData: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleInitiateHandshake({
      actor: 'system',
      input: {
        mode: 'mutual',
        policy_id: 'pol-2',
        policy_version: null,
        interaction_id: null,
        parties: [{ role: 'initiator', entity_ref: 'e1' }, { role: 'responder', entity_ref: 'e2' }],
        payload_hash: 'hash2',
        nonce: 'nonce2',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        metadata: {},
        binding: null,
        idempotency_key: 'idem-key-2',
        action_type: null,
        resource_ref: null,
        intent_ref: null,
        action_hash: null,
      },
    });

    expect(res.result.idempotent).toBe(true);
    expect(res.result.parties).toHaveLength(2);
    expect(res.result.binding).toBeNull();
  });

  it('throws DB_ERROR when idempotency lookup fails', async () => {
    const db = buildSupabaseMock({
      idempotencyError: { message: 'query timeout' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleInitiateHandshake({
      actor: 'system',
      input: {
        mode: 'basic',
        policy_id: 'pol-1',
        policy_version: null,
        interaction_id: null,
        parties: [{ role: 'initiator', entity_ref: 'entity-1' }],
        payload_hash: 'hash1',
        nonce: 'nonce1',
        expires_at: new Date().toISOString(),
        metadata: {},
        binding: null,
        idempotency_key: 'idem-key-err',
        action_type: null,
        resource_ref: null,
        intent_ref: null,
        action_hash: null,
      },
    })).rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

// ── _handleInitiateHandshake — RPC error (line 363) ──────────────────────────

describe('_handleInitiateHandshake — RPC error (line ~363)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws DB_ERROR when create_handshake_atomic RPC fails', async () => {
    const db = buildSupabaseMock({
      idempotencyExisting: null,
      rpcError: { message: 'transaction aborted' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleInitiateHandshake({
      actor: 'system',
      input: {
        mode: 'basic',
        policy_id: 'pol-1',
        policy_version: null,
        interaction_id: null,
        parties: [{ role: 'initiator', entity_ref: 'entity-1' }],
        payload_hash: 'hash1',
        nonce: 'nonce1',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        metadata: {},
        binding: null,
        idempotency_key: null,
        action_type: null,
        resource_ref: null,
        intent_ref: null,
        action_hash: 'action-hash',
      },
    })).rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('returns _protocolEventWritten: true on successful creation', async () => {
    const db = buildSupabaseMock({
      idempotencyExisting: null,
      rpcResult: { handshake_id: 'hs-new-1' },
      rpcError: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleInitiateHandshake({
      actor: 'system',
      input: {
        mode: 'basic',
        policy_id: 'pol-1',
        policy_version: 'v1',
        interaction_id: null,
        parties: [{ role: 'initiator', entity_ref: 'entity-1' }],
        payload_hash: 'hash1',
        nonce: 'nonce1',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        metadata: {},
        binding: null,
        idempotency_key: null,
        action_type: 'connect',
        resource_ref: 'resource-1',
        intent_ref: null,
        action_hash: 'action-hash-1',
      },
    });

    expect(res._protocolEventWritten).toBe(true);
    expect(res.result.handshake_id).toBe('hs-new-1');
    expect(res.result.status).toBe('initiated');
  });

  it('result includes party list with correct structure', async () => {
    const db = buildSupabaseMock({
      rpcResult: { handshake_id: 'hs-party-test' },
    });
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleInitiateHandshake({
      actor: 'system',
      input: {
        mode: 'mutual',
        policy_id: 'pol-1',
        policy_version: null,
        interaction_id: null,
        parties: [
          { role: 'initiator', entity_ref: 'e1', assurance_level: 'medium' },
          { role: 'responder', entity_ref: 'e2' },
        ],
        payload_hash: 'hash1',
        nonce: 'nonce1',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        metadata: {},
        binding: null,
        idempotency_key: null,
        action_type: null,
        resource_ref: null,
        intent_ref: null,
        action_hash: null,
      },
    });

    expect(res.result.parties).toHaveLength(2);
    const initiatorParty = res.result.parties.find(p => p.party_role === 'initiator');
    expect(initiatorParty).toBeDefined();
    expect(initiatorParty.assurance_level).toBe('medium');
    expect(initiatorParty.verified_status).toBe('pending');
  });
});
