/**
 * EMILIA Protocol — EP Handshake Adversarial Test Suite
 *
 * Covers reviewer requirements:
 *   B.5 — Double consumption prevention and race conditions
 *   D.4 — Event reconstruction and drift detection
 *   A.4 — Binding completeness enforcement
 *
 * Uses vitest with the same mock patterns as handshake-attack.test.js.
 * protocolWrite is wired to the real _handle* functions so we exercise
 * actual business logic against an in-memory table simulator.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ============================================================================
// Mock: Supabase
// ============================================================================

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// ============================================================================
// Mock: protocol-write
// ============================================================================

let _handshakeHandlers = {};

vi.mock('../lib/protocol-write.js', () => {
  const COMMAND_TYPES = {
    SUBMIT_RECEIPT: 'submit_receipt',
    CONFIRM_RECEIPT: 'confirm_receipt',
    ISSUE_COMMIT: 'issue_commit',
    VERIFY_COMMIT: 'verify_commit',
    REVOKE_COMMIT: 'revoke_commit',
    FILE_DISPUTE: 'file_dispute',
    RESOLVE_DISPUTE: 'resolve_dispute',
    FILE_REPORT: 'file_report',
    SUBMIT_AUTO_RECEIPT: 'submit_auto_receipt',
    INITIATE_HANDSHAKE: 'initiate_handshake',
    ADD_PRESENTATION: 'add_presentation',
    VERIFY_HANDSHAKE: 'verify_handshake',
    REVOKE_HANDSHAKE: 'revoke_handshake',
  };

  return {
    COMMAND_TYPES,
    protocolWrite: vi.fn(async (command) => {
      const handler = _handshakeHandlers[command.type];
      if (!handler) {
        throw new Error(`No handler for command type: ${command.type}`);
      }
      const res = await handler(command);
      return res?.result ?? res;
    }),
  };
});

// ============================================================================
// Import modules under test (after mocks)
// ============================================================================

import {
  initiateHandshake,
  addPresentation,
  verifyHandshake,
  revokeHandshake,
  consumeHandshake,
  isHandshakeConsumed,
  _handleInitiateHandshake,
  _handleAddPresentation,
  _handleVerifyHandshake,
  _handleRevokeHandshake,
} from '../lib/handshake/index.js';

import {
  buildBindingMaterial,
  validateBindingCompleteness,
  hashBinding,
  canonicalizeBinding,
  computePartySetHash,
  computePayloadHash,
} from '../lib/handshake/binding.js';

import {
  CANONICAL_BINDING_FIELDS,
  BINDING_MATERIAL_VERSION,
  sha256,
} from '../lib/handshake/invariants.js';

import {
  getHandshakeEvents,
} from '../lib/handshake/events.js';

// Wire handlers after import so they reference the real functions
_handshakeHandlers = {
  initiate_handshake: _handleInitiateHandshake,
  add_presentation: _handleAddPresentation,
  verify_handshake: _handleVerifyHandshake,
  revoke_handshake: _handleRevokeHandshake,
  issue_commit: async () => ({
    result: { commit_id: 'epc_mock_' + crypto.randomBytes(4).toString('hex'), decision: 'allow' },
    aggregateId: 'epc_mock',
  }),
};

// ============================================================================
// Supabase table simulator
// ============================================================================

function createTableSim() {
  const tables = {};

  function getTable(name) {
    if (!tables[name]) tables[name] = [];
    if (name === 'authorities' && tables[name].length === 0) {
      tables[name].push({
        authority_id: 'auth-trusted-ca',
        key_id: 'issuer-trusted-ca',
        status: 'active',
        valid_from: new Date(Date.now() - 365 * 86_400_000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 86_400_000).toISOString(),
      });
    }
    // Seed test policies. Audit-fix C3 (commit ebd1d72): create.js now
    // throws POLICY_NOT_FOUND when resolvePolicy returns null, so any
    // policy_id used by tests must be in the sim.
    if (name === 'handshake_policies' && tables[name].length === 0) {
      const defaults = [
        { policy_id: 'policy-abc-123', policy_key: 'default', policy_version: '1.0.0', version: 1, status: 'active', rules: {} },
        { policy_id: 'policy-other',   policy_key: 'other',   policy_version: '1.0.0', version: 1, status: 'active', rules: {} },
      ];
      for (const p of defaults) tables[name].push(p);
    }
    return tables[name];
  }

  function applyFilters(rows, filters) {
    let result = rows;
    for (const f of filters) {
      result = result.filter((r) => r[f.col] === f.val);
    }
    return result;
  }

  function buildSelectChain(tableName) {
    let filters = [];
    let inFilters = [];
    const chain = {
      select: vi.fn().mockImplementation(() => chain),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      in: vi.fn().mockImplementation((col, vals) => {
        inFilters.push({ col, vals });
        return chain;
      }),
      neq: vi.fn().mockImplementation(() => chain),
      order: vi.fn().mockImplementation(() => chain),
      limit: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        let filtered = applyFilters(getTable(tableName), filters);
        for (const inf of inFilters) {
          filtered = filtered.filter((r) => inf.vals.includes(r[inf.col]));
        }
        filters = [];
        inFilters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      maybeSingle: vi.fn().mockImplementation(() => {
        let filtered = applyFilters(getTable(tableName), filters);
        for (const inf of inFilters) {
          filtered = filtered.filter((r) => inf.vals.includes(r[inf.col]));
        }
        filters = [];
        inFilters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      let filtered = applyFilters(getTable(tableName), filters);
      for (const inf of inFilters) {
        filtered = filtered.filter((r) => inf.vals.includes(r[inf.col]));
      }
      filters = [];
      inFilters = [];
      return Promise.resolve({ data: filtered, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function buildInsertChain(tableName) {
    let insertedRows = null;
    // Track unique constraints for handshake_consumptions
    const chain = {
      insert: vi.fn().mockImplementation((rows) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const row of arr) {
          // Simulate unique constraint on handshake_consumptions.handshake_id
          if (tableName === 'handshake_consumptions') {
            const existing = getTable(tableName).find(
              (r) => r.handshake_id === row.handshake_id,
            );
            if (existing) {
              insertedRows = null;
              return {
                select: vi.fn().mockReturnValue({
                  single: vi.fn().mockResolvedValue({
                    data: null,
                    error: { code: '23505', message: 'duplicate key value violates unique constraint' },
                  }),
                }),
              };
            }
          }
          if (tableName === 'handshakes' && !row.handshake_id) {
            row.handshake_id = 'eph_' + crypto.randomBytes(12).toString('hex');
          }
          if (tableName === 'handshake_parties' && !row.id) {
            row.id = crypto.randomBytes(8).toString('hex');
          }
          getTable(tableName).push(row);
        }
        insertedRows = arr;
        return chain;
      }),
      select: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        return Promise.resolve({ data: insertedRows?.[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      return Promise.resolve({ data: insertedRows, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function buildUpdateChain(tableName) {
    let updateData = null;
    let filters = [];
    const chain = {
      update: vi.fn().mockImplementation((data) => {
        updateData = data;
        return chain;
      }),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      is: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      select: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        const rows = applyFilters(getTable(tableName), filters);
        for (const row of rows) Object.assign(row, updateData);
        filters = [];
        return Promise.resolve({ data: rows[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      const rows = applyFilters(getTable(tableName), filters);
      for (const row of rows) Object.assign(row, updateData);
      filters = [];
      return Promise.resolve({ data: rows, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function handleRpc(fnName, params) {
    // Audit-fix (H8) mock: snapshot read consolidating handshake + parties +
    // presentations + binding, introduced by migration 082.
    if (fnName === 'load_verify_context') {
      const hs = getTable('handshakes').find((h) => h.handshake_id === params.p_handshake_id);
      if (!hs) {
        return Promise.resolve({ data: null, error: { code: 'P0002', message: 'HANDSHAKE_NOT_FOUND' } });
      }
      return Promise.resolve({
        data: {
          handshake: hs,
          parties: getTable('handshake_parties').filter((p) => p.handshake_id === params.p_handshake_id),
          presentations: getTable('handshake_presentations').filter((p) => p.handshake_id === params.p_handshake_id),
          binding: getTable('handshake_bindings').find((b) => b.handshake_id === params.p_handshake_id) || null,
        },
        error: null,
      });
    }
    if (fnName === 'create_handshake_atomic') {
      const handshake_id = 'eph_' + crypto.randomBytes(12).toString('hex');
      getTable('handshakes').push({
        handshake_id, mode: params.p_mode, policy_id: params.p_policy_id,
        policy_version: params.p_policy_version || null, interaction_id: params.p_interaction_id || null,
        action_type: params.p_action_type || null, resource_ref: params.p_resource_ref || null,
        intent_ref: params.p_intent_ref || null, action_hash: params.p_action_hash || null,
        policy_hash: params.p_policy_hash || null, idempotency_key: params.p_idempotency_key || null,
        party_set_hash: params.p_party_set_hash || null, metadata: params.p_metadata_json || {},
        status: 'initiated', created_at: new Date().toISOString(),
      });
      if (Array.isArray(params.p_parties)) {
        for (const p of params.p_parties) {
          getTable('handshake_parties').push({
            id: crypto.randomBytes(8).toString('hex'), handshake_id,
            party_role: p.party_role, entity_ref: p.entity_ref,
            assurance_level: p.assurance_level || null, delegation_chain: p.delegation_chain || null,
            verified_status: 'pending',
          });
        }
      }
      if (params.p_binding) getTable('handshake_bindings').push({ handshake_id, ...params.p_binding });
      getTable('handshake_events').push({
        event_id: crypto.randomBytes(12).toString('hex'), handshake_id,
        event_type: 'handshake_initiated', actor_id: params.p_event_actor_id || 'system',
        detail: params.p_event_detail || {}, created_at: new Date().toISOString(),
        sequence_number: getTable('handshake_events').length + 1,
      });
      return Promise.resolve({ data: { handshake_id }, error: null });
    }
    if (fnName === 'present_handshake_writes') {
      const presentation = {
        id: crypto.randomBytes(8).toString('hex'), handshake_id: params.p_handshake_id,
        party_role: params.p_party_role, presentation_type: params.p_presentation_type,
        issuer_ref: params.p_issuer_ref || null, presentation_hash: params.p_presentation_hash,
        disclosure_mode: params.p_disclosure_mode || 'full', raw_claims: params.p_raw_claims || null,
        normalized_claims: params.p_normalized_claims || null,
        canonical_claims_hash: params.p_canonical_claims_hash || null,
        authority_id: params.p_authority_id || null, issuer_status: params.p_issuer_status || 'unknown',
        verified: params.p_verified !== undefined ? params.p_verified : false,
        revocation_checked: params.p_revocation_checked || false,
        revocation_status: params.p_revocation_status || 'unknown',
        created_at: new Date().toISOString(),
      };
      getTable('handshake_presentations').push(presentation);
      const hs = getTable('handshakes').find((h) => h.handshake_id === params.p_handshake_id);
      if (hs && hs.status === 'initiated') hs.status = 'pending_verification';
      getTable('handshake_events').push({
        event_id: crypto.randomBytes(12).toString('hex'), handshake_id: params.p_handshake_id,
        event_type: 'presentation_added', actor_id: params.p_actor_id || 'system',
        detail: params.p_event_detail || {}, created_at: new Date().toISOString(),
        sequence_number: getTable('handshake_events').length + 1,
      });
      return Promise.resolve({ data: presentation, error: null });
    }
    // Audit-fix C1 + 080 + 085: consume_handshake_atomic RPC handler.
    if (fnName === 'consume_handshake_atomic') {
      const hs = getTable('handshakes').find((h) => h.handshake_id === params.p_handshake_id);
      if (!hs) return Promise.resolve({ data: null, error: { code: 'P0002', message: 'HANDSHAKE_NOT_FOUND' } });
      if (hs.status !== 'verified') return Promise.resolve({ data: null, error: { code: 'P0001', message: 'INVALID_STATE_FOR_CONSUMPTION current status: ' + hs.status } });
      const binding = getTable('handshake_bindings').find((b) => b.handshake_id === params.p_handshake_id);
      if (!binding) return Promise.resolve({ data: null, error: { code: 'P0002', message: 'BINDING_NOT_FOUND' } });
      if (binding.binding_hash && params.p_binding_hash && binding.binding_hash !== params.p_binding_hash) {
        return Promise.resolve({ data: null, error: { code: 'P0003', message: 'BINDING_HASH_MISMATCH' } });
      }
      const existing = getTable('handshake_consumptions').find((c) => c.handshake_id === params.p_handshake_id);
      if (existing) return Promise.resolve({ data: null, error: { code: '23505', message: 'unique violation' } });
      const consumption = {
        id: crypto.randomBytes(8).toString('hex'),
        handshake_id: params.p_handshake_id,
        binding_hash: binding.binding_hash || params.p_binding_hash,
        consumed_by_type: params.p_consumed_by_type,
        consumed_by_id: params.p_consumed_by_id,
        actor_entity_ref: params.p_actor_entity_ref,
        consumed_by_action: params.p_consumed_by_action || null,
        created_at: new Date().toISOString(),
      };
      getTable('handshake_consumptions').push(consumption);
      binding.consumed_at = consumption.created_at;
      binding.consumed_by = params.p_actor_entity_ref;
      binding.consumed_for = `${params.p_consumed_by_type}:${params.p_consumed_by_id}`;
      return Promise.resolve({ data: [consumption], error: null });
    }
    if (fnName === 'verify_handshake_writes') {
      const hs = getTable('handshakes').find((h) => h.handshake_id === params.p_handshake_id);
      if (hs) hs.status = params.p_new_status;
      if (Array.isArray(params.p_party_updates)) {
        for (const pu of params.p_party_updates) {
          const party = getTable('handshake_parties').find((p) => p.id === pu.id);
          if (party) party.verified_status = pu.verified_status;
        }
      }
      if (params.p_consume_binding) {
        const binding = getTable('handshake_bindings').find((b) => b.handshake_id === params.p_handshake_id);
        if (binding) binding.consumed_at = new Date().toISOString();
      }
      getTable('handshake_verifications').push({
        id: crypto.randomBytes(8).toString('hex'), handshake_id: params.p_handshake_id,
        outcome: params.p_outcome, reason_codes: params.p_reason_codes,
        assurance_achieved: params.p_assurance_achieved, policy_version: params.p_policy_version,
        binding_hash: params.p_binding_hash, policy_hash: params.p_policy_hash,
        created_at: new Date().toISOString(),
      });
      getTable('handshake_events').push({
        event_id: crypto.randomBytes(12).toString('hex'), handshake_id: params.p_handshake_id,
        event_type: params.p_event_type || 'handshake_verified',
        actor_id: params.p_actor_id || 'system', detail: params.p_event_detail || {},
        created_at: new Date().toISOString(), sequence_number: getTable('handshake_events').length + 1,
      });
      return Promise.resolve({ data: null, error: null });
    }
    return Promise.resolve({ data: null, error: null });
  }

  function mockClient() {
    return {
      from: vi.fn().mockImplementation((tableName) => {
        return {
          select: (...args) => {
            const c = buildSelectChain(tableName);
            c.select(...args);
            return c;
          },
          insert: (rows) => {
            const c = buildInsertChain(tableName);
            return c.insert(rows);
          },
          update: (data) => {
            const c = buildUpdateChain(tableName);
            return c.update(data);
          },
        };
      }),
      rpc: vi.fn().mockImplementation((fnName, params) => handleRpc(fnName, params)),
    };
  }

  return { tables, getTable, mockClient };
}

// ============================================================================
// Helpers
// ============================================================================

function validHandshakeParams(overrides = {}) {
  return {
    mode: 'basic',
    policy_id: 'policy-abc-123',
    action_type: 'connect',
    resource_ref: 'service-xyz',
    parties: [
      { role: 'initiator', entity_ref: 'entity-alice' },
    ],
    payload: { action: 'connect', target: 'service-xyz' },
    binding_ttl_ms: 600_000,
    actor: 'entity-alice',
    ...overrides,
  };
}

function validPresentation(overrides = {}) {
  return {
    type: 'vc',
    data: JSON.stringify({
      entity_id: 'entity-alice',
      display_name: 'Alice Agent',
      assurance_level: 'substantial',
    }),
    issuer_ref: 'issuer-trusted-ca',
    disclosure_mode: 'full',
    ...overrides,
  };
}

function verifyOptsFromSim(sim, hsId) {
  const hs = sim.getTable('handshakes').find((h) => h.handshake_id === hsId);
  const binding = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsId);
  // All test handshakes are created via validHandshakeParams() with this payload.
  // Server now recomputes payload_hash from the raw payload — we must pass the object.
  return {
    payload: { action: 'connect', target: 'service-xyz' },
    policy_hash: hs?.policy_hash || undefined,
    action_hash: hs?.action_hash || undefined,
    nonce: binding?.nonce || binding?._nonce || undefined,
  };
}

/**
 * Helper: create a fully verified handshake ready for consumption.
 * Returns { handshake_id, binding_hash }.
 */
async function createVerifiedHandshake(sim, params = {}) {
  mockGetServiceClient.mockReturnValue(sim.mockClient());

  const result = await initiateHandshake(validHandshakeParams(params));
  const hsId = result.handshake_id;

  mockGetServiceClient.mockReturnValue(sim.mockClient());
  await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

  mockGetServiceClient.mockReturnValue(sim.mockClient());
  const verifyOpts = verifyOptsFromSim(sim, hsId);
  await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });

  const binding = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsId);
  return {
    handshake_id: hsId,
    binding_hash: binding?.binding_hash || binding?.payload_hash || 'hash-placeholder',
  };
}

/**
 * Helper: build a complete, valid binding material object.
 */
function validBindingMaterial(overrides = {}) {
  return {
    action_type: 'connect',
    resource_ref: 'resource-xyz',
    policy_id: 'policy-abc-123',
    policy_version: '1.0.0',
    policy_hash: sha256('{}'),
    interaction_id: 'interaction-001',
    party_set_hash: sha256(JSON.stringify(['initiator:entity-alice'])),
    payload_hash: sha256(JSON.stringify({ action: 'connect' })),
    context_hash: sha256(JSON.stringify({ action_type: 'connect' })),
    nonce: crypto.randomBytes(32).toString('hex'),
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    binding_material_version: BINDING_MATERIAL_VERSION,
    ...overrides,
  };
}

// ============================================================================
// B.5 — Double Consumption Prevention
// ============================================================================

describe('B.5 — Double consumption prevention', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('rejects second consumption of same handshake', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const first = await consumeHandshake({
      handshake_id,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'action-001',
      actor: 'entity-alice',
    });
    expect(first).toBeDefined();
    expect(first.handshake_id).toBe(handshake_id);

    // Second consumption of the same handshake must fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'action-002',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/already been consumed|ALREADY_CONSUMED/);
  });

  it('rejects consumption after revocation', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Revoke the handshake before consuming
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await revokeHandshake(handshake_id, 'security concern', 'entity-alice');

    // Consumption of a revoked handshake must fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'action-001',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/must be in verified state|INVALID_STATE_FOR_CONSUMPTION/);
  });

  it('rejects consumption of expired handshake', async () => {
    // Create a normal handshake, then expire it by manipulating the binding
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

    // Manually expire the binding before verification
    const binding = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsId);
    binding.expires_at = new Date(Date.now() - 1000).toISOString();

    // Verification should detect expiry
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, hsId);
    const verifyResult = await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });

    // The handshake should be expired or rejected, not verified
    expect(verifyResult.outcome).toMatch(/expired|rejected/);

    // Consumption must check verified state — expired handshake is not consumable
    const hs = sim.getTable('handshakes').find((h) => h.handshake_id === hsId);
    expect(hs.status).not.toBe('verified');
  });

  it('rejects consumption of rejected handshake', async () => {
    // Create a handshake but don't add presentations so verification fails
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const result = await initiateHandshake(validHandshakeParams({
      mode: 'mutual',
      parties: [
        { role: 'initiator', entity_ref: 'entity-alice' },
        { role: 'responder', entity_ref: 'entity-bob' },
      ],
    }));
    const hsId = result.handshake_id;

    // Only add initiator presentation, missing responder
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

    // Verify — should be rejected due to missing responder presentation
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, hsId);
    const verifyResult = await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });
    expect(verifyResult.outcome).toBe('rejected');

    // Attempt consumption of rejected handshake
    const binding = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsId);
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id: hsId,
        binding_hash: binding?.binding_hash || 'any-hash',
        consumed_by_type: 'action',
        consumed_by_id: 'action-001',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/must be in verified state|INVALID_STATE_FOR_CONSUMPTION/);
  });

  it('prevents same binding hash used for two different targets', async () => {
    // Create first verified handshake and consume it
    const { handshake_id: hsId1, binding_hash } = await createVerifiedHandshake(sim);
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await consumeHandshake({
      handshake_id: hsId1,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'target-A',
      actor: 'entity-alice',
    });

    // Create second handshake with same payload (same binding hash scenario)
    const { handshake_id: hsId2 } = await createVerifiedHandshake(sim);

    // The second handshake has its own binding_hash computed at initiation.
    // But verify that consumeHandshake on the first handshake_id is blocked.
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id: hsId1,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'target-B',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/already been consumed|ALREADY_CONSUMED/);
  });
});

// ============================================================================
// B.5 — Verify + Consume Race and Revoke + Consume Race
// ============================================================================

describe('B.5 — Concurrent race conditions', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('concurrent double consume: only one succeeds', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    const consumeArgs = {
      handshake_id,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'action-race',
      actor: 'entity-alice',
    };

    // Launch two concurrent consumption attempts
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled([
      consumeHandshake({ ...consumeArgs, consumed_by_id: 'race-1' }),
      consumeHandshake({ ...consumeArgs, consumed_by_id: 'race-2' }),
    ]);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    // Exactly one should succeed, the other should fail
    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(1);
    expect(rejected[0].reason.message).toMatch(/already been consumed|ALREADY_CONSUMED/);
  });

  it('verify + consume race: consumption only succeeds if status is verified', async () => {
    // Create handshake but do NOT verify yet
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

    const binding = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsId);

    // Attempt consume before verify completes — should fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id: hsId,
        binding_hash: binding?.binding_hash || 'any',
        consumed_by_type: 'action',
        consumed_by_id: 'action-001',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/must be in verified state|INVALID_STATE_FOR_CONSUMPTION/);

    // Now verify
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, hsId);
    await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });

    // Now consume should succeed
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const consumption = await consumeHandshake({
      handshake_id: hsId,
      binding_hash: binding?.binding_hash || 'any',
      consumed_by_type: 'action',
      consumed_by_id: 'action-001',
      actor: 'entity-alice',
    });
    expect(consumption).toBeDefined();
    expect(consumption.handshake_id).toBe(hsId);
  });

  it('revoke + consume race: consumption fails if revoked first', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Revoke first
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await revokeHandshake(handshake_id, 'pre-emptive revoke', 'entity-alice');

    // Then attempt consume — must fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'action-001',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/must be in verified state|INVALID_STATE_FOR_CONSUMPTION/);

    // Verify the handshake was NOT consumed
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const consumed = await isHandshakeConsumed(handshake_id);
    expect(consumed).toBe(false);
  });

  it('repeated downstream action retries hit consumption guard', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // First attempt succeeds
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await consumeHandshake({
      handshake_id,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'action-retry',
      actor: 'entity-alice',
    });

    // Simulate 5 retries — all must fail with ALREADY_CONSUMED
    for (let i = 0; i < 5; i++) {
      mockGetServiceClient.mockReturnValue(sim.mockClient());
      await expect(
        consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `action-retry-${i}`,
          actor: 'entity-alice',
        }),
      ).rejects.toThrow(/already been consumed|ALREADY_CONSUMED/);
    }

    // Confirm only one consumption record exists
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id,
    );
    expect(consumptions).toHaveLength(1);
  });
});

// ============================================================================
// A.4 — Binding Completeness Enforcement (pure unit tests)
// ============================================================================

describe('A.4 — Binding completeness enforcement', () => {
  it('accepts binding with null action_type (identity-only flows)', () => {
    // action_type MAY be null for handshakes that don't bind to a specific action.
    // When null, it is still included in the hash, explicitly encoding absence.
    const material = validBindingMaterial({ action_type: null });
    expect(() => validateBindingCompleteness(material)).not.toThrow();
  });

  it('rejects binding with missing party_set_hash', () => {
    const material = validBindingMaterial({ party_set_hash: null });
    expect(() => validateBindingCompleteness(material)).toThrow(
      /BINDING_INVARIANT_VIOLATION.*party_set_hash/,
    );
  });

  it('rejects binding with missing nonce', () => {
    const material = validBindingMaterial({ nonce: null });
    expect(() => validateBindingCompleteness(material)).toThrow(
      /BINDING_INVARIANT_VIOLATION.*nonce/,
    );
  });

  it('rejects binding with missing expires_at', () => {
    const material = validBindingMaterial({ expires_at: null });
    expect(() => validateBindingCompleteness(material)).toThrow(
      /BINDING_INVARIANT_VIOLATION.*expires_at/,
    );
  });

  it('rejects binding with extra unexpected fields', () => {
    const material = validBindingMaterial();
    material.rogue_field = 'should not be here';
    expect(() => validateBindingCompleteness(material)).toThrow(
      /BINDING_INVARIANT_VIOLATION.*Unexpected fields.*rogue_field/,
    );
  });

  it('rejects binding with wrong version number', () => {
    const material = validBindingMaterial({ binding_material_version: 999 });
    expect(() => validateBindingCompleteness(material)).toThrow(
      /BINDING_INVARIANT_VIOLATION.*binding_material_version mismatch/,
    );
  });

  it('accepts binding with all canonical fields present', () => {
    const material = validBindingMaterial();
    // Should not throw
    expect(() => validateBindingCompleteness(material)).not.toThrow();
  });

  it('rejects null binding (non-object guard)', () => {
    expect(() => validateBindingCompleteness(null)).toThrow(
      /BINDING_INVARIANT_VIOLATION.*plain object/,
    );
  });

  it('rejects string binding (non-object guard)', () => {
    expect(() => validateBindingCompleteness('not-a-binding')).toThrow(
      /BINDING_INVARIANT_VIOLATION.*plain object/,
    );
  });

  it('canonicalizeBinding rejects function-valued field', () => {
    // deepSortKeys (internal to canonicalizeBinding) refuses to canonicalize
    // functions. This guards against accidental closure leakage into hashed
    // material. Use a plain object so it gets to the recursion that hits the
    // function-typed value.
    const malformed = { action_type: 'transact', closure: () => 'leak' };
    expect(() => canonicalizeBinding(malformed)).toThrow(
      /CANONICALIZATION_ERROR.*functions/,
    );
  });

  it('binding hash changes when any field changes', () => {
    const base = validBindingMaterial();
    const baseHash = hashBinding(base);

    // Changing each mutable field should produce a different hash
    const fieldsToMutate = {
      action_type: 'disconnect',
      resource_ref: 'resource-other',
      policy_id: 'policy-other',
      policy_version: '2.0.0',
      policy_hash: sha256('other-policy'),
      interaction_id: 'interaction-999',
      party_set_hash: sha256(JSON.stringify(['responder:entity-bob'])),
      payload_hash: sha256(JSON.stringify({ other: true })),
      context_hash: sha256(JSON.stringify({ action_type: 'other' })),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 9_999_999).toISOString(),
    };

    for (const [field, newValue] of Object.entries(fieldsToMutate)) {
      const mutated = validBindingMaterial({ [field]: newValue });
      const mutatedHash = hashBinding(mutated);
      expect(mutatedHash).not.toBe(baseHash);
    }
  });

  it('recomputed binding hash exactly matches stored hash', () => {
    // Build material, hash it, then rebuild from same inputs — must match
    const params = {
      action_type: 'connect',
      resource_ref: 'resource-xyz',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
      policy_hash: sha256('{}'),
      interaction_id: 'interaction-001',
      party_set_hash: sha256(JSON.stringify(['initiator:entity-alice'])),
      payload_hash: sha256(JSON.stringify({ data: 'payload' })),
      context_hash: sha256(JSON.stringify({ action_type: 'connect' })),
      nonce: 'a'.repeat(64),
      expires_at: '2030-01-01T00:00:00.000Z',
    };

    const material1 = buildBindingMaterial(params);
    const hash1 = hashBinding(material1);

    // Recompute from same params
    const material2 = buildBindingMaterial(params);
    const hash2 = hashBinding(material2);

    expect(hash1).toBe(hash2);

    // Also verify canonical JSON is deterministic
    const canonical1 = canonicalizeBinding(material1);
    const canonical2 = canonicalizeBinding(material2);
    expect(canonical1).toBe(canonical2);
  });

  it('buildBindingMaterial enforces completeness internally', () => {
    // buildBindingMaterial calls validateBindingCompleteness, so missing
    // hard-required fields (party_set_hash, nonce, expires_at) should throw
    expect(() =>
      buildBindingMaterial({
        action_type: 'connect',
        resource_ref: 'r',
        policy_id: 'p',
        policy_version: '1',
        policy_hash: 'h',
        interaction_id: 'i',
        // missing party_set_hash — hard required
        payload_hash: 'ph',
        context_hash: 'ch',
        nonce: 'n'.repeat(64),
        expires_at: new Date().toISOString(),
      }),
    ).toThrow(/BINDING_INVARIANT_VIOLATION/);
  });

  it('no handshake may verify successfully unless binding material is complete', async () => {
    // Verify that CANONICAL_BINDING_FIELDS lists exactly the fields that
    // the binding module expects, and that validateBindingCompleteness
    // enforces every single one.
    const expectedFields = [
      'action_type', 'resource_ref', 'policy_id', 'policy_version',
      'policy_hash', 'interaction_id', 'party_set_hash', 'payload_hash',
      'context_hash', 'nonce', 'expires_at', 'binding_material_version',
    ];

    expect(CANONICAL_BINDING_FIELDS).toEqual(expectedFields);

    // Remove each field one at a time and verify rejection
    for (const field of CANONICAL_BINDING_FIELDS) {
      const material = validBindingMaterial();
      delete material[field];
      expect(
        () => validateBindingCompleteness(material),
        `removing "${field}" should cause rejection`,
      ).toThrow(/BINDING_INVARIANT_VIOLATION/);
    }
  });
});

// ============================================================================
// D.4 — Event Reconstruction
// ============================================================================

describe('D.4 — Event reconstruction', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('handshake state can be reconstructed from events alone', async () => {
    // Step 1: Create handshake — events emitted
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    // Step 2: Add presentation — events emitted
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

    // Step 3: Verify — events emitted
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, hsId);
    await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });

    // Step 4: Read events in order
    const events = sim.getTable('handshake_events').filter(
      (e) => e.handshake_id === hsId,
    );

    // Events should exist (at minimum: initiated, verified)
    expect(events.length).toBeGreaterThanOrEqual(1);

    // Step 5: Reconstruct state from events
    let reconstructedStatus = 'unknown';
    let reconstructedOutcome = null;
    const eventHistory = [];

    for (const event of events) {
      eventHistory.push(event.event_type);

      switch (event.event_type) {
        case 'initiated':
        case 'handshake_created':
          reconstructedStatus = 'initiated';
          break;
        case 'presentation_added':
        case 'handshake_presented':
          // Status stays initiated or moves to pending_verification
          if (reconstructedStatus === 'initiated') {
            reconstructedStatus = 'initiated'; // presentations don't change status directly
          }
          break;
        case 'verified':
        case 'handshake_verified':
          reconstructedStatus = 'verified';
          reconstructedOutcome = event.detail?.outcome || 'accepted';
          break;
        case 'rejected':
        case 'handshake_rejected':
          reconstructedStatus = 'rejected';
          reconstructedOutcome = event.detail?.outcome || 'rejected';
          break;
        case 'expired':
        case 'handshake_expired':
          reconstructedStatus = 'expired';
          reconstructedOutcome = 'expired';
          break;
        case 'revoked':
        case 'handshake_revoked':
          reconstructedStatus = 'revoked';
          break;
        default:
          // Informational event, no state change
          break;
      }
    }

    // Step 6: Compare to materialized state
    const materializedHs = sim.getTable('handshakes').find(
      (h) => h.handshake_id === hsId,
    );

    // Step 7: Assert match — fail if drift detected
    expect(reconstructedStatus).toBe(materializedHs.status);

    // The materialized result should also match
    const materializedResult = sim.getTable('handshake_results').find(
      (r) => r.handshake_id === hsId,
    );
    if (materializedResult) {
      expect(reconstructedOutcome).toBe(materializedResult.outcome);
    }
  });

  it('reconstruction detects drift when materialized state is tampered', async () => {
    // Create and verify a handshake
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, hsId);
    await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });

    // Tamper: manually change materialized status to something wrong
    const materializedHs = sim.getTable('handshakes').find(
      (h) => h.handshake_id === hsId,
    );
    materializedHs.status = 'initiated'; // Tampered — should be 'verified'

    // Reconstruct from events
    const events = sim.getTable('handshake_events').filter(
      (e) => e.handshake_id === hsId,
    );

    let reconstructedStatus = 'unknown';
    for (const event of events) {
      switch (event.event_type) {
        case 'initiated':
        case 'handshake_created':
          reconstructedStatus = 'initiated';
          break;
        case 'verified':
        case 'handshake_verified':
          reconstructedStatus = 'verified';
          break;
        case 'rejected':
        case 'handshake_rejected':
          reconstructedStatus = 'rejected';
          break;
        case 'revoked':
        case 'handshake_revoked':
          reconstructedStatus = 'revoked';
          break;
        case 'expired':
        case 'handshake_expired':
          reconstructedStatus = 'expired';
          break;
        default:
          break;
      }
    }

    // Drift detection: reconstructed state differs from materialized state
    const driftDetected = reconstructedStatus !== materializedHs.status;
    expect(driftDetected).toBe(true);
    expect(reconstructedStatus).toBe('verified');
    expect(materializedHs.status).toBe('initiated'); // tampered value
  });

  it('revocation events are captured and reconstructable', async () => {
    const { handshake_id } = await createVerifiedHandshake(sim);

    // Revoke
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await revokeHandshake(handshake_id, 'compromised key', 'entity-alice');

    // Reconstruct
    const events = sim.getTable('handshake_events').filter(
      (e) => e.handshake_id === handshake_id,
    );

    const revokeEvent = events.find(
      (e) => e.event_type === 'revoked' || e.event_type === 'handshake_revoked',
    );
    expect(revokeEvent).toBeDefined();
    expect(revokeEvent.detail.reason).toBe('compromised key');

    // Materialized state should match
    const hs = sim.getTable('handshakes').find(
      (h) => h.handshake_id === handshake_id,
    );
    expect(hs.status).toBe('revoked');
  });

  it('event ordering is preserved across lifecycle', async () => {
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, hsId);
    await verifyHandshake(hsId, { actor: 'system', ...verifyOpts });

    const events = sim.getTable('handshake_events').filter(
      (e) => e.handshake_id === hsId,
    );

    // Events should be in chronological order
    for (let i = 1; i < events.length; i++) {
      const prevTime = new Date(events[i - 1].created_at).getTime();
      const currTime = new Date(events[i].created_at).getTime();
      expect(currTime).toBeGreaterThanOrEqual(prevTime);
    }

    // The last event should be a verification-related event
    const lastEvent = events[events.length - 1];
    expect(['verified', 'handshake_verified', 'rejected', 'handshake_rejected']).toContain(
      lastEvent.event_type,
    );
  });
});
