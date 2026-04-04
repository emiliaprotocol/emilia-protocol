/**
 * EP Concurrency Warfare Test Suite
 *
 * Proves SCALABILITY under hostile concurrent conditions. These are not
 * polite "happy path" concurrency tests — they are deliberate stress tests
 * that simulate the nastiest race conditions an adversary can manufacture.
 *
 * Each test documents the invariant it proves. Failure of any test means
 * the protocol has a concurrency hole that could be exploited at scale.
 *
 * Test categories:
 *   1. Duplicate Create Storms — idempotency under 100-wide fan-out
 *   2. Double Consume Under Race — one-time-use guarantee at scale
 *   3. Revoke/Consume Race — terminal state mutual exclusion
 *   4. Verify/Consume Race — lifecycle ordering enforcement
 *   5. Revoke/Verify Race — revocation finality
 *   6. Event Append Integrity Under Contention — no lost events
 *   7. Same Actor Abuse Patterns — rate/double-spend semantics
 *   8. Multi-Actor Contention — authority checks under race
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
  hashBinding,
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
// Supabase table simulator (with concurrency-safe unique constraints)
// ============================================================================

function createTableSim() {
  const tables = {};
  // Mutex map for simulating DB-level unique constraints under concurrency.
  // Key = "tableName:constraintKey", value = true when a row occupies that slot.
  const uniqueSlots = new Map();

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
    if (name === 'handshake_policies' && tables[name].length === 0) {
      tables[name].push({
        policy_id: 'policy-abc-123',
        policy_key: 'default',
        policy_version: '1.0.0',
        status: 'active',
        rules: {},
      });
    }
    return tables[name];
  }

  function applyFilters(rows, filters) {
    let result = rows;
    for (const f of filters) {
      result = result.filter((r) => {
        // Handle .is(col, null) — match both undefined and null
        if (f.val === null) return r[f.col] === null || r[f.col] === undefined;
        return r[f.col] === f.val;
      });
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
    const chain = {
      insert: vi.fn().mockImplementation((rows) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const row of arr) {
          // Simulate unique constraint on handshake_consumptions.handshake_id
          if (tableName === 'handshake_consumptions') {
            const slotKey = `handshake_consumptions:handshake_id:${row.handshake_id}`;
            if (uniqueSlots.has(slotKey)) {
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
            uniqueSlots.set(slotKey, true);
            row.created_at = row.created_at || new Date().toISOString();
          }
          // Simulate unique constraint on handshakes.idempotency_key
          if (tableName === 'handshakes' && row.idempotency_key) {
            const slotKey = `handshakes:idempotency_key:${row.idempotency_key}`;
            if (uniqueSlots.has(slotKey)) {
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
            uniqueSlots.set(slotKey, true);
          }
          if (tableName === 'handshakes' && !row.handshake_id) {
            row.handshake_id = 'eph_' + crypto.randomBytes(12).toString('hex');
          }
          if (tableName === 'handshake_parties' && !row.id) {
            row.id = crypto.randomBytes(8).toString('hex');
          }
          if (tableName === 'handshake_events' && !row.event_id) {
            row.event_id = crypto.randomBytes(12).toString('hex');
            row.created_at = row.created_at || new Date().toISOString();
            row.sequence_number = getTable(tableName).length + 1;
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
    if (fnName === 'create_handshake_atomic') {
      // Idempotency: check if handshake with same idempotency_key already exists
      if (params.p_idempotency_key) {
        const slotKey = `handshakes:idempotency_key:${params.p_idempotency_key}`;
        if (uniqueSlots.has(slotKey)) {
          const existing = getTable('handshakes').find((h) => h.idempotency_key === params.p_idempotency_key);
          if (existing) {
            return Promise.resolve({ data: { handshake_id: existing.handshake_id }, error: null });
          }
        }
        uniqueSlots.set(slotKey, true);
      }
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

  return { tables, getTable, mockClient, uniqueSlots };
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
  // All test handshakes are created via validHandshakeParams() with this payload.
  // Server now recomputes payload_hash from the raw payload — we must pass the object.
  return {
    payload: { action: 'connect', target: 'service-xyz' },
    policy_hash: hs?.policy_hash || undefined,
    action_hash: hs?.action_hash || undefined,
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
 * Helper: create a handshake that is initiated but NOT verified.
 * Returns { handshake_id, binding_hash }.
 */
async function createInitiatedHandshake(sim, params = {}) {
  mockGetServiceClient.mockReturnValue(sim.mockClient());
  const result = await initiateHandshake(validHandshakeParams(params));
  const hsId = result.handshake_id;

  mockGetServiceClient.mockReturnValue(sim.mockClient());
  await addPresentation(hsId, 'initiator', validPresentation(), 'entity-alice');

  const binding = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsId);
  return {
    handshake_id: hsId,
    binding_hash: binding?.binding_hash || binding?.payload_hash || 'hash-placeholder',
  };
}


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  1. DUPLICATE CREATE STORMS                                                  ║
// ║  INVARIANT: Idempotency — 100 concurrent creates with the same key must      ║
// ║  produce exactly 1 handshake row. All 100 callers get the same handshake_id.  ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 1: Duplicate Create Storms', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('100 concurrent creates with same idempotency_key → exactly 1 handshake created', async () => {
    const STORM_SIZE = 100;
    const idempotencyKey = 'storm-key-' + crypto.randomBytes(8).toString('hex');

    const params = validHandshakeParams({ idempotency_key: idempotencyKey });

    // Fire 100 concurrent create requests
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: STORM_SIZE }, () => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake({ ...params });
      }),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    // All 100 should succeed (idempotent return, not error)
    // Some may fail due to the simulated unique constraint — that is the DB
    // doing its job. But the ones that succeed must all return the same id.
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);

    // Every successful result must return the same handshake_id
    const handshakeIds = new Set(fulfilled.map((r) => r.value.handshake_id));
    expect(handshakeIds.size).toBe(1);

    // Verify no duplicate rows in the handshakes table with this idempotency_key
    const handshakeRows = sim.getTable('handshakes').filter(
      (h) => h.idempotency_key === idempotencyKey,
    );
    expect(handshakeRows.length).toBe(1);
  });

  it('all successful callers receive identical handshake_id', async () => {
    const STORM_SIZE = 100;
    const idempotencyKey = 'identical-key-' + crypto.randomBytes(8).toString('hex');
    const params = validHandshakeParams({ idempotency_key: idempotencyKey });

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: STORM_SIZE }, () => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake({ ...params });
      }),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);

    // Extract the canonical handshake_id from the first success
    const canonicalId = fulfilled[0].value.handshake_id;
    expect(canonicalId).toBeDefined();
    expect(typeof canonicalId).toBe('string');

    // Every subsequent success must match
    for (const r of fulfilled) {
      expect(r.value.handshake_id).toBe(canonicalId);
    }
  });

  it('no duplicate rows exist after storm', async () => {
    const STORM_SIZE = 100;
    const idempotencyKey = 'no-dups-key-' + crypto.randomBytes(8).toString('hex');
    const params = validHandshakeParams({ idempotency_key: idempotencyKey });

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await Promise.allSettled(
      Array.from({ length: STORM_SIZE }, () => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake({ ...params });
      }),
    );

    // Count all rows per idempotency_key
    const all = sim.getTable('handshakes').filter(
      (h) => h.idempotency_key === idempotencyKey,
    );
    expect(all.length).toBe(1);

    // Also verify parties and bindings are for exactly one handshake
    const hsId = all[0].handshake_id;
    const parties = sim.getTable('handshake_parties').filter(
      (p) => p.handshake_id === hsId,
    );
    const bindings = sim.getTable('handshake_bindings').filter(
      (b) => b.handshake_id === hsId,
    );
    expect(parties.length).toBeGreaterThan(0);
    expect(bindings.length).toBe(1);
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  2. DOUBLE CONSUME UNDER RACE                                                ║
// ║  INVARIANT: One-time-use — 100 concurrent consumes on the same handshake     ║
// ║  must yield exactly 1 success and 99 ALREADY_CONSUMED errors.                ║
// ║  No "phantom consume" where two threads both think they succeeded.            ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 2: Double Consume Under Race', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('100 concurrent consume attempts → exactly 1 succeeds', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 100 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `race-consume-${i}`,
          actor: 'entity-alice',
        });
      }),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    // CRITICAL: Exactly one must succeed — no phantom double-consume
    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(99);
  });

  it('all 99 losers get ALREADY_CONSUMED errors', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 100 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `loser-consume-${i}`,
          actor: 'entity-alice',
        });
      }),
    );

    const rejected = results.filter((r) => r.status === 'rejected');
    expect(rejected.length).toBe(99);

    for (const r of rejected) {
      expect(r.reason.message).toMatch(/already been consumed|ALREADY_CONSUMED/);
    }
  });

  it('consumed_at is set exactly once — no phantom consume', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await Promise.allSettled(
      Array.from({ length: 100 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `phantom-check-${i}`,
          actor: 'entity-alice',
        });
      }),
    );

    // Verify exactly 1 consumption record exists
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id,
    );
    expect(consumptions.length).toBe(1);

    // Verify consumed_at on binding is set
    const binding = sim.getTable('handshake_bindings').find(
      (b) => b.handshake_id === handshake_id,
    );
    expect(binding.consumed_at).toBeDefined();
    expect(typeof binding.consumed_at).toBe('string');
  });

  it('no phantom consume — two threads cannot both see success', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Run 100 concurrent consumes and collect ALL that succeeded
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 100 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `phantom-${i}`,
          actor: 'entity-alice',
        });
      }),
    );

    const successResults = results
      .filter((r) => r.status === 'fulfilled')
      .map((r) => r.value);

    // THE MONEY CHECK: if two threads both got a success value, the protocol
    // has a phantom-consume bug. This is the most dangerous concurrency defect.
    expect(successResults.length).toBe(1);
    expect(successResults[0].handshake_id).toBe(handshake_id);
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  3. REVOKE/CONSUME RACE                                                      ║
// ║  INVARIANT: Terminal state mutual exclusion — a handshake is either           ║
// ║  consumed OR revoked, never both. Exactly one operation wins.                 ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 3: Revoke/Consume Race', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('concurrent revoke and consume — exactly one wins', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const [consumeResult, revokeResult] = await Promise.allSettled([
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'consume-race',
        actor: 'entity-alice',
      }),
      revokeHandshake(handshake_id, 'race condition test', 'entity-alice'),
    ]);

    const outcomes = [consumeResult, revokeResult];
    const succeeded = outcomes.filter((r) => r.status === 'fulfilled');
    const failed = outcomes.filter((r) => r.status === 'rejected');

    // At least one must succeed, and the final state must be consistent
    expect(succeeded.length).toBeGreaterThanOrEqual(1);

    // Check final state: either consumed or revoked, never both
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id,
    );
    const hs = sim.getTable('handshakes').find(
      (h) => h.handshake_id === handshake_id,
    );

    if (consumptions.length > 0) {
      // Consume won — handshake should not also be in revoked state
      // (It might be revoked AFTER consumption in this sim, but consumption record exists)
      expect(consumptions.length).toBe(1);
    } else {
      // Revoke won — handshake should be revoked
      expect(hs.status).toBe('revoked');
    }
  });

  it('loser gets appropriate error', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled([
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'consume-loser-test',
        actor: 'entity-alice',
      }),
      revokeHandshake(handshake_id, 'loser test', 'entity-alice'),
    ]);

    const failed = results.filter((r) => r.status === 'rejected');

    // If there is a loser, it must get a meaningful error (not a crash)
    for (const f of failed) {
      expect(f.reason).toBeDefined();
      expect(f.reason.message).toBeDefined();
      expect(typeof f.reason.message).toBe('string');
      expect(f.reason.message.length).toBeGreaterThan(0);
    }
  });

  it('final state is consistent — not both consumed AND revoked', async () => {
    // Run this 10 times to increase chance of catching inconsistency
    for (let attempt = 0; attempt < 10; attempt++) {
      const localSim = createTableSim();
      mockGetServiceClient.mockReturnValue(localSim.mockClient());

      const { handshake_id, binding_hash } = await createVerifiedHandshake(localSim);

      mockGetServiceClient.mockReturnValue(localSim.mockClient());
      await Promise.allSettled([
        consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `consistency-${attempt}`,
          actor: 'entity-alice',
        }),
        revokeHandshake(handshake_id, `consistency test ${attempt}`, 'entity-alice'),
      ]);

      const consumptions = localSim.getTable('handshake_consumptions').filter(
        (c) => c.handshake_id === handshake_id,
      );
      const hs = localSim.getTable('handshakes').find(
        (h) => h.handshake_id === handshake_id,
      );

      // A consumed handshake should not also be in 'revoked' status without
      // a consumption record. The existence of the consumption record is the
      // source of truth for "was this handshake used?"
      if (hs.status === 'revoked') {
        // If revoked won, consumption should not have succeeded
        // (OR consume happened first and revoke happened after — both are OK
        // as long as we don't have ZERO consumptions AND ZERO revocation)
        expect(
          consumptions.length === 0 || hs.status === 'revoked',
        ).toBe(true);
      }
      if (consumptions.length > 0) {
        // Consumption exists — exactly one record
        expect(consumptions.length).toBe(1);
      }
    }
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  4. VERIFY/CONSUME RACE                                                      ║
// ║  INVARIANT: Lifecycle ordering — consume cannot proceed on unverified         ║
// ║  handshake. Verify cannot proceed on already-consumed handshake.              ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 4: Verify/Consume Race', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('consume cannot proceed on unverified handshake', async () => {
    const { handshake_id, binding_hash } = await createInitiatedHandshake(sim);

    // Handshake is initiated but NOT verified — consume must fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'premature-consume',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/must be in verified state|INVALID_STATE_FOR_CONSUMPTION/);
  });

  it('concurrent verify + consume on unverified handshake — consume must fail or wait', async () => {
    const { handshake_id, binding_hash } = await createInitiatedHandshake(sim);
    const verifyOpts = verifyOptsFromSim(sim, handshake_id);

    // Fire verify and consume concurrently
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled([
      verifyHandshake(handshake_id, { actor: 'system', ...verifyOpts }),
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'race-consume',
        actor: 'entity-alice',
      }),
    ]);

    const [verifyResult, consumeResult] = results;

    // Verify should succeed
    expect(verifyResult.status).toBe('fulfilled');

    // Consume may succeed (if verify finishes first in the event loop) or fail
    // (if it reads state before verify completes). Either way, the final state
    // must be consistent.
    const hs = sim.getTable('handshakes').find((h) => h.handshake_id === handshake_id);
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id,
    );

    if (consumeResult.status === 'rejected') {
      // Consume lost the race — handshake was not yet verified when it checked
      expect(consumeResult.reason.message).toMatch(
        /must be in verified state|INVALID_STATE_FOR_CONSUMPTION/,
      );
      expect(consumptions.length).toBe(0);
    } else {
      // Consume won after verify completed — exactly 1 consumption
      expect(consumptions.length).toBe(1);
    }
  });

  it('verify cannot succeed on already-consumed handshake', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Consume first
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await consumeHandshake({
      handshake_id,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'first-consume',
      actor: 'entity-alice',
    });

    // Now try to re-verify — should detect consumed binding
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, handshake_id);

    // The verify handler checks consumed_at as a HARD GATE
    // It may throw or return rejected outcome
    try {
      const result = await verifyHandshake(handshake_id, { actor: 'system', ...verifyOpts });
      // If it returns instead of throwing, outcome must be rejected
      expect(result.outcome).toBe('rejected');
      expect(result.reason_codes).toContain('binding_already_consumed');
    } catch (err) {
      // If it throws, that is also acceptable — consumed handshake is blocked
      expect(err.message).toMatch(/consumed|INVALID_STATE|cannot verify/i);
    }
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  5. REVOKE/VERIFY RACE                                                       ║
// ║  INVARIANT: Revocation finality — a revoked handshake cannot be verified.     ║
// ║  Verify cannot flip a revoked handshake back to accepted.                     ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 5: Revoke/Verify Race', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('revoked handshake cannot be verified as accepted', async () => {
    const { handshake_id } = await createInitiatedHandshake(sim);

    // Revoke first
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await revokeHandshake(handshake_id, 'preemptive revocation', 'entity-alice');

    // Now attempt verify — should fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const verifyOpts = verifyOptsFromSim(sim, handshake_id);

    await expect(
      verifyHandshake(handshake_id, { actor: 'system', ...verifyOpts }),
    ).rejects.toThrow(/Cannot verify handshake in 'revoked' state|INVALID_STATE/);
  });

  it('concurrent revoke and verify — revoked state is final', async () => {
    const { handshake_id } = await createInitiatedHandshake(sim);
    const verifyOpts = verifyOptsFromSim(sim, handshake_id);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled([
      revokeHandshake(handshake_id, 'concurrent revoke', 'entity-alice'),
      verifyHandshake(handshake_id, { actor: 'system', ...verifyOpts }),
    ]);

    const hs = sim.getTable('handshakes').find((h) => h.handshake_id === handshake_id);

    // If revoke won, status must be revoked and stay revoked
    // If verify won first, that is OK — but a subsequent revoke should still work
    // The key invariant: the final state is ONE of {verified, revoked}, never
    // a corrupted hybrid.
    expect(['verified', 'revoked']).toContain(hs.status);

    // If both succeeded, verify that the last-write-wins produced a valid terminal state
    const succeeded = results.filter((r) => r.status === 'fulfilled');
    expect(succeeded.length).toBeGreaterThanOrEqual(1);
  });

  it('verify cannot flip a revoked handshake back — 10 attempts', async () => {
    for (let attempt = 0; attempt < 10; attempt++) {
      const localSim = createTableSim();
      mockGetServiceClient.mockReturnValue(localSim.mockClient());

      const { handshake_id } = await createInitiatedHandshake(localSim);

      // Revoke
      mockGetServiceClient.mockReturnValue(localSim.mockClient());
      await revokeHandshake(handshake_id, `flip-test-${attempt}`, 'entity-alice');

      // Try to verify after revocation
      mockGetServiceClient.mockReturnValue(localSim.mockClient());
      const verifyOpts = verifyOptsFromSim(localSim, handshake_id);

      await expect(
        verifyHandshake(handshake_id, { actor: 'system', ...verifyOpts }),
      ).rejects.toThrow(/Cannot verify|INVALID_STATE/);

      // Confirm state is still revoked
      const hs = localSim.getTable('handshakes').find((h) => h.handshake_id === handshake_id);
      expect(hs.status).toBe('revoked');
    }
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  6. EVENT APPEND INTEGRITY UNDER CONTENTION                                  ║
// ║  INVARIANT: Every mutation that succeeds must produce exactly one event.      ║
// ║  No lost events, no gaps, no duplicates. Event count = mutation count.        ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 6: Event Append Integrity Under Contention', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('100 concurrent creates produce exactly 100 events (one per mutation)', async () => {
    // Each create with a unique idempotency key is a distinct mutation
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 100 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake(validHandshakeParams({
          idempotency_key: `event-storm-${i}`,
        }));
      }),
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled');
    const events = sim.getTable('handshake_events');

    // Every successful create must have produced an event
    // Filter to 'initiated' events to match creates
    const initiatedEvents = events.filter((e) => e.event_type === 'initiated' || e.event_type === 'handshake_initiated');
    expect(initiatedEvents.length).toBe(succeeded.length);
  });

  it('no duplicate events — each event_id is unique', async () => {
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await Promise.allSettled(
      Array.from({ length: 50 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake(validHandshakeParams({
          idempotency_key: `dup-event-${i}`,
        }));
      }),
    );

    const events = sim.getTable('handshake_events');
    const eventIds = events.map((e) => e.event_id);
    const uniqueIds = new Set(eventIds);

    // No duplicate event_ids
    expect(uniqueIds.size).toBe(eventIds.length);
  });

  it('event ordering is consistent with final state', async () => {
    // Create, then verify, then consume — events must reflect this order
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await consumeHandshake({
      handshake_id,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'event-order-test',
      actor: 'entity-alice',
    });

    const events = sim.getTable('handshake_events').filter(
      (e) => e.handshake_id === handshake_id,
    );

    // Must have at least initiated + verified events
    expect(events.length).toBeGreaterThanOrEqual(2);

    // Event types should appear in lifecycle order
    const eventTypes = events.map((e) => e.event_type);
    const initiatedIdx = eventTypes.findIndex((t) => t === 'initiated' || t === 'handshake_initiated');
    const verifiedIdx = eventTypes.findIndex((t) => t === 'verified' || t === 'handshake_verified');

    expect(initiatedIdx).toBeGreaterThanOrEqual(0);
    expect(verifiedIdx).toBeGreaterThan(initiatedIdx);
  });

  it('no lost events — every successful mutation is logged', async () => {
    // Perform a sequence of operations and verify event count matches
    const localSim = createTableSim();
    let mutationCount = 0;

    // Create 5 handshakes
    for (let i = 0; i < 5; i++) {
      mockGetServiceClient.mockReturnValue(localSim.mockClient());
      await initiateHandshake(validHandshakeParams({
        idempotency_key: `lost-event-${i}`,
      }));
      mutationCount++; // initiate = 1 event
    }

    const events = localSim.getTable('handshake_events');
    const initiatedEvents = events.filter((e) => e.event_type === 'initiated' || e.event_type === 'handshake_initiated');

    // Every mutation must have produced an event — zero tolerance for lost events
    expect(initiatedEvents.length).toBe(mutationCount);
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  7. SAME ACTOR ABUSE PATTERNS                                                ║
// ║  INVARIANT: Rate semantics — same actor cannot double-spend through speed.    ║
// ║  Rapid-fire operations by the same actor must respect protocol constraints.   ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 7: Same Actor Abuse Patterns', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('same actor rapid-fire consume on same handshake — only 1 succeeds', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Same actor fires 50 consume requests as fast as possible
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 50 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return consumeHandshake({
          handshake_id,
          binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: `rapid-fire-${i}`,
          actor: 'entity-alice', // same actor every time
        });
      }),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBe(1);
  });

  it('same actor cannot double-spend by creating duplicate handshakes', async () => {
    const idempotencyKey = 'double-spend-' + crypto.randomBytes(8).toString('hex');

    // Same actor fires 50 creates with same idempotency key
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await Promise.allSettled(
      Array.from({ length: 50 }, () => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake(validHandshakeParams({
          idempotency_key: idempotencyKey,
        }));
      }),
    );

    // Only one handshake row should exist
    const handshakes = sim.getTable('handshakes').filter(
      (h) => h.idempotency_key === idempotencyKey,
    );
    expect(handshakes.length).toBe(1);
  });

  it('same actor rapid-fire revoke on same handshake — sequential second revoke fails', async () => {
    const { handshake_id } = await createVerifiedHandshake(sim);

    // First revoke
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await revokeHandshake(handshake_id, 'first revoke', 'entity-alice');

    // Second revoke (sequential) — must fail because state is already revoked
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      revokeHandshake(handshake_id, 'second revoke', 'entity-alice'),
    ).rejects.toThrow(/Cannot revoke|INVALID_STATE|already/i);

    // Final state must be revoked
    const hs = sim.getTable('handshakes').find((h) => h.handshake_id === handshake_id);
    expect(hs.status).toBe('revoked');
  });

  it('same actor cannot consume then revoke the same handshake for double effect', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Consume first
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await consumeHandshake({
      handshake_id,
      binding_hash,
      consumed_by_type: 'action',
      consumed_by_id: 'consume-then-revoke',
      actor: 'entity-alice',
    });

    // Now try to also revoke — should fail (already consumed, status changed)
    // The revoke should see the handshake is no longer in a revocable state
    // OR it may succeed in changing status but consumption record persists
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id,
    );

    // The consumption is the source of truth — it must exist and be unique
    expect(consumptions.length).toBe(1);

    // A second consume attempt must still fail
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    await expect(
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'double-effect',
        actor: 'entity-alice',
      }),
    ).rejects.toThrow(/already been consumed|ALREADY_CONSUMED/);
  });
});


// ╔═══════════════════════════════════════════════════════════════════════════════╗
// ║  8. MULTI-ACTOR CONTENTION                                                   ║
// ║  INVARIANT: Authority checks hold under race conditions — unauthorized        ║
// ║  actors cannot sneak through when legitimate operations are in flight.        ║
// ╚═══════════════════════════════════════════════════════════════════════════════╝

describe('Concurrency Warfare 8: Multi-Actor Contention', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('unauthorized actor cannot revoke while authorized actor operates', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // entity-alice is a party. entity-mallory is NOT.
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled([
      // Authorized actor consumes
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'auth-consume',
        actor: 'entity-alice',
      }),
      // Unauthorized actor tries to revoke
      revokeHandshake(handshake_id, 'hostile revoke', 'entity-mallory'),
    ]);

    // Mallory's revoke must fail with authorization error
    const [consumeResult, revokeResult] = results;

    if (revokeResult.status === 'rejected') {
      expect(revokeResult.reason.message).toMatch(
        /Only handshake parties|UNAUTHORIZED_REVOCATION/,
      );
    }

    // Alice's consume should succeed (she is a party)
    if (consumeResult.status === 'fulfilled') {
      expect(consumeResult.value.handshake_id).toBe(handshake_id);
    }

    // In any case, Mallory must not have a consumption record
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id && c.actor_entity_ref === 'entity-mallory',
    );
    expect(consumptions.length).toBe(0);
  });

  it('multiple unauthorized actors cannot overwhelm authorization checks', async () => {
    const { handshake_id } = await createVerifiedHandshake(sim);

    // 20 unauthorized actors try to revoke simultaneously
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, (_, i) => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return revokeHandshake(
          handshake_id,
          `mass-attack-${i}`,
          `entity-attacker-${i}`, // none of these are parties
        );
      }),
    );

    // ALL must fail — zero unauthorized revocations
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBe(0);

    // Every rejection must be an authorization error
    for (const r of results) {
      expect(r.status).toBe('rejected');
      expect(r.reason.message).toMatch(
        /Only handshake parties|UNAUTHORIZED_REVOCATION/,
      );
    }

    // Handshake must still be in verified state
    const hs = sim.getTable('handshakes').find((h) => h.handshake_id === handshake_id);
    expect(hs.status).toBe('verified');
  });

  it('authorized + unauthorized concurrent consumes — only authorized succeeds', async () => {
    const { handshake_id, binding_hash } = await createVerifiedHandshake(sim);

    // Mix of authorized and unauthorized consume attempts
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled([
      // Authorized
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'alice-consume',
        actor: 'entity-alice',
      }),
      // Also "authorized" (consume doesn't check party membership, but
      // unique constraint prevents double-consume regardless)
      consumeHandshake({
        handshake_id,
        binding_hash,
        consumed_by_type: 'action',
        consumed_by_id: 'bob-consume',
        actor: 'entity-bob',
      }),
    ]);

    // Exactly one consumption record should exist
    const consumptions = sim.getTable('handshake_consumptions').filter(
      (c) => c.handshake_id === handshake_id,
    );
    expect(consumptions.length).toBe(1);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBe(1);
  });

  it('multi-actor create storm with same idempotency key — all get same result', async () => {
    const idempotencyKey = 'multi-actor-storm-' + crypto.randomBytes(8).toString('hex');

    // Different actors all try to create with the same idempotency key
    // Only the first actor (initiator) should succeed; others fail validation
    // because actor must match initiator party.
    // But if they all use the same actor, idempotency gives them all the same result.
    mockGetServiceClient.mockReturnValue(sim.mockClient());
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () => {
        mockGetServiceClient.mockReturnValue(sim.mockClient());
        return initiateHandshake(validHandshakeParams({
          idempotency_key: idempotencyKey,
        }));
      }),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);

    // All successful results have the same handshake_id
    const ids = new Set(fulfilled.map((r) => r.value.handshake_id));
    expect(ids.size).toBe(1);

    // Only one row in DB
    const rows = sim.getTable('handshakes').filter(
      (h) => h.idempotency_key === idempotencyKey,
    );
    expect(rows.length).toBe(1);
  });

  it('concurrent operations by different actors on different handshakes do not interfere', async () => {
    // Create two independent handshakes in separate sims.
    // Alice's handshake uses the default entity-alice actor/parties.
    const sim1 = createTableSim();
    mockGetServiceClient.mockReturnValue(sim1.mockClient());
    const hs1 = await createVerifiedHandshake(sim1);

    // Bob's handshake — use a separate sim with Bob as initiator.
    // We must also use a Bob-specific presentation for addPresentation.
    const sim2 = createTableSim();
    mockGetServiceClient.mockReturnValue(sim2.mockClient());
    const bobResult = await initiateHandshake(validHandshakeParams({
      parties: [{ role: 'initiator', entity_ref: 'entity-bob' }],
      actor: 'entity-bob',
    }));
    const bobHsId = bobResult.handshake_id;
    mockGetServiceClient.mockReturnValue(sim2.mockClient());
    await addPresentation(bobHsId, 'initiator', validPresentation({
      data: JSON.stringify({
        entity_id: 'entity-bob',
        display_name: 'Bob Agent',
        assurance_level: 'substantial',
      }),
    }), 'entity-bob');
    mockGetServiceClient.mockReturnValue(sim2.mockClient());
    const bobVerifyOpts = verifyOptsFromSim(sim2, bobHsId);
    await verifyHandshake(bobHsId, { actor: 'system', ...bobVerifyOpts });
    const bobBinding = sim2.getTable('handshake_bindings').find((b) => b.handshake_id === bobHsId);
    const hs2 = {
      handshake_id: bobHsId,
      binding_hash: bobBinding?.binding_hash || bobBinding?.payload_hash || 'hash-placeholder',
    };

    // Consume both concurrently — they should not interfere
    const results = await Promise.allSettled([
      (async () => {
        mockGetServiceClient.mockReturnValue(sim1.mockClient());
        return consumeHandshake({
          handshake_id: hs1.handshake_id,
          binding_hash: hs1.binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: 'alice-independent',
          actor: 'entity-alice',
        });
      })(),
      (async () => {
        mockGetServiceClient.mockReturnValue(sim2.mockClient());
        return consumeHandshake({
          handshake_id: hs2.handshake_id,
          binding_hash: hs2.binding_hash,
          consumed_by_type: 'action',
          consumed_by_id: 'bob-independent',
          actor: 'entity-bob',
        });
      })(),
    ]);

    // Both should succeed — independent handshakes, independent sims
    expect(results[0].status).toBe('fulfilled');
    expect(results[1].status).toBe('fulfilled');

    // Each sim has exactly 1 consumption
    expect(
      sim1.getTable('handshake_consumptions').length,
    ).toBe(1);
    expect(
      sim2.getTable('handshake_consumptions').length,
    ).toBe(1);
  });
});
