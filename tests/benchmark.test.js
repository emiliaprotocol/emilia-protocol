/**
 * EMILIA Protocol — Performance Benchmark Suite
 *
 * Measures code-path overhead for EP hot paths using mock infrastructure.
 * These benchmarks prove the protocol kernel is lightweight — they do NOT
 * measure real DB latency (which is infrastructure-dependent).
 *
 * What's included:
 *   - Handshake create logic (validation, hash computation, mock DB writes)
 *   - Handshake verify logic (state checks, binding re-hash, policy evaluation)
 *   - Consume logic (state check, mock atomic insert)
 *   - Binding hash computation (SHA-256 of canonical binding material)
 *   - Policy evaluation (trust profile computation + policy gate)
 *
 * What's excluded:
 *   - Real database I/O (mocked via createTableSim)
 *   - Network latency
 *   - TLS handshakes
 *
 * SLO targets (GOD FILE §13.1 — code-path overhead, not end-to-end):
 *   Handshake create: p50 < 60ms, p95 < 150ms, p99 < 300ms
 *   Handshake verify: p50 < 80ms, p95 < 200ms, p99 < 400ms
 *   Consume:          p50 < 40ms, p95 < 120ms, p99 < 250ms
 *
 * Run: npx vitest run tests/benchmark.test.js
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ============================================================================
// Constants
// ============================================================================

const ITERATIONS = 1000;

const SLO = {
  handshake_create: { p50: 60, p95: 150, p99: 300 },
  handshake_verify: { p50: 80, p95: 200, p99: 400 },
  consume:          { p50: 40, p95: 120, p99: 250 },
};

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
// Import module under test (after mocks)
// ============================================================================

import {
  initiateHandshake,
  verifyHandshake,
  consumeHandshake,
  _handleInitiateHandshake,
  _handleVerifyHandshake,
  hashBinding,
  buildBindingMaterial,
  computePartySetHash,
  computeContextHash,
  computePayloadHash,
  computePolicyHash,
} from '../lib/handshake/index.js';

import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
} from '../lib/scoring-v2.js';

// Wire handlers after import
_handshakeHandlers = {
  initiate_handshake: _handleInitiateHandshake,
  verify_handshake: _handleVerifyHandshake,
  issue_commit: async () => ({
    result: { commit_id: 'epc_mock_' + crypto.randomBytes(4).toString('hex'), decision: 'allow' },
    aggregateId: 'epc_mock',
  }),
};

// ============================================================================
// Supabase table simulator (from handshake.test.js)
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
      result = result.filter((r) => r[f.col] === f.val);
    }
    return result;
  }

  function buildSelectChain(tableName) {
    let filters = [];
    const chain = {
      select: vi.fn().mockImplementation(() => chain),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      neq: vi.fn().mockImplementation(() => chain),
      order: vi.fn().mockImplementation(() => chain),
      limit: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        const filtered = applyFilters(getTable(tableName), filters);
        filters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      maybeSingle: vi.fn().mockImplementation(() => {
        const filtered = applyFilters(getTable(tableName), filters);
        filters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      const filtered = applyFilters(getTable(tableName), filters);
      filters = [];
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
          if (tableName === 'handshakes' && !row.handshake_id) {
            row.handshake_id = 'eph_' + crypto.randomBytes(12).toString('hex');
          }
          if (tableName === 'handshake_parties' && !row.id) {
            row.id = crypto.randomBytes(8).toString('hex');
          }
          if (tableName === 'handshake_consumptions' && !row.id) {
            row.id = crypto.randomBytes(8).toString('hex');
            row.created_at = new Date().toISOString();
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
    parties: [
      { role: 'initiator', entity_ref: 'entity-alice' },
    ],
    payload: { action: 'connect', target: 'service-xyz' },
    binding_ttl_ms: 600_000,
    actor: 'entity-alice',
    ...overrides,
  };
}

function percentile(sortedArr, p) {
  const idx = Math.ceil((p / 100) * sortedArr.length) - 1;
  return sortedArr[Math.max(0, idx)];
}

function computePercentiles(timings) {
  const sorted = [...timings].sort((a, b) => a - b);
  return {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean: timings.reduce((s, t) => s + t, 0) / timings.length,
  };
}

function reportResults(label, stats) {
  console.log(
    `[BENCH] ${label}: p50=${stats.p50.toFixed(3)}ms p95=${stats.p95.toFixed(3)}ms ` +
    `p99=${stats.p99.toFixed(3)}ms mean=${stats.mean.toFixed(3)}ms ` +
    `min=${stats.min.toFixed(3)}ms max=${stats.max.toFixed(3)}ms (n=${ITERATIONS})`
  );
}

function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 90,
    product_accuracy: 85,
    price_integrity: 95,
    return_processing: 80,
    agent_satisfaction: 88,
    composite_score: 88,
    submitted_by: overrides.submitted_by || 'submitter-1',
    submitter_score: overrides.submitter_score ?? 85,
    submitter_established: overrides.submitter_established ?? true,
    graph_weight: overrides.graph_weight ?? 1.0,
    agent_behavior: overrides.agent_behavior || 'completed',
    created_at: overrides.created_at || new Date().toISOString(),
    context: overrides.context || null,
    ...overrides,
  };
}

// ============================================================================
// 1. Handshake Create Benchmark
// ============================================================================

describe('Benchmark: Handshake Create Latency', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it(`measures handshake create over ${ITERATIONS} iterations`, async () => {
    const timings = [];

    for (let i = 0; i < ITERATIONS; i++) {
      // Fresh sim per iteration to prevent table accumulation
      sim = createTableSim();
      mockGetServiceClient.mockReturnValue(sim.mockClient());

      const start = performance.now();
      await initiateHandshake(validHandshakeParams());
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('Handshake Create', stats);

    // SLO assertions (code-path overhead, not end-to-end)
    expect(stats.p50).toBeLessThan(SLO.handshake_create.p50);
    expect(stats.p95).toBeLessThan(SLO.handshake_create.p95);
    expect(stats.p99).toBeLessThan(SLO.handshake_create.p99);
  }, 120_000);
});

// ============================================================================
// 2. Handshake Verify Benchmark
// ============================================================================

describe('Benchmark: Handshake Verify Latency', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it(`measures handshake verify over ${ITERATIONS} iterations`, async () => {
    const timings = [];

    for (let i = 0; i < ITERATIONS; i++) {
      // Create a fresh handshake to verify each iteration
      sim = createTableSim();
      mockGetServiceClient.mockReturnValue(sim.mockClient());

      const created = await initiateHandshake(validHandshakeParams());

      // Add a presentation so the verify path exercises the full pipeline
      const presRecord = {
        handshake_id: created.handshake_id,
        party_role: 'initiator',
        type: 'vc',
        data: JSON.stringify({ entity_id: 'entity-alice', display_name: 'Alice' }),
        issuer_ref: 'issuer-trusted-ca',
        disclosure_mode: 'full',
        verified: true,
        normalized_claims: { entity_id: 'entity-alice' },
      };
      sim.getTable('handshake_presentations').push(presRecord);

      const start = performance.now();
      await verifyHandshake(created.handshake_id);
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('Handshake Verify', stats);

    expect(stats.p50).toBeLessThan(SLO.handshake_verify.p50);
    expect(stats.p95).toBeLessThan(SLO.handshake_verify.p95);
    expect(stats.p99).toBeLessThan(SLO.handshake_verify.p99);
  }, 120_000);
});

// ============================================================================
// 3. Consume Benchmark
// ============================================================================

describe('Benchmark: Consume Latency', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it(`measures consume over ${ITERATIONS} iterations`, async () => {
    const timings = [];

    for (let i = 0; i < ITERATIONS; i++) {
      sim = createTableSim();
      mockGetServiceClient.mockReturnValue(sim.mockClient());

      // Set up a verified handshake directly in the sim tables
      const hsId = 'eph_bench_consume_' + i;
      sim.getTable('handshakes').push({
        handshake_id: hsId,
        status: 'verified',
        mode: 'basic',
        policy_id: 'policy-abc-123',
      });
      sim.getTable('handshake_bindings').push({
        handshake_id: hsId,
        binding_hash: 'bench_hash_' + i,
        consumed_at: null,
      });

      const start = performance.now();
      await consumeHandshake({
        handshake_id: hsId,
        binding_hash: 'bench_hash_' + i,
        consumed_by_type: 'commit_issue',
        consumed_by_id: 'epc_bench_' + i,
        actor: 'entity-alice',
      });
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('Consume', stats);

    expect(stats.p50).toBeLessThan(SLO.consume.p50);
    expect(stats.p95).toBeLessThan(SLO.consume.p95);
    expect(stats.p99).toBeLessThan(SLO.consume.p99);
  }, 120_000);
});

// ============================================================================
// 4. Binding Hash Computation Benchmark
// ============================================================================

describe('Benchmark: Binding Hash Computation', () => {
  it(`measures SHA-256 binding hash over ${ITERATIONS} iterations`, () => {
    const timings = [];

    const material = buildBindingMaterial({
      action_type: 'connect',
      resource_ref: 'service-xyz',
      policy_id: 'policy-abc-123',
      policy_version: '1.0.0',
      policy_hash: crypto.createHash('sha256').update('test-policy').digest('hex'),
      interaction_id: 'interaction-001',
      party_set_hash: computePartySetHash([
        { role: 'initiator', entity_ref: 'entity-alice' },
        { role: 'responder', entity_ref: 'entity-bob' },
      ]),
      payload_hash: computePayloadHash({ action: 'connect', target: 'service-xyz' }),
      context_hash: computeContextHash({
        action_type: 'connect',
        resource_ref: 'service-xyz',
        intent_ref: null,
        policy_id: 'policy-abc-123',
        policy_version: '1.0.0',
        interaction_id: 'interaction-001',
      }),
      nonce: crypto.randomBytes(32).toString('hex'),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    });

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      hashBinding(material);
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('Binding Hash (SHA-256)', stats);

    // Binding hash should be sub-millisecond: p99 < 2ms
    expect(stats.p99).toBeLessThan(2);
  });
});

// ============================================================================
// 5. Policy Evaluation Benchmark
// ============================================================================

describe('Benchmark: Policy Evaluation', () => {
  it(`measures trust profile + policy evaluation over ${ITERATIONS} iterations`, () => {
    const timings = [];

    // Pre-build a realistic receipt set (20 receipts from 5 submitters)
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `submitter-${i % 5}`,
      submitter_established: true,
      submitter_score: 85 + (i % 10),
      delivery_accuracy: 88 + (i % 8),
      product_accuracy: 85 + (i % 10),
      price_integrity: 90 + (i % 5),
      agent_behavior: 'completed',
    }));

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const profile = computeTrustProfile(receipts, {});
      evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('Policy Evaluation (profile + gate)', stats);

    // Policy evaluation is pure computation — p99 < 5ms
    expect(stats.p99).toBeLessThan(5);
  });
});

// ============================================================================
// 6. Component Hash Benchmarks
// ============================================================================

describe('Benchmark: Component Hash Functions', () => {
  it(`measures computePartySetHash over ${ITERATIONS} iterations`, () => {
    const timings = [];
    const parties = [
      { role: 'initiator', entity_ref: 'entity-alice' },
      { role: 'responder', entity_ref: 'entity-bob' },
      { role: 'verifier', entity_ref: 'entity-carol' },
    ];

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      computePartySetHash(parties);
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('computePartySetHash', stats);
    expect(stats.p99).toBeLessThan(1);
  });

  it(`measures computePayloadHash over ${ITERATIONS} iterations`, () => {
    const timings = [];
    const payload = {
      action: 'connect',
      target: 'service-xyz',
      metadata: { region: 'us-east-1', version: '2.1.0' },
    };

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      computePayloadHash(payload);
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('computePayloadHash', stats);
    expect(stats.p99).toBeLessThan(1);
  });

  it(`measures computePolicyHash over ${ITERATIONS} iterations`, () => {
    const timings = [];
    const rules = {
      required_parties: {
        initiator: { required_claims: ['entity_id'], minimum_assurance: 'substantial' },
        responder: { required_claims: ['entity_id'], minimum_assurance: 'medium' },
      },
      binding: { payload_hash_required: true, nonce_required: true, expiry_minutes: 10 },
      storage: { store_raw_payload: false, store_normalized_claims: true },
    };

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      computePolicyHash(rules);
      const elapsed = performance.now() - start;
      timings.push(elapsed);
    }

    const stats = computePercentiles(timings);
    reportResults('computePolicyHash', stats);
    expect(stats.p99).toBeLessThan(1);
  });
});

// ============================================================================
// 7. Summary Report
// ============================================================================

describe('Benchmark: Summary', () => {
  it('documents benchmark configuration', () => {
    console.log('\n========================================');
    console.log('EP Benchmark Configuration');
    console.log('========================================');
    console.log(`Iterations per test: ${ITERATIONS}`);
    console.log(`Percentiles: p50, p95, p99`);
    console.log(`SLO (Handshake Create): p50<${SLO.handshake_create.p50}ms p95<${SLO.handshake_create.p95}ms p99<${SLO.handshake_create.p99}ms`);
    console.log(`SLO (Handshake Verify): p50<${SLO.handshake_verify.p50}ms p95<${SLO.handshake_verify.p95}ms p99<${SLO.handshake_verify.p99}ms`);
    console.log(`SLO (Consume):          p50<${SLO.consume.p50}ms p95<${SLO.consume.p95}ms p99<${SLO.consume.p99}ms`);
    console.log('NOTE: Mock-based. Measures code-path overhead, NOT DB latency.');
    console.log('========================================\n');

    // Verify the SLO constants are internally coherent (p50 < p95 < p99)
    for (const [label, thresholds] of Object.entries(SLO)) {
      expect(thresholds.p50).toBeLessThan(thresholds.p95);
      expect(thresholds.p95).toBeLessThan(thresholds.p99);
    }
  });
});
