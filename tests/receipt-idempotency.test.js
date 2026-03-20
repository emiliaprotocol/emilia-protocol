/**
 * Tests for system-level receipt idempotency (migration 034).
 *
 * Covers:
 *  1. Same idempotency_key returns existing receipt (dedup hit)
 *  2. Different idempotency_key creates new receipt
 *  3. Missing idempotency_key is generated deterministically for machine-originated writes
 *  4. Race condition (DB unique violation) returns existing receipt, not error
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Mock infrastructure — intercept Supabase, scoring, sybil, signatures, env
// ---------------------------------------------------------------------------

/** Track all .from() / .select() / .eq() / .insert() calls for assertion. */
let _queryLog = [];

/** Map of table+filter → result to return from mock supabase queries. */
let _mockResults = {};

/** If set, the next insert will fail with this error. */
let _nextInsertError = null;

/** The receipt returned after a successful insert. */
let _insertedReceipt = null;

function resetMocks() {
  _queryLog = [];
  _mockResults = {};
  _nextInsertError = null;
  _insertedReceipt = null;
}

// Build a chainable mock that records calls and returns configured results.
function buildChain(table) {
  const state = { table, filters: {}, method: null };

  const chain = {
    select: (cols, opts) => { state.method = 'select'; state.cols = cols; return chain; },
    eq: (col, val) => { state.filters[col] = val; return chain; },
    gte: (col, val) => { state.filters[`${col}_gte`] = val; return chain; },
    order: () => chain,
    limit: () => chain,
    in: () => chain,
    single: () => {
      _queryLog.push({ ...state, op: 'single' });
      // Check for configured results
      const key = `${state.table}:${JSON.stringify(state.filters)}`;
      if (_mockResults[key] !== undefined) {
        return Promise.resolve({ data: _mockResults[key], error: null });
      }
      return Promise.resolve({ data: null, error: null });
    },
    insert: (row) => {
      _queryLog.push({ ...state, op: 'insert', row });
      _insertedReceipt = {
        ...row,
        created_at: new Date().toISOString(),
      };
      if (_nextInsertError) {
        const err = _nextInsertError;
        _nextInsertError = null;
        return {
          select: () => ({
            single: () => Promise.resolve({ data: null, error: err }),
          }),
        };
      }
      return {
        select: () => ({
          single: () => Promise.resolve({ data: _insertedReceipt, error: null }),
        }),
      };
    },
  };
  return chain;
}

const mockSupabaseClient = {
  from: (table) => buildChain(table),
  rpc: vi.fn(() => Promise.resolve({ data: [{ established: false }], error: null })),
};

vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(() => mockSupabaseClient),
}));

vi.mock('@/lib/scoring', () => ({
  computeReceiptComposite: vi.fn(() => 75),
  computeReceiptHash: vi.fn(async () => 'mock_hash_' + crypto.randomBytes(4).toString('hex')),
  behaviorToSatisfaction: vi.fn(() => 0.8),
  computeScoresFromClaims: vi.fn(() => ({ delivery_accuracy: 1.0 })),
}));

vi.mock('@/lib/sybil', () => ({
  runReceiptFraudChecks: vi.fn(async () => ({ allowed: true, flags: [], graphWeight: 1.0 })),
}));

vi.mock('@/lib/signatures', () => ({
  resolveProvenanceTier: vi.fn(() => ({ tier: 'self_attested', warning: null })),
}));

vi.mock('@/lib/env', () => ({
  getUpstashConfig: vi.fn(() => null), // no Redis — use in-memory locks
}));

// Import after mocks
import { createReceipt } from '../lib/create-receipt.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TARGET_ENTITY_ID = 'aaaaaaaa-1111-2222-3333-444444444444';
const SUBMITTER_ID = 'bbbbbbbb-1111-2222-3333-444444444444';

function makeParams(overrides = {}) {
  return {
    targetEntitySlug: 'test-entity',
    submitter: { id: SUBMITTER_ID, entity_id: 'submitter-slug', emilia_score: 60 },
    transactionRef: `tx_${crypto.randomBytes(4).toString('hex')}`,
    transactionType: 'purchase',
    claims: { delivered: true },
    evidence: {},
    ...overrides,
  };
}

/** Register a mock result so that when the mock chain matches table + filters, it returns data. */
function whenQuery(table, filters, data) {
  const key = `${table}:${JSON.stringify(filters)}`;
  _mockResults[key] = data;
}

/** Compute the deterministic idempotency key that createReceipt would generate. */
function deterministicKey(submitterId, txRef, txType) {
  return `ep_idem_${crypto.createHash('sha256').update(`${submitterId}:${txRef}:${txType}`).digest('hex')}`;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  resetMocks();
  vi.clearAllMocks();

  // Default: entity lookup succeeds
  whenQuery('entities', { entity_id: 'test-entity' }, { id: TARGET_ENTITY_ID, entity_id: 'test-entity' });
  // Default: updated entity score
  whenQuery('entities', { id: TARGET_ENTITY_ID }, { emilia_score: 55, total_receipts: 10 });
});

// ============================================================================
// 1. Same idempotency_key returns existing receipt
// ============================================================================

describe('Idempotency key deduplication', () => {
  it('returns existing receipt when idempotency_key already exists', async () => {
    const idemKey = 'ep_idem_user_provided_key_123';
    const existingReceipt = {
      receipt_id: 'ep_rcpt_existing',
      receipt_hash: 'hash_existing',
      created_at: '2025-01-01T00:00:00.000Z',
    };

    // Configure: idempotency_key lookup returns a hit
    whenQuery('receipts', { idempotency_key: idemKey }, existingReceipt);

    const params = makeParams({ idempotencyKey: idemKey });
    const result = await createReceipt(params);

    expect(result.deduplicated).toBe(true);
    expect(result.receipt.receipt_id).toBe('ep_rcpt_existing');
    expect(result._message).toContain('idempotency_key');
  });
});

// ============================================================================
// 2. Different idempotency_key creates new receipt
// ============================================================================

describe('Different idempotency_key creates new receipt', () => {
  it('creates a new receipt when idempotency_key is unique', async () => {
    const params = makeParams({ idempotencyKey: 'ep_idem_brand_new_key' });
    const result = await createReceipt(params);

    expect(result.deduplicated).toBeUndefined();
    expect(result.receipt).toBeDefined();
    expect(result.receipt.receipt_id).toMatch(/^ep_rcpt_/);
    expect(result.receipt.idempotency_key).toBe('ep_idem_brand_new_key');
  });

  it('two calls with different keys produce different receipts', async () => {
    const params1 = makeParams({ idempotencyKey: 'ep_idem_key_A' });
    const params2 = makeParams({ idempotencyKey: 'ep_idem_key_B' });

    const r1 = await createReceipt(params1);
    const r2 = await createReceipt(params2);

    expect(r1.receipt.receipt_id).not.toBe(r2.receipt.receipt_id);
  });
});

// ============================================================================
// 3. Missing idempotency_key is generated deterministically
// ============================================================================

describe('Deterministic idempotency_key generation', () => {
  it('generates idempotency_key from submitter + transactionRef + transactionType when not provided', async () => {
    const txRef = 'tx_deterministic_test';
    const txType = 'service';
    const params = makeParams({
      transactionRef: txRef,
      transactionType: txType,
      // No idempotencyKey provided
    });

    const result = await createReceipt(params);

    const expectedKey = deterministicKey(SUBMITTER_ID, txRef, txType);
    expect(result.receipt.idempotency_key).toBe(expectedKey);
  });

  it('same inputs produce same deterministic key (reproducible)', () => {
    const k1 = deterministicKey(SUBMITTER_ID, 'tx_abc', 'purchase');
    const k2 = deterministicKey(SUBMITTER_ID, 'tx_abc', 'purchase');
    expect(k1).toBe(k2);
  });

  it('different inputs produce different deterministic keys', () => {
    const k1 = deterministicKey(SUBMITTER_ID, 'tx_abc', 'purchase');
    const k2 = deterministicKey(SUBMITTER_ID, 'tx_abc', 'service');
    expect(k1).not.toBe(k2);
  });

  it('deterministic key starts with ep_idem_ prefix', async () => {
    const params = makeParams({ transactionRef: 'tx_prefix_test', transactionType: 'delivery' });
    const result = await createReceipt(params);
    expect(result.receipt.idempotency_key).toMatch(/^ep_idem_[a-f0-9]{64}$/);
  });
});

// ============================================================================
// 4. Race condition (DB unique violation) returns existing receipt, not error
// ============================================================================

describe('Race condition handling (DB unique constraint violation)', () => {
  it('returns existing receipt on 23505 unique violation instead of error', async () => {
    const idemKey = 'ep_idem_race_condition_key';
    const racedReceipt = {
      receipt_id: 'ep_rcpt_raced',
      receipt_hash: 'hash_raced',
      created_at: '2025-01-01T12:00:00.000Z',
    };

    // The insert will fail with a unique constraint violation
    _nextInsertError = { code: '23505', message: 'duplicate key value violates unique constraint' };

    // The follow-up lookup by idempotency_key finds the raced receipt
    whenQuery('receipts', { idempotency_key: idemKey }, racedReceipt);

    const params = makeParams({ idempotencyKey: idemKey });
    const result = await createReceipt(params);

    expect(result.deduplicated).toBe(true);
    expect(result.receipt.receipt_id).toBe('ep_rcpt_raced');
    expect(result.error).toBeUndefined();
  });

  it('returns existing receipt on "duplicate key" message even without code 23505', async () => {
    const idemKey = 'ep_idem_race_condition_msg';
    const racedReceipt = {
      receipt_id: 'ep_rcpt_raced_msg',
      receipt_hash: 'hash_raced_msg',
      created_at: '2025-01-02T00:00:00.000Z',
    };

    _nextInsertError = { message: 'duplicate key value violates unique constraint on idx_receipts_idempotency_key' };

    whenQuery('receipts', { idempotency_key: idemKey }, racedReceipt);

    const params = makeParams({ idempotencyKey: idemKey });
    const result = await createReceipt(params);

    expect(result.deduplicated).toBe(true);
    expect(result.receipt.receipt_id).toBe('ep_rcpt_raced_msg');
  });

  it('real insert errors (non-unique) still return 500', async () => {
    _nextInsertError = { code: '42P01', message: 'relation "receipts" does not exist' };

    const params = makeParams({ idempotencyKey: 'ep_idem_real_error' });
    const result = await createReceipt(params);

    expect(result.error).toBe('Failed to submit receipt');
    expect(result.status).toBe(500);
  });
});

// ============================================================================
// 5. idempotency_key is included in the insert payload
// ============================================================================

describe('idempotency_key in insert payload', () => {
  it('caller-supplied idempotency_key is passed to the DB insert', async () => {
    const idemKey = 'ep_idem_explicit_key_xyz';
    const params = makeParams({ idempotencyKey: idemKey });
    await createReceipt(params);

    const insertCall = _queryLog.find(q => q.op === 'insert');
    expect(insertCall).toBeDefined();
    expect(insertCall.row.idempotency_key).toBe(idemKey);
  });

  it('auto-generated idempotency_key is passed to the DB insert when none provided', async () => {
    const txRef = 'tx_auto_idem';
    const txType = 'purchase';
    const params = makeParams({ transactionRef: txRef, transactionType: txType });
    await createReceipt(params);

    const insertCall = _queryLog.find(q => q.op === 'insert');
    expect(insertCall).toBeDefined();
    expect(insertCall.row.idempotency_key).toBe(deterministicKey(SUBMITTER_ID, txRef, txType));
  });
});
