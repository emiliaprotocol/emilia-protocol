/**
 * create-receipt-extended.test.js
 *
 * Extended coverage for lib/create-receipt.js targeting uncovered lines:
 *   lines 469-483: unique constraint violation (race condition) → dedup fallback
 *   line 518:      provenanceWarning merged into result.warnings
 *   line 521:      result.warnings only set when warnings exist
 *
 * Also covers previously-untested branches:
 *   - self-score check (submitter == target)
 *   - entity not found path
 *   - fraudCheck.allowed === false
 *   - no meaningful signals
 *   - requestBilateral=true (bilateral_status set)
 *   - happy-path result shape
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// =============================================================================
// Module-level mocks (must be hoisted before any import of the module under test)
// =============================================================================

vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(),
}));

vi.mock('@/lib/sybil', () => ({
  runReceiptFraudChecks: vi.fn(),
}));

vi.mock('@/lib/signatures', () => ({
  resolveProvenanceTier: vi.fn(),
}));

// getUpstashConfig is called at module-load time — return null so Redis is disabled
vi.mock('@/lib/env', () => ({
  getUpstashConfig: vi.fn(() => null),
}));

vi.mock('@/lib/scoring', () => ({
  computeReceiptComposite: vi.fn(() => 85),
  computeReceiptHash: vi.fn(async () => 'deadbeef'.repeat(8)),
  behaviorToSatisfaction: vi.fn((b) => ({ completed: 95, abandoned: 15 }[b] ?? null)),
  computeScoresFromClaims: vi.fn(() => ({})),
}));

import { createReceipt } from '../lib/create-receipt.js';
import { getServiceClient } from '@/lib/supabase';
import { runReceiptFraudChecks } from '@/lib/sybil';
import { resolveProvenanceTier } from '@/lib/signatures';

const mockGetServiceClient = getServiceClient;
const mockRunReceiptFraudChecks = runReceiptFraudChecks;
const mockResolveProvenanceTier = resolveProvenanceTier;

// =============================================================================
// Helpers
// =============================================================================

function makeChain(resolveValue = { data: null, error: null }) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

/**
 * Build a mock Supabase client whose table handlers can be customized per test.
 *
 * @param {Object} handlers  key = table name, value = function(table) => chain
 */
function makeSupabase(handlers = {}) {
  return {
    from: vi.fn((table) => {
      if (handlers[table]) return handlers[table](table);
      return makeChain({ data: null, error: null });
    }),
    rpc: vi.fn().mockResolvedValue({ data: [{ established: false }], error: null }),
  };
}

const SUBMITTER = { id: 'submitter-uuid', emilia_score: 80 };
const TARGET_ENTITY = { id: 'target-uuid', entity_id: 'target-slug' };

function defaultHandlers(overrides = {}) {
  return {
    entities: () => makeChain({ data: TARGET_ENTITY, error: null }),
    receipts: () => makeChain({ data: null, error: null }),
    ...overrides,
  };
}

function defaultParams(overrides = {}) {
  return {
    targetEntitySlug: 'target-slug',
    submitter: SUBMITTER,
    transactionRef: 'tx-001',
    transactionType: 'purchase',
    signals: { delivery_accuracy: 90 },
    ...overrides,
  };
}

// =============================================================================
// Setup
// =============================================================================

beforeEach(() => {
  vi.clearAllMocks();
  mockRunReceiptFraudChecks.mockResolvedValue({ allowed: true, flags: [], graphWeight: 1.0 });
  mockResolveProvenanceTier.mockReturnValue({ tier: 'self_attested', warning: null });
});

// =============================================================================
// Entity not found
// =============================================================================

describe('createReceipt — entity not found', () => {
  it('returns 404 when target entity does not exist', async () => {
    const db = makeSupabase({
      entities: () => makeChain({ data: null, error: null }),
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams());
    expect(result.error).toMatch(/not found/i);
    expect(result.status).toBe(404);
  });
});

// =============================================================================
// Self-score prevention
// =============================================================================

describe('createReceipt — self-score prevention', () => {
  it('returns 403 when submitter and target are the same entity', async () => {
    const db = makeSupabase({
      entities: () => makeChain({ data: { id: SUBMITTER.id, entity_id: 'same-entity' }, error: null }),
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ submitter: { id: SUBMITTER.id } }));
    expect(result.error).toMatch(/cannot submit/i);
    expect(result.status).toBe(403);
  });
});

// =============================================================================
// Fraud check blocks
// =============================================================================

describe('createReceipt — fraud check blocking', () => {
  it('returns 429 when fraud checks fail', async () => {
    mockRunReceiptFraudChecks.mockResolvedValue({
      allowed: false,
      detail: 'Sybil detected',
      flags: ['sybil_ring'],
    });

    const db = makeSupabase(defaultHandlers());
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams());
    expect(result.error).toMatch(/Sybil/);
    expect(result.status).toBe(429);
    expect(result.flags).toContain('sybil_ring');
  });
});

// =============================================================================
// No meaningful signals
// =============================================================================

describe('createReceipt — no meaningful signals', () => {
  it('returns 400 when no signals and no claims produce values', async () => {
    const db = makeSupabase(defaultHandlers());
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({
      signals: {}, // no signals
      agentBehavior: undefined,
      claims: undefined,
    }));
    expect(result.error).toMatch(/no meaningful signals/i);
    expect(result.status).toBe(400);
  });
});

// =============================================================================
// Idempotency key dedup hit
// =============================================================================

describe('createReceipt — idempotency key dedup', () => {
  it('returns existing receipt when idempotency_key already exists', async () => {
    const existingReceipt = { receipt_id: 'ep_rcpt_existing', receipt_hash: 'abc', created_at: '2025-01-01' };

    // idempotencyKey lookup returns a hit
    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn()
        .mockResolvedValueOnce({ data: existingReceipt, error: null }) // idempotencyKey check
        .mockResolvedValue({ data: null, error: null }),
    };

    const db = makeSupabase({
      entities: () => makeChain({ data: TARGET_ENTITY, error: null }),
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ idempotencyKey: 'my-idem-key' }));
    expect(result.deduplicated).toBe(true);
    expect(result.receipt.receipt_id).toBe('ep_rcpt_existing');
  });
});

// =============================================================================
// Unique constraint race condition (lines 469-483)
// =============================================================================

describe('createReceipt — unique constraint race condition dedup', () => {
  it('returns deduplicated receipt on unique constraint violation (line 469-483)', async () => {
    const racedReceipt = { receipt_id: 'ep_rcpt_raced', receipt_hash: 'xyz', created_at: '2025-01-02' };

    let insertCalled = false;
    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn()
        .mockResolvedValueOnce({ data: null, error: null }) // idempotencyKey check: miss
        .mockResolvedValueOnce({ data: null, error: null }) // transaction_ref check: miss
        .mockResolvedValueOnce({ data: null, error: null }) // prevReceipt chain link
        .mockResolvedValueOnce({ data: racedReceipt, error: null }) // racedByKey lookup
        .mockResolvedValue({ data: null, error: null }),
      insert: vi.fn().mockImplementation(() => {
        if (!insertCalled) {
          insertCalled = true;
          return {
            select: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({
              data: null,
              error: { code: '23505', message: 'duplicate key value' },
            }),
          };
        }
        return {
          select: vi.fn().mockReturnThis(),
          single: vi.fn().mockResolvedValue({ data: null, error: null }),
        };
      }),
    };

    const db = makeSupabase({
      entities: () => makeChain({ data: TARGET_ENTITY, error: null }),
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams());
    expect(result.deduplicated).toBe(true);
    expect(result._message).toMatch(/unique constraint/i);
  });

  it('falls back to entity+submitter+ref lookup when idempotency_key race lookup returns null', async () => {
    const racedReceiptByRef = { receipt_id: 'ep_rcpt_by_ref', receipt_hash: 'abc123', created_at: '2025-01-03' };

    let singleCallCount = 0;
    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount === 1) return Promise.resolve({ data: null, error: null }); // idem key miss
        if (singleCallCount === 2) return Promise.resolve({ data: null, error: null }); // tx_ref miss
        if (singleCallCount === 3) return Promise.resolve({ data: null, error: null }); // prevReceipt
        if (singleCallCount === 4) return Promise.resolve({ data: null, error: null }); // racedByKey → null
        if (singleCallCount === 5) return Promise.resolve({ data: racedReceiptByRef, error: null }); // legacy fallback
        return Promise.resolve({ data: null, error: null });
      }),
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({
          data: null,
          error: { code: '23505', message: 'duplicate key' },
        }),
      }),
    };

    const db = makeSupabase({
      entities: () => makeChain({ data: TARGET_ENTITY, error: null }),
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams());
    expect(result.deduplicated).toBe(true);
  });
});

// =============================================================================
// provenance warning merged into warnings (line 518-521)
// =============================================================================

describe('createReceipt — provenanceWarning and warnings array', () => {
  function buildHappyPathDb(insertedReceipt) {
    let singleCallCount = 0;
    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount <= 2) return Promise.resolve({ data: null, error: null }); // dedup misses
        if (singleCallCount === 3) return Promise.resolve({ data: null, error: null }); // prevReceipt
        // insert -> single
        return Promise.resolve({ data: insertedReceipt, error: null });
      }),
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: insertedReceipt, error: null }),
      }),
    };

    const db = makeSupabase({
      entities: (t) => {
        // First call: resolve target entity; second call: return updated entity
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          single: vi.fn()
            .mockResolvedValueOnce({ data: TARGET_ENTITY, error: null })
            .mockResolvedValue({ data: { emilia_score: 88, total_receipts: 15 }, error: null }),
        };
      },
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    return db;
  }

  it('includes provenanceWarning in result.warnings when present (line 518)', async () => {
    mockResolveProvenanceTier.mockReturnValue({
      tier: 'self_attested',
      warning: 'Provenance downgraded: missing signature',
    });

    const insertedReceipt = {
      receipt_id: 'ep_rcpt_abc',
      idempotency_key: 'idem-001',
      entity_id: TARGET_ENTITY.id,
      composite_score: 85,
      receipt_hash: 'abc123',
      created_at: '2025-01-01T00:00:00Z',
    };

    const db = buildHappyPathDb(insertedReceipt);
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ signals: { delivery_accuracy: 90 } }));
    expect(result.warnings).toContain('Provenance downgraded: missing signature');
  });

  it('does not include warnings key when no warnings or flags (line 521)', async () => {
    mockResolveProvenanceTier.mockReturnValue({ tier: 'self_attested', warning: null });
    mockRunReceiptFraudChecks.mockResolvedValue({ allowed: true, flags: [], graphWeight: 1.0 });

    const insertedReceipt = {
      receipt_id: 'ep_rcpt_clean',
      idempotency_key: 'idem-002',
      entity_id: TARGET_ENTITY.id,
      composite_score: 85,
      receipt_hash: 'def456',
      created_at: '2025-01-01T00:00:00Z',
    };

    const db = buildHappyPathDb(insertedReceipt);
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ signals: { delivery_accuracy: 90 } }));
    // warnings should not exist when there are none
    expect(result.warnings).toBeUndefined();
  });

  it('includes fraud flags in warnings when present', async () => {
    mockResolveProvenanceTier.mockReturnValue({ tier: 'self_attested', warning: null });
    mockRunReceiptFraudChecks.mockResolvedValue({
      allowed: true,
      flags: ['graph_loop_detected'],
      graphWeight: 0.3,
    });

    const insertedReceipt = {
      receipt_id: 'ep_rcpt_flagged',
      idempotency_key: 'idem-003',
      entity_id: TARGET_ENTITY.id,
      composite_score: 60,
      receipt_hash: 'fff000',
      created_at: '2025-01-01T00:00:00Z',
    };

    const db = buildHappyPathDb(insertedReceipt);
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ signals: { delivery_accuracy: 90 } }));
    expect(result.warnings).toContain('graph_loop_detected');
  });
});

// =============================================================================
// Insert fails with a non-unique error → 500
// =============================================================================

describe('createReceipt — generic insert error returns 500', () => {
  it('returns 500 on a non-unique insert error', async () => {
    let singleCallCount = 0;
    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockImplementation(() => {
        singleCallCount++;
        return Promise.resolve({ data: null, error: null });
      }),
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({
          data: null,
          error: { code: '50000', message: 'unexpected server error' },
        }),
      }),
    };

    const db = makeSupabase({
      entities: () => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: TARGET_ENTITY, error: null }),
      }),
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ signals: { delivery_accuracy: 90 } }));
    expect(result.status).toBe(500);
    expect(result.error).toMatch(/Failed to submit/i);
  });
});

// =============================================================================
// agentBehavior signal path
// =============================================================================

describe('createReceipt — agentBehavior satisfaction scoring', () => {
  it('uses behaviorToSatisfaction for agent_satisfaction when agentBehavior is set', async () => {
    let singleCallCount = 0;
    const insertedReceipt = {
      receipt_id: 'ep_rcpt_beh',
      idempotency_key: 'idem-beh',
      entity_id: TARGET_ENTITY.id,
      composite_score: 85,
      receipt_hash: 'beh123',
      created_at: '2025-01-01T00:00:00Z',
    };

    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount <= 2) return Promise.resolve({ data: null, error: null });
        if (singleCallCount === 3) return Promise.resolve({ data: null, error: null });
        return Promise.resolve({ data: insertedReceipt, error: null });
      }),
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: insertedReceipt, error: null }),
      }),
    };

    const db = makeSupabase({
      entities: () => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn()
          .mockResolvedValueOnce({ data: TARGET_ENTITY, error: null })
          .mockResolvedValue({ data: { emilia_score: 88, total_receipts: 15 }, error: null }),
      }),
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    // Should not return 400 — agentBehavior provides a signal
    const result = await createReceipt(defaultParams({
      signals: {},
      agentBehavior: 'completed',
    }));
    expect(result.error).toBeUndefined();
    expect(result.receipt).toBeDefined();
  });
});

// =============================================================================
// Transaction ref dedup (lines 314-315)
// =============================================================================

describe('createReceipt — transaction_ref dedup', () => {
  it('returns existing receipt when same transaction_ref already exists — lines 314-315', async () => {
    const existingReceipt = { receipt_id: 'ep_rcpt_txref', receipt_hash: 'abc', created_at: '2025-01-01' };

    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn()
        .mockResolvedValueOnce({ data: null, error: null }) // idempotency_key check: miss
        .mockResolvedValueOnce({ data: existingReceipt, error: null }), // transaction_ref check: hit
    };

    const db = makeSupabase({
      entities: () => makeChain({ data: TARGET_ENTITY, error: null }),
      receipts: () => receiptsChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams());
    expect(result.deduplicated).toBe(true);
    expect(result.receipt.receipt_id).toBe('ep_rcpt_txref');
    expect(result._message).toMatch(/transaction_ref/);
  });
});

// =============================================================================
// rpc throws — submitterEstablished fallback (line 345)
// =============================================================================

describe('createReceipt — rpc throws fallback', () => {
  it('continues with submitterEstablished=false when rpc throws — line 345', async () => {
    const insertedReceipt = {
      receipt_id: 'ep_rcpt_rpc_err',
      idempotency_key: 'idem-rpc',
      entity_id: TARGET_ENTITY.id,
      composite_score: 85,
      receipt_hash: 'rpc123',
      created_at: '2025-01-01T00:00:00Z',
    };

    let singleCallCount = 0;
    const receiptsChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount <= 2) return Promise.resolve({ data: null, error: null });
        if (singleCallCount === 3) return Promise.resolve({ data: null, error: null });
        return Promise.resolve({ data: insertedReceipt, error: null });
      }),
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: insertedReceipt, error: null }),
      }),
    };

    const db = makeSupabase({
      entities: () => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn()
          .mockResolvedValueOnce({ data: TARGET_ENTITY, error: null })
          .mockResolvedValue({ data: { emilia_score: 88, total_receipts: 15 }, error: null }),
      }),
      receipts: () => receiptsChain,
    });
    // Make rpc throw to exercise the catch block at line 345
    db.rpc = vi.fn().mockRejectedValue(new Error('function not found'));
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams({ signals: { delivery_accuracy: 90 } }));
    // Should still succeed (submitterEstablished defaults to false, not fatal)
    expect(result.error).toBeUndefined();
    expect(result.receipt).toBeDefined();
  });
});

// =============================================================================
// Daily quota exceeded — DB count path (lines 179 and 261)
// =============================================================================

describe('createReceipt — daily quota exceeded', () => {
  it('returns 429 when DB count shows entity has hit daily limit — lines 179 and 261', async () => {
    // The quota check queries receipts with count. Return count >= 500 to trigger exceeded path.
    const quotaChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      gte: vi.fn().mockResolvedValue({ count: 500, data: null, error: null }),
    };

    const db = makeSupabase({
      entities: () => makeChain({ data: TARGET_ENTITY, error: null }),
      receipts: () => quotaChain,
    });
    db.rpc = vi.fn().mockResolvedValue({ data: [{ established: false }] });
    mockGetServiceClient.mockReturnValue(db);

    const result = await createReceipt(defaultParams());
    expect(result.status).toBe(429);
    expect(result.error).toMatch(/Daily receipt limit/i);
  });
});
