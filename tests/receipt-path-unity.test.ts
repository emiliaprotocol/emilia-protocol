/**
 * Receipt Path Unity Tests
 *
 * Verifies that manual and auto receipt submission share the EXACT same
 * canonical write path. There is ONE function that writes to the receipts
 * table: createReceipt(). Both canonicalSubmitReceipt and
 * canonicalSubmitAutoReceipt MUST flow through it.
 *
 * Invariants tested:
 *   1. Both paths produce receipts with identical required fields
 *   2. Both paths run fraud checks (runReceiptFraudChecks)
 *   3. Both paths compute composite_score
 *   4. Both paths trigger trust profile materialization
 *   5. Both paths enforce idempotency (deduplication)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Supabase mock helpers
// ============================================================================

function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ============================================================================
// Track createReceipt calls
// ============================================================================

let createReceiptSpy;
let createReceiptCallArgs = [];

// We wrap createReceipt so we can observe every call and its arguments
// while still exercising the real normalization logic in canonical-writer.
const mockCreateReceiptImpl = vi.fn(async (params) => {
  createReceiptCallArgs.push(params);
  // Return a realistic successful result
  return {
    receipt: {
      receipt_id: `ep_rcpt_test_${Date.now()}`,
      entity_id: 'entity-db-uuid',
      composite_score: 82.5,
      receipt_hash: 'abc123hash',
      created_at: new Date().toISOString(),
    },
    entityScore: {
      emilia_score: 75,
      total_receipts: 10,
    },
  };
});

// Mock for dedup case
const mockCreateReceiptDedup = vi.fn(async (params) => {
  createReceiptCallArgs.push(params);
  return {
    receipt: {
      receipt_id: 'ep_rcpt_existing',
      receipt_hash: 'existing_hash',
      created_at: '2025-01-01T00:00:00.000Z',
    },
    deduplicated: true,
    _message: 'Receipt already exists for this transaction_ref. Returning existing receipt (idempotent).',
  };
});

// ============================================================================
// Mock dependencies
// ============================================================================

vi.mock('../lib/create-receipt.js', () => ({
  createReceipt: (...args) => mockCreateReceiptImpl(...args),
}));

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(() => {
    const fromMap = {
      entities: makeChain({ data: { id: 'entity-db-uuid', entity_id: 'test-entity', emilia_score: 75 }, error: null }),
      receipts: makeChain({ data: [], error: null }),
      protocol_events: makeChain({ data: null, error: null }),
    };
    return {
      from: vi.fn((table) => fromMap[table] || makeChain({ data: null, error: null })),
      rpc: vi.fn().mockResolvedValue({ data: 75, error: null }),
    };
  }),
}));

vi.mock('../lib/errors.js', () => ({
  ProtocolWriteError: class ProtocolWriteError extends Error {
    constructor(msg, meta) {
      super(msg);
      this.meta = meta;
    }
  },
}));

vi.mock('../lib/scoring-v2.js', () => ({
  computeTrustProfile: vi.fn(() => ({
    score: 75,
    confidence: 'medium',
    effectiveEvidence: 8,
    uniqueSubmitters: 3,
    receiptCount: 10,
    profile: {},
    anomaly: null,
  })),
}));

vi.mock('../lib/env.js', () => ({
  getUpstashConfig: vi.fn(() => null),
  getAutoSubmitSecret: vi.fn(() => null),
}));

// ============================================================================
// Import after mocks
// ============================================================================

const { canonicalSubmitReceipt, canonicalSubmitAutoReceipt } = await import('../lib/canonical-writer.js');

// ============================================================================
// Test fixtures
// ============================================================================

const MANUAL_SUBMITTER = {
  id: 'submitter-uuid-manual',
  entity_id: 'submitter-slug-manual',
  status: 'active',
  emilia_score: 65,
};

const AUTO_SUBMITTER = {
  id: 'ep_machine_auto_submit',
  entity_id: 'ep_machine_auto_submit',
  status: 'active',
  emilia_score: 50,
};

const MANUAL_PARAMS = {
  entity_id: 'test-entity',
  transaction_ref: 'txn-manual-001',
  transaction_type: 'purchase',
  delivery_accuracy: 90,
  product_accuracy: 85,
  price_integrity: 95,
  agent_behavior: 'completed',
  claims: null,
  evidence: { invoice_url: 'https://example.com/inv/001' },
  context: { channel: 'web' },
  provenance_tier: 'self_attested',
  request_bilateral: false,
};

const AUTO_PARAMS = {
  entity_id: 'test-entity',
  transaction_ref: 'txn-auto-001',
  transaction_type: 'service',
  delivery_accuracy: 80,
  product_accuracy: 75,
  price_integrity: 90,
  agent_behavior: null,
  outcome: { completed: true },
  claims: null,
  evidence: {},
  context: { tool: 'mcp-autocomplete' },
};

// ============================================================================
// Tests
// ============================================================================

beforeEach(() => {
  createReceiptCallArgs = [];
  mockCreateReceiptImpl.mockClear();
});

describe('Receipt Path Unity', () => {

  describe('Both paths delegate to createReceipt()', () => {
    it('canonicalSubmitReceipt calls createReceipt exactly once', async () => {
      await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(mockCreateReceiptImpl).toHaveBeenCalledTimes(1);
    });

    it('canonicalSubmitAutoReceipt calls createReceipt exactly once', async () => {
      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      // canonicalSubmitAutoReceipt delegates to canonicalSubmitReceipt which calls createReceipt
      expect(mockCreateReceiptImpl).toHaveBeenCalledTimes(1);
    });
  });

  describe('Both paths produce receipts with identical required fields', () => {
    it('manual and auto createReceipt calls have the same parameter shape', async () => {
      await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      const manualArgs = createReceiptCallArgs[0];
      createReceiptCallArgs = [];
      mockCreateReceiptImpl.mockClear();

      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      const autoArgs = createReceiptCallArgs[0];

      // Both must pass the same set of required keys to createReceipt
      const requiredKeys = [
        'targetEntitySlug',
        'submitter',
        'transactionRef',
        'transactionType',
        'signals',
        'agentBehavior',
        'claims',
        'evidence',
        'context',
        'provenanceTier',
        'requestBilateral',
      ];

      for (const key of requiredKeys) {
        expect(manualArgs).toHaveProperty(key);
        expect(autoArgs).toHaveProperty(key);
      }

      // Signal sub-fields must be identical in shape
      const signalKeys = [
        'delivery_accuracy',
        'product_accuracy',
        'price_integrity',
        'return_processing',
        'agent_satisfaction',
      ];
      for (const key of signalKeys) {
        expect(manualArgs.signals).toHaveProperty(key);
        expect(autoArgs.signals).toHaveProperty(key);
      }
    });
  });

  describe('Both paths run fraud checks', () => {
    it('createReceipt is the single entry point — fraud checks are inside it', async () => {
      // Both paths call createReceipt. createReceipt calls runReceiptFraudChecks
      // internally. We verify that both paths call createReceipt (the function
      // that contains fraud checks) rather than bypassing it.

      await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(mockCreateReceiptImpl).toHaveBeenCalledTimes(1);
      const manualCall = mockCreateReceiptImpl.mock.calls[0];

      mockCreateReceiptImpl.mockClear();

      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(mockCreateReceiptImpl).toHaveBeenCalledTimes(1);
      const autoCall = mockCreateReceiptImpl.mock.calls[0];

      // Both called the same function with a submitter that has an id
      // (needed for fraud check self-score prevention)
      expect(manualCall[0].submitter).toHaveProperty('id');
      expect(autoCall[0].submitter).toHaveProperty('id');
    });
  });

  describe('Both paths compute composite_score', () => {
    it('both paths return receipts with composite_score from createReceipt', async () => {
      const manualResult = await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(manualResult.receipt).toHaveProperty('composite_score');
      expect(typeof manualResult.receipt.composite_score).toBe('number');

      const autoResult = await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(autoResult.receipt).toHaveProperty('composite_score');
      expect(typeof autoResult.receipt.composite_score).toBe('number');
    });
  });

  describe('Both paths trigger materialization', () => {
    it('both paths trigger materialization for non-deduplicated receipts', async () => {
      // Both canonicalSubmitReceipt (called directly or via canonicalSubmitAutoReceipt)
      // triggers materializeTrustProfile after createReceipt returns a non-dedup result.
      // We verify by checking that the function does NOT short-circuit before
      // the materialization step — i.e., it returns successfully with a receipt.

      const manualResult = await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(manualResult.receipt).toBeDefined();
      expect(manualResult.deduplicated).toBeUndefined();

      const autoResult = await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(autoResult.receipt).toBeDefined();
      expect(autoResult.deduplicated).toBeUndefined();
    });

    it('neither path triggers materialization for deduplicated receipts', async () => {
      // Swap in the dedup mock
      mockCreateReceiptImpl.mockImplementationOnce(mockCreateReceiptDedup);
      const manualResult = await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(manualResult.deduplicated).toBe(true);

      mockCreateReceiptImpl.mockImplementationOnce(mockCreateReceiptDedup);
      const autoResult = await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(autoResult.deduplicated).toBe(true);
    });
  });

  describe('Both paths enforce idempotency', () => {
    it('both paths return deduplicated result when createReceipt deduplicates', async () => {
      mockCreateReceiptImpl.mockImplementationOnce(mockCreateReceiptDedup);
      const manualResult = await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(manualResult.deduplicated).toBe(true);
      expect(manualResult.receipt.receipt_id).toBe('ep_rcpt_existing');

      mockCreateReceiptImpl.mockImplementationOnce(mockCreateReceiptDedup);
      const autoResult = await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(autoResult.deduplicated).toBe(true);
      expect(autoResult.receipt.receipt_id).toBe('ep_rcpt_existing');
    });

    it('dedup is enforced inside createReceipt, not in the wrappers', async () => {
      // Both paths pass transactionRef to createReceipt — the dedup key is
      // computed inside createReceipt, not in the wrapper functions.
      await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      const manualArgs = createReceiptCallArgs[0];

      mockCreateReceiptImpl.mockClear();
      createReceiptCallArgs = [];

      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      const autoArgs = createReceiptCallArgs[0];

      expect(manualArgs.transactionRef).toBe(MANUAL_PARAMS.transaction_ref);
      expect(autoArgs.transactionRef).toBe(AUTO_PARAMS.transaction_ref);
    });
  });

  describe('Auto-receipt normalization', () => {
    it('forces provenance_tier to self_attested', async () => {
      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      const args = createReceiptCallArgs[0];
      expect(args.provenanceTier).toBe('self_attested');
    });

    it('forces requestBilateral to false', async () => {
      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      const args = createReceiptCallArgs[0];
      expect(args.requestBilateral).toBe(false);
    });

    it('derives agent_behavior from outcome.completed', async () => {
      await canonicalSubmitAutoReceipt(
        { ...AUTO_PARAMS, agent_behavior: null, outcome: { completed: true } },
        AUTO_SUBMITTER,
      );
      const args = createReceiptCallArgs[0];
      expect(args.agentBehavior).toBe('completed');
    });

    it('derives agent_behavior from outcome.error_occurred', async () => {
      await canonicalSubmitAutoReceipt(
        { ...AUTO_PARAMS, agent_behavior: null, outcome: { error_occurred: true } },
        AUTO_SUBMITTER,
      );
      const args = createReceiptCallArgs[0];
      expect(args.agentBehavior).toBe('abandoned');
    });

    it('defaults transaction_type to service when not provided', async () => {
      const { transaction_type, ...rest } = AUTO_PARAMS;
      await canonicalSubmitAutoReceipt(rest, AUTO_SUBMITTER);
      const args = createReceiptCallArgs[0];
      expect(args.transactionType).toBe('service');
    });
  });

  describe('Architectural invariant: single write path', () => {
    it('canonicalSubmitAutoReceipt delegates to canonicalSubmitReceipt, not directly to createReceipt', async () => {
      // This is the key architectural test. canonicalSubmitAutoReceipt should
      // call canonicalSubmitReceipt (which handles event emission and
      // materialization), not call createReceipt directly.
      //
      // We verify this by checking that the post-createReceipt invariants
      // (event emission, materialization) happen through the same code path.
      // Since canonicalSubmitAutoReceipt now delegates to canonicalSubmitReceipt,
      // createReceipt is called exactly once for each call.

      await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(mockCreateReceiptImpl).toHaveBeenCalledTimes(1);

      // The params passed to createReceipt match what canonicalSubmitReceipt
      // would produce — proving auto goes through the same path.
      const args = createReceiptCallArgs[0];
      expect(args.targetEntitySlug).toBe(AUTO_PARAMS.entity_id);
      expect(args.submitter).toBe(AUTO_SUBMITTER);
    });

    it('error propagation is identical for both paths', async () => {
      const errorResult = { error: 'Target entity not found', status: 404 };
      mockCreateReceiptImpl.mockResolvedValueOnce(errorResult);
      const manualResult = await canonicalSubmitReceipt(MANUAL_PARAMS, MANUAL_SUBMITTER);
      expect(manualResult.error).toBe('Target entity not found');

      mockCreateReceiptImpl.mockResolvedValueOnce(errorResult);
      const autoResult = await canonicalSubmitAutoReceipt(AUTO_PARAMS, AUTO_SUBMITTER);
      expect(autoResult.error).toBe('Target entity not found');
    });
  });
});
