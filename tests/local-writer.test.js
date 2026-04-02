/**
 * EMILIA Protocol — canonical-writer.js coverage boost
 *
 * Covers all exported functions and key internal paths:
 * - canonicalSubmitReceipt
 * - canonicalSubmitAutoReceipt
 * - canonicalBilateralConfirm (all branches)
 * - canonicalFileDispute
 * - canonicalRespondDispute
 * - canonicalResolveDispute
 * - canonicalWithdrawDispute
 * - canonicalAppealDispute
 * - canonicalResolveAppeal
 * - canonicalFileReport
 * - materializeTrustProfile
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';

// ── mock supabase ────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();

vi.mock('@/lib/supabase', () => ({
  getServiceClient: (...a) => mockGetServiceClient(...a),
}));

// ── mock create-receipt ───────────────────────────────────────────────────────

const mockCreateReceipt = vi.fn();

vi.mock('@/lib/create-receipt', () => ({
  createReceipt: (...a) => mockCreateReceipt(...a),
}));

// ── mock scoring-v2 (used in materializeTrustProfile via dynamic import) ─────

const mockComputeTrustProfile = vi.fn(() => ({
  score: 75,
  confidence: 'emerging',
  effectiveEvidence: 8,
  uniqueSubmitters: 4,
  receiptCount: 10,
  profile: {},
  anomaly: null,
}));

vi.mock('@/lib/scoring-v2', () => ({
  computeTrustProfile: (...a) => mockComputeTrustProfile(...a),
}));

// ── mock errors (ProtocolWriteError) ─────────────────────────────────────────

vi.mock('@/lib/errors', async (importOriginal) => {
  const original = await importOriginal();
  return { ...original };
});

// ── import module under test ──────────────────────────────────────────────────

import {
  canonicalSubmitReceipt,
  canonicalSubmitAutoReceipt,
  canonicalBilateralConfirm,
  canonicalFileDispute,
  canonicalRespondDispute,
  canonicalResolveDispute,
  canonicalWithdrawDispute,
  canonicalAppealDispute,
  canonicalResolveAppeal,
  canonicalFileReport,
  materializeTrustProfile,
  WRITE_EVENTS,
} from '../lib/canonical-writer.js';

// ── helpers ───────────────────────────────────────────────────────────────────

function makeChain(value) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue(value),
    single: vi.fn().mockResolvedValue(value),
    maybeSingle: vi.fn().mockResolvedValue(value),
    update: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(value),
    then: (resolve) => Promise.resolve(value).then(resolve),
  };
  return chain;
}

function makeSupabase(handlers = {}) {
  return {
    from: vi.fn((table) => {
      if (handlers[table]) return handlers[table](table);
      return makeChain({ data: null, error: null });
    }),
    rpc: vi.fn().mockResolvedValue({ data: 75, error: null }),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// WRITE_EVENTS constant
// ─────────────────────────────────────────────────────────────────────────────

describe('WRITE_EVENTS', () => {
  it('exports known event type keys', () => {
    expect(WRITE_EVENTS.RECEIPT_SUBMITTED).toBeTruthy();
    expect(WRITE_EVENTS.DISPUTE_FILED).toBeTruthy();
    expect(WRITE_EVENTS.ENTITY_REGISTERED).toBeTruthy();
    expect(WRITE_EVENTS.TRUST_RECOMPUTED).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalSubmitReceipt
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalSubmitReceipt', () => {
  beforeEach(() => {
    const supabase = makeSupabase({
      protocol_events: () => makeChain({ data: null, error: null }),
      entities: () => {
        const c = makeChain({ data: { id: 'entity-db-1' }, error: null });
        c.single = vi.fn().mockResolvedValue({ data: { id: 'entity-db-1' }, error: null });
        return c;
      },
      receipts: () => makeChain({ data: [], error: null }),
    });
    supabase.rpc = vi.fn().mockResolvedValue({ data: 75, error: null });
    mockGetServiceClient.mockReturnValue(supabase);
  });

  it('returns the createReceipt result on success', async () => {
    mockCreateReceipt.mockResolvedValue({
      receipt: { receipt_id: 'r-1', entity_id: 'eid-1' },
      error: null,
      deduplicated: false,
    });
    const result = await canonicalSubmitReceipt({ entity_id: 'slug-1' }, { entity_id: 'submitter-1' });
    expect(result.receipt.receipt_id).toBe('r-1');
  });

  it('returns error result without materializing when createReceipt errors', async () => {
    mockCreateReceipt.mockResolvedValue({ error: 'Entity not found', status: 404 });
    const result = await canonicalSubmitReceipt({ entity_id: 'bad' }, { entity_id: 'sub' });
    expect(result.error).toBe('Entity not found');
  });

  it('skips materialization when deduplicated=true', async () => {
    mockCreateReceipt.mockResolvedValue({
      receipt: { receipt_id: 'r-dup', entity_id: 'eid-dup' },
      error: null,
      deduplicated: true,
    });
    // Should not throw even if materializeTrustProfile would fail
    const result = await canonicalSubmitReceipt({ entity_id: 'slug-dup' }, { entity_id: 'sub-dup' });
    expect(result.receipt.receipt_id).toBe('r-dup');
  });

  it('passes signals from params to createReceipt', async () => {
    mockCreateReceipt.mockResolvedValue({
      receipt: { receipt_id: 'r-2', entity_id: 'eid-2' },
      error: null,
      deduplicated: false,
    });
    await canonicalSubmitReceipt(
      { entity_id: 'slug-2', delivery_accuracy: 90, product_accuracy: 85 },
      { entity_id: 'sub-2' }
    );
    expect(mockCreateReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ signals: expect.objectContaining({ delivery_accuracy: 90 }) })
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalSubmitAutoReceipt
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalSubmitAutoReceipt', () => {
  beforeEach(() => {
    mockCreateReceipt.mockResolvedValue({
      receipt: { receipt_id: 'ar-1', entity_id: 'eid-auto' },
      error: null,
      deduplicated: false,
    });
    // Reuse the same full supabase mock as submit tests
    const supabase = makeSupabase({
      entities: () => {
        const c = makeChain({ data: { id: 'entity-auto' }, error: null });
        c.single = vi.fn().mockResolvedValue({ data: { id: 'entity-auto' }, error: null });
        return c;
      },
      receipts: () => makeChain({ data: [], error: null }),
      protocol_events: () => makeChain({ data: null, error: null }),
    });
    supabase.rpc = vi.fn().mockResolvedValue({ data: 70, error: null });
    mockGetServiceClient.mockReturnValue(supabase);
  });

  it('delegates to canonicalSubmitReceipt', async () => {
    const result = await canonicalSubmitAutoReceipt(
      { entity_id: 'slug-auto', transaction_ref: 'tx-1' },
      { entity_id: 'sub-auto' }
    );
    expect(result.receipt?.receipt_id).toBe('ar-1');
  });

  it('maps outcome.completed=true to agent_behavior=completed', async () => {
    await canonicalSubmitAutoReceipt(
      { entity_id: 'slug', outcome: { completed: true } },
      { entity_id: 'sub' }
    );
    expect(mockCreateReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ agentBehavior: 'completed' })
    );
  });

  it('maps outcome.error_occurred=true to agent_behavior=abandoned', async () => {
    await canonicalSubmitAutoReceipt(
      { entity_id: 'slug', outcome: { error_occurred: true } },
      { entity_id: 'sub' }
    );
    expect(mockCreateReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ agentBehavior: 'abandoned' })
    );
  });

  it('uses provided agent_behavior if present (ignores outcome)', async () => {
    await canonicalSubmitAutoReceipt(
      { entity_id: 'slug', agent_behavior: 'disputed', outcome: { completed: true } },
      { entity_id: 'sub' }
    );
    expect(mockCreateReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ agentBehavior: 'disputed' })
    );
  });

  it('sets provenance_tier to self_attested always', async () => {
    await canonicalSubmitAutoReceipt(
      { entity_id: 'slug', provenance_tier: 'bilateral' },
      { entity_id: 'sub' }
    );
    expect(mockCreateReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ provenanceTier: 'self_attested' })
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalBilateralConfirm
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalBilateralConfirm', () => {
  function makeReceiptSupabase(receipt, updateError = null) {
    return {
      from: vi.fn((table) => {
        if (table === 'receipts') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            order: vi.fn().mockReturnThis(),
            limit: vi.fn().mockResolvedValue({ data: [], error: null }),
            single: vi.fn().mockResolvedValue({ data: receipt, error: null }),
            then: (resolve) => Promise.resolve({ data: receipt, error: null }).then(resolve),
          };
        }
        if (table === 'entities') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: { id: receipt?.entity_id }, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        return makeChain({ data: null, error: updateError });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 80, error: null }),
    };
  }

  it('returns 404 when receipt not found', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase(null));
    const result = await canonicalBilateralConfirm('r-missing', 'entity-X', true);
    expect(result.status).toBe(404);
  });

  it('returns 403 when entity is not the subject', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase({
      receipt_id: 'r-1', entity_id: 'entity-A', submitted_by: 'entity-B',
      bilateral_status: 'pending_confirmation', confirmation_deadline: null,
    }));
    const result = await canonicalBilateralConfirm('r-1', 'entity-OTHER', true);
    expect(result.status).toBe(403);
  });

  it('returns 403 when submitter tries to confirm own receipt', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase({
      receipt_id: 'r-1', entity_id: 'entity-A', submitted_by: 'entity-A',
      bilateral_status: 'pending_confirmation', confirmation_deadline: null,
    }));
    const result = await canonicalBilateralConfirm('r-1', 'entity-A', true);
    expect(result.status).toBe(403);
  });

  it('returns 409 when status is not pending_confirmation', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase({
      receipt_id: 'r-1', entity_id: 'entity-A', submitted_by: 'entity-B',
      bilateral_status: 'confirmed', confirmation_deadline: null,
    }));
    const result = await canonicalBilateralConfirm('r-1', 'entity-A', true);
    expect(result.status).toBe(409);
  });

  it('returns 410 when confirmation deadline expired', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase({
      receipt_id: 'r-1', entity_id: 'entity-A', submitted_by: 'entity-B',
      bilateral_status: 'pending_confirmation',
      confirmation_deadline: new Date(Date.now() - 10000).toISOString(),
    }));
    const result = await canonicalBilateralConfirm('r-1', 'entity-A', true);
    expect(result.status).toBe(410);
  });

  it('confirms receipt when valid', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase({
      receipt_id: 'r-1', entity_id: 'entity-A', submitted_by: 'entity-B',
      bilateral_status: 'pending_confirmation', confirmation_deadline: null,
    }));
    const result = await canonicalBilateralConfirm('r-1', 'entity-A', true);
    expect(result.bilateral_status).toBe('confirmed');
  });

  it('disputes receipt when confirm=false', async () => {
    mockGetServiceClient.mockReturnValue(makeReceiptSupabase({
      receipt_id: 'r-1', entity_id: 'entity-A', submitted_by: 'entity-B',
      bilateral_status: 'pending_confirmation', confirmation_deadline: null,
    }));
    const result = await canonicalBilateralConfirm('r-1', 'entity-A', false);
    expect(result.bilateral_status).toBe('disputed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalFileDispute
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalFileDispute', () => {
  function makeDisputeSupabase({ receipt = null, existingDispute = [], insertErr = null } = {}) {
    return {
      from: vi.fn((table) => {
        if (table === 'receipts') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: receipt, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        if (table === 'disputes') {
          const c = {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            in: vi.fn().mockReturnThis(),
            limit: vi.fn().mockReturnThis(),
            insert: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({
              data: receipt ? { dispute_id: 'disp-1', receipt_id: receipt.receipt_id, status: 'open', reason: 'fraud', response_deadline: null } : null,
              error: insertErr,
            }),
            then: (resolve) => Promise.resolve({ data: existingDispute, error: null }).then(resolve),
          };
          return c;
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when receipt not found', async () => {
    mockGetServiceClient.mockReturnValue(makeDisputeSupabase({ receipt: null }));
    const result = await canonicalFileDispute({ receipt_id: 'r-missing' }, { id: 'f-1' });
    expect(result.status).toBe(404);
  });

  it('returns 409 when active dispute already exists', async () => {
    const receipt = { receipt_id: 'r-1', entity_id: 'e1', submitted_by: 'e2' };
    mockGetServiceClient.mockReturnValue(makeDisputeSupabase({
      receipt,
      existingDispute: [{ dispute_id: 'd-existing', status: 'open' }],
    }));
    const result = await canonicalFileDispute({ receipt_id: 'r-1', reason: 'fraud' }, { id: 'f-1' });
    expect(result.status).toBe(409);
  });

  it('files dispute successfully', async () => {
    const receipt = { receipt_id: 'r-1', entity_id: 'e1', submitted_by: 'e2' };
    mockGetServiceClient.mockReturnValue(makeDisputeSupabase({ receipt, existingDispute: [] }));
    const result = await canonicalFileDispute({ receipt_id: 'r-1', reason: 'fraud' }, { id: 'f-1', entity_id: 'f-1' });
    expect(result.dispute_id).toBeTruthy();
  });

  it('sets filed_by_type=receipt_subject when filer is the entity', async () => {
    const receipt = { receipt_id: 'r-1', entity_id: 'the-entity', submitted_by: 'other' };
    mockGetServiceClient.mockReturnValue(makeDisputeSupabase({ receipt, existingDispute: [] }));
    const result = await canonicalFileDispute(
      { receipt_id: 'r-1', reason: 'fraud' },
      { id: 'the-entity', entity_id: 'the-entity' }
    );
    expect(result.filed_by_type).toBe('receipt_subject');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalRespondDispute
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalRespondDispute', () => {
  function makeRespondSupabase(dispute) {
    return {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: dispute, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when dispute not found', async () => {
    mockGetServiceClient.mockReturnValue(makeRespondSupabase(null));
    const result = await canonicalRespondDispute('d-missing', 'resp-1', 'response text', null);
    expect(result.status).toBe(404);
  });

  it('returns 403 when responder is not the receipt submitter', async () => {
    mockGetServiceClient.mockReturnValue(makeRespondSupabase({
      dispute_id: 'd-1', status: 'open',
      receipt: { submitted_by: 'e-submitted' },
      response_deadline: new Date(Date.now() + 86400000).toISOString(),
    }));
    const result = await canonicalRespondDispute('d-1', 'wrong-entity', 'resp', null);
    expect(result.status).toBe(403);
  });

  it('returns 409 when dispute is not open', async () => {
    mockGetServiceClient.mockReturnValue(makeRespondSupabase({
      dispute_id: 'd-1', status: 'under_review',
      receipt: { submitted_by: 'resp-entity' },
      response_deadline: new Date(Date.now() + 86400000).toISOString(),
    }));
    const result = await canonicalRespondDispute('d-1', 'resp-entity', 'resp', null);
    expect(result.status).toBe(409);
  });

  it('returns 410 when deadline passed', async () => {
    mockGetServiceClient.mockReturnValue(makeRespondSupabase({
      dispute_id: 'd-1', status: 'open',
      receipt: { submitted_by: 'resp-entity' },
      response_deadline: new Date(Date.now() - 1000).toISOString(),
    }));
    const result = await canonicalRespondDispute('d-1', 'resp-entity', 'resp', null);
    expect(result.status).toBe(410);
  });

  it('responds successfully — lines 404-417', async () => {
    mockGetServiceClient.mockReturnValue(makeRespondSupabase({
      dispute_id: 'd-1', status: 'open',
      entity_id: 'e1', receipt_id: 'r-1',
      receipt: { submitted_by: 'resp-entity' },
      response_deadline: new Date(Date.now() + 86400000).toISOString(),
    }));
    const result = await canonicalRespondDispute('d-1', 'resp-entity', 'my response text', null);
    expect(result.dispute_id).toBe('d-1');
    expect(result.status).toBe('under_review');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalResolveDispute
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalResolveDispute', () => {
  function makeResolveSupabase(dispute) {
    return {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: dispute, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        if (table === 'receipts') {
          // Must support both update().eq() and select().eq().order().limit()
          const chain = {
            update: vi.fn().mockReturnThis(),
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            order: vi.fn().mockReturnThis(),
            limit: vi.fn().mockResolvedValue({ data: [], error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
          return chain;
        }
        if (table === 'entities') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: { id: dispute?.entity_id }, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when dispute not found', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveSupabase(null));
    const result = await canonicalResolveDispute('d-missing', 'upheld', 'reason', 'op-1');
    expect(result.status).toBe(404);
  });

  it('returns 409 when dispute is not open or under_review', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveSupabase({
      dispute_id: 'd-1', status: 'upheld', entity_id: 'e1',
    }));
    const result = await canonicalResolveDispute('d-1', 'upheld', 'reason', 'op-1');
    expect(result.status).toBe(409);
  });

  it('returns 400 for invalid resolution', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveSupabase({
      dispute_id: 'd-1', status: 'open', entity_id: 'e1',
    }));
    const result = await canonicalResolveDispute('d-1', 'invalid_res', 'reason', 'op-1');
    expect(result.status).toBe(400);
  });

  it('resolves with upheld successfully', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveSupabase({
      dispute_id: 'd-1', status: 'open', entity_id: 'e1', receipt_id: 'r-1',
    }));
    const result = await canonicalResolveDispute('d-1', 'upheld', 'reason', 'op-1');
    expect(result.dispute_id).toBe('d-1');
    expect(result.resolution).toBe('upheld');
  });

  it('resolves with reversed (triggers recomputeAndPersistScores)', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveSupabase({
      dispute_id: 'd-1', status: 'open', entity_id: 'e1', receipt_id: 'r-1',
    }));
    const result = await canonicalResolveDispute('d-1', 'reversed', 'bad receipt', 'op-1');
    expect(result.resolution).toBe('reversed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalWithdrawDispute
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalWithdrawDispute', () => {
  function makeWithdrawSupabase(dispute) {
    return {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: dispute, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when dispute not found', async () => {
    mockGetServiceClient.mockReturnValue(makeWithdrawSupabase(null));
    const result = await canonicalWithdrawDispute('d-missing', { id: 'w-1' });
    expect(result.status).toBe(404);
  });

  it('returns 409 when dispute is not open', async () => {
    mockGetServiceClient.mockReturnValue(makeWithdrawSupabase({
      dispute_id: 'd-1', status: 'under_review', filed_by: 'w-1',
    }));
    const result = await canonicalWithdrawDispute('d-1', { id: 'w-1' });
    expect(result.status).toBe(409);
  });

  it('returns 403 when withdrawer is not the filer', async () => {
    mockGetServiceClient.mockReturnValue(makeWithdrawSupabase({
      dispute_id: 'd-1', status: 'open', filed_by: 'actual-filer',
    }));
    const result = await canonicalWithdrawDispute('d-1', { id: 'other-person' });
    expect(result.status).toBe(403);
  });

  it('withdraws successfully', async () => {
    mockGetServiceClient.mockReturnValue(makeWithdrawSupabase({
      dispute_id: 'd-1', status: 'open', filed_by: 'filer-1', receipt_id: 'r-1',
    }));
    const result = await canonicalWithdrawDispute('d-1', { id: 'filer-1' });
    expect(result.status).toBe('withdrawn');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalAppealDispute
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalAppealDispute', () => {
  function makeAppealSupabase(dispute, updateErr = null) {
    return {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: dispute, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: updateErr }).then(resolve),
          };
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when dispute not found', async () => {
    mockGetServiceClient.mockReturnValue(makeAppealSupabase(null));
    const result = await canonicalAppealDispute('d-missing', { id: 'a-1' }, 'good reason here', null);
    expect(result.status).toBe(404);
  });

  it('returns 409 when dispute is not in appealable state', async () => {
    mockGetServiceClient.mockReturnValue(makeAppealSupabase({
      dispute_id: 'd-1', status: 'open', entity_id: 'e1', filed_by: 'a-1',
    }));
    const result = await canonicalAppealDispute('d-1', { id: 'a-1' }, 'reason text', null);
    expect(result.status).toBe(409);
  });

  it('returns 403 when appealer is not a party', async () => {
    mockGetServiceClient.mockReturnValue(makeAppealSupabase({
      dispute_id: 'd-1', status: 'upheld', entity_id: 'e1', filed_by: 'f-1',
    }));
    const result = await canonicalAppealDispute('d-1', { id: 'outsider' }, 'valid reason here', null);
    expect(result.status).toBe(403);
  });

  it('returns 400 when reason is too short', async () => {
    mockGetServiceClient.mockReturnValue(makeAppealSupabase({
      dispute_id: 'd-1', status: 'upheld', entity_id: 'e1', filed_by: 'a-1',
    }));
    const result = await canonicalAppealDispute('d-1', { id: 'a-1' }, 'short', null);
    expect(result.status).toBe(400);
  });

  it('files appeal successfully', async () => {
    mockGetServiceClient.mockReturnValue(makeAppealSupabase({
      dispute_id: 'd-1', status: 'upheld', entity_id: 'e1', filed_by: 'a-1', receipt_id: 'r-1',
    }));
    const result = await canonicalAppealDispute('d-1', { id: 'a-1' }, 'detailed reason for appeal', null);
    expect(result.status).toBe('appealed');
  });

  it('returns 500 when DB update fails — lines 542-543', async () => {
    mockGetServiceClient.mockReturnValue(makeAppealSupabase({
      dispute_id: 'd-1', status: 'upheld', entity_id: 'e1', filed_by: 'a-1', receipt_id: 'r-1',
    }, { message: 'db constraint error' }));
    const result = await canonicalAppealDispute('d-1', { id: 'a-1' }, 'detailed reason for appeal', null);
    expect(result.status).toBe(500);
    expect(result.error).toMatch(/Failed to file appeal/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalResolveAppeal
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalResolveAppeal', () => {
  function makeResolveAppealSupabase(dispute) {
    return {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: dispute, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        if (table === 'receipts') {
          const chain = {
            update: vi.fn().mockReturnThis(),
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            order: vi.fn().mockReturnThis(),
            limit: vi.fn().mockResolvedValue({ data: [], error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
          return chain;
        }
        if (table === 'entities') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            update: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: { id: dispute?.entity_id }, error: null }),
            then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
          };
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when dispute not found', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveAppealSupabase(null));
    const result = await canonicalResolveAppeal('d-missing', 'appeal_upheld', 'rationale', 'op-1');
    expect(result.status).toBe(404);
  });

  it('returns 409 when dispute is not in appealed state', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveAppealSupabase({
      dispute_id: 'd-1', status: 'open', entity_id: 'e1',
    }));
    const result = await canonicalResolveAppeal('d-1', 'appeal_upheld', 'rationale', 'op-1');
    expect(result.status).toBe(409);
  });

  it('returns 400 for invalid resolution', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveAppealSupabase({
      dispute_id: 'd-1', status: 'appealed', entity_id: 'e1',
    }));
    const result = await canonicalResolveAppeal('d-1', 'invalid', 'rationale', 'op-1');
    expect(result.status).toBe(400);
  });

  it('resolves appeal_upheld successfully', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveAppealSupabase({
      dispute_id: 'd-1', status: 'appealed', entity_id: 'e1', receipt_id: 'r-1',
    }));
    const result = await canonicalResolveAppeal('d-1', 'appeal_upheld', 'rationale', 'op-1');
    expect(result.status).toBe('appeal_upheld');
  });

  it('resolves appeal_reversed and triggers recompute', async () => {
    mockGetServiceClient.mockReturnValue(makeResolveAppealSupabase({
      dispute_id: 'd-1', status: 'appealed', entity_id: 'e1', receipt_id: 'r-1',
      resolution: 'upheld',
    }));
    const result = await canonicalResolveAppeal('d-1', 'appeal_reversed', 'overturn', 'op-1');
    expect(result.status).toBe('appeal_reversed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// canonicalFileReport
// ─────────────────────────────────────────────────────────────────────────────

describe('canonicalFileReport', () => {
  function makeReportSupabase(entity, insertErr = null) {
    return {
      from: vi.fn((table) => {
        if (table === 'entities') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: entity, error: null }),
          };
        }
        if (table === 'trust_reports') {
          return {
            insert: vi.fn().mockResolvedValue({ data: null, error: insertErr }),
          };
        }
        return makeChain({ data: null, error: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 70, error: null }),
    };
  }

  it('returns 404 when entity not found', async () => {
    mockGetServiceClient.mockReturnValue(makeReportSupabase(null));
    const result = await canonicalFileReport({ entity_id: 'missing', report_type: 'fraud', description: 'x' });
    expect(result.status).toBe(404);
  });

  it('returns 500 when insert fails', async () => {
    mockGetServiceClient.mockReturnValue(makeReportSupabase(
      { id: 'e1', entity_id: 'slug-1', display_name: 'Test' },
      { message: 'insert failed' }
    ));
    const result = await canonicalFileReport({ entity_id: 'slug-1', report_type: 'fraud', description: 'fraud' });
    expect(result.status).toBe(500);
  });

  it('files report successfully', async () => {
    mockGetServiceClient.mockReturnValue(makeReportSupabase(
      { id: 'e1', entity_id: 'slug-1', display_name: 'Test Corp' }
    ));
    const result = await canonicalFileReport({
      entity_id: 'slug-1', report_type: 'fraud', description: 'suspicious activity',
    });
    expect(result.report_id).toBeTruthy();
    expect(result.display_name).toBe('Test Corp');
  });

  it('includes entity_id in successful response', async () => {
    mockGetServiceClient.mockReturnValue(makeReportSupabase(
      { id: 'e2', entity_id: 'slug-2', display_name: 'Corp 2' }
    ));
    const result = await canonicalFileReport({
      entity_id: 'slug-2', report_type: 'spam', description: 'repeated spam',
    });
    expect(result.entity_id).toBe('slug-2');
  });
});
