import { describe, it, expect, vi, beforeEach } from 'vitest';
import { findVouchers, computeWeightedVote, adjudicateDispute } from '../lib/dispute-adjudication.js';

// ============================================================================
// Supabase mock helpers
// ============================================================================

/**
 * makeChain builds a fluent Supabase query builder mock.
 * Each chainable method returns `this` so you can call .from().select()... etc.
 * The terminal call (single, maybeSingle) or implicit resolution resolves to
 * { data, error }.
 */
function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    // When the chain is awaited directly (e.g. after .limit()) it resolves.
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ============================================================================
// Mock @/lib/supabase so dispute-adjudication never calls a real DB
// ============================================================================

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(),
}));

import { getServiceClient } from '../lib/supabase.js';

// ============================================================================
// findVouchers
// ============================================================================

describe('findVouchers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns entities with confidence >= "confident" who transacted with target', async () => {
    const disputedId = 'entity-disputed-uuid';
    const voucherId = 'entity-voucher-uuid';

    // receipts query: direction 1 — voucher submitted about disputed
    const receiptsChain1 = makeChain({ data: [{ submitted_by: voucherId, entity_id: disputedId }], error: null });
    // receipts query: direction 2 — disputed submitted about someone
    const receiptsChain2 = makeChain({ data: [], error: null });
    // entities query
    const entitiesChain = makeChain({
      data: [
        {
          id: voucherId,
          entity_id: 'voucher-slug',
          display_name: 'Voucher Entity',
          trust_snapshot: { confidence: 'confident' },
          emilia_score: 88,
          status: 'active',
        },
      ],
      error: null,
    });

    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn(() => {
        fromCallCount += 1;
        if (fromCallCount === 1) return receiptsChain1; // submitted_by query
        if (fromCallCount === 2) return receiptsChain2; // submitted about voucher
        return entitiesChain;                            // entities lookup
      }),
    };

    const vouchers = await findVouchers(disputedId, mockSupabase);

    expect(vouchers.length).toBe(1);
    expect(vouchers[0].entity_id).toBe(voucherId);
    expect(vouchers[0].confidence).toBe('confident');
    expect(vouchers[0].confidence_score).toBe(1.0);
  });

  it('excludes entities below the "confident" threshold', async () => {
    const disputedId = 'entity-disputed-uuid';
    const lowConfidenceId = 'entity-low-uuid';

    const receiptsChain1 = makeChain({ data: [{ submitted_by: lowConfidenceId, entity_id: disputedId }], error: null });
    const receiptsChain2 = makeChain({ data: [], error: null });
    const entitiesChain = makeChain({
      data: [
        {
          id: lowConfidenceId,
          entity_id: 'low-slug',
          display_name: 'Low Confidence Entity',
          trust_snapshot: { confidence: 'provisional' },
          emilia_score: 40,
          status: 'active',
        },
      ],
      error: null,
    });

    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn(() => {
        fromCallCount += 1;
        if (fromCallCount === 1) return receiptsChain1;
        if (fromCallCount === 2) return receiptsChain2;
        return entitiesChain;
      }),
    };

    const vouchers = await findVouchers(disputedId, mockSupabase);
    expect(vouchers.length).toBe(0);
  });

  it('includes "emerging" confidence tier as an admitted voucher', async () => {
    const disputedId = 'entity-disputed-uuid';
    const emergingId = 'entity-emerging-uuid';

    const receiptsChain1 = makeChain({ data: [{ submitted_by: emergingId, entity_id: disputedId }], error: null });
    const receiptsChain2 = makeChain({ data: [], error: null });
    const entitiesChain = makeChain({
      data: [
        {
          id: emergingId,
          entity_id: 'emerging-slug',
          display_name: 'Emerging Entity',
          trust_snapshot: { confidence: 'emerging' },
          emilia_score: 72,
          status: 'active',
        },
      ],
      error: null,
    });

    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn(() => {
        fromCallCount += 1;
        if (fromCallCount === 1) return receiptsChain1;
        if (fromCallCount === 2) return receiptsChain2;
        return entitiesChain;
      }),
    };

    const vouchers = await findVouchers(disputedId, mockSupabase);
    expect(vouchers.length).toBe(1);
    expect(vouchers[0].confidence).toBe('emerging');
    expect(vouchers[0].confidence_score).toBe(0.6);
  });

  it('returns empty array when there are no counterparties', async () => {
    const receiptsChain1 = makeChain({ data: [], error: null });
    const receiptsChain2 = makeChain({ data: [], error: null });

    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn(() => {
        fromCallCount += 1;
        if (fromCallCount <= 2) {
          // Return empty data for both directions
          return fromCallCount === 1 ? receiptsChain1 : receiptsChain2;
        }
        return makeChain({ data: [], error: null });
      }),
    };

    const vouchers = await findVouchers('disputed-uuid', mockSupabase);
    expect(vouchers).toEqual([]);
  });

  it('tags direction as "both" when voucher appears in both directions', async () => {
    const disputedId = 'entity-disputed-uuid';
    const voucherId = 'entity-voucher-uuid';

    // submitted_by (direction 1) — voucher submitted about disputed
    const receiptsChain1 = makeChain({ data: [{ submitted_by: voucherId, entity_id: disputedId }], error: null });
    // submitted by disputed about voucher (direction 2)
    const receiptsChain2 = makeChain({ data: [{ submitted_by: disputedId, entity_id: voucherId }], error: null });
    const entitiesChain = makeChain({
      data: [
        {
          id: voucherId,
          entity_id: 'voucher-slug',
          display_name: 'Voucher Entity',
          trust_snapshot: { confidence: 'confident' },
          emilia_score: 88,
          status: 'active',
        },
      ],
      error: null,
    });

    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn(() => {
        fromCallCount += 1;
        if (fromCallCount === 1) return receiptsChain1;
        if (fromCallCount === 2) return receiptsChain2;
        return entitiesChain;
      }),
    };

    const vouchers = await findVouchers(disputedId, mockSupabase);
    expect(vouchers.length).toBe(1);
    expect(vouchers[0].direction).toBe('both');
    expect(vouchers[0].receipt_count).toBe(2);
  });
});

// ============================================================================
// computeWeightedVote
// ============================================================================

describe('computeWeightedVote', () => {
  it('returns "uphold_dispute" when >60% weighted vote is negative (low sentiment)', () => {
    // Two confident vouchers (weight 1.0 each) with very low sentiment → uphold
    const voucherSentiments = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 3 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 2 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.9, receipt_count: 1 },
    ];
    const result = computeWeightedVote(voucherSentiments);
    // uphold = 2, dismiss = 1 → fraction = 2/3 ≈ 0.67 > 0.60 → uphold
    expect(result.recommendation).toBe('uphold_dispute');
    expect(result.uphold_fraction).toBeGreaterThan(0.60);
  });

  it('returns "dismiss_dispute" when <40% weighted vote is negative', () => {
    // Three vouchers dismissing, one upholding
    const voucherSentiments = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.9, receipt_count: 5 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.8, receipt_count: 4 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.85, receipt_count: 3 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 1 },
    ];
    const result = computeWeightedVote(voucherSentiments);
    // dismiss = 3, uphold = 1 → fraction = 1/4 = 0.25 < 0.40 → dismiss
    expect(result.recommendation).toBe('dismiss_dispute');
    expect(result.uphold_fraction).toBeLessThan(0.40);
  });

  it('returns "inconclusive" when weighted vote fraction is between 40-60%', () => {
    // 2 uphold (sentiment < 0.35) + 2 dismiss (sentiment > 0.65) with equal weight → fraction = 0.5
    const voucherSentiments = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 2 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 2 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.9, receipt_count: 2 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.9, receipt_count: 2 },
    ];
    const result = computeWeightedVote(voucherSentiments);
    expect(result.recommendation).toBe('inconclusive');
    expect(result.uphold_fraction).toBeCloseTo(0.5, 2);
  });

  it('returns confidence proportional to vote clarity — unanimous vote is higher confidence', () => {
    const unanimousUphold = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 5 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 4 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 3 },
    ];
    const splitVote = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 5 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 4 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.9, receipt_count: 3 },
    ];

    const unanimousResult = computeWeightedVote(unanimousUphold);
    const splitResult = computeWeightedVote(splitVote);

    expect(unanimousResult.confidence).toBeGreaterThan(splitResult.confidence);
  });

  it('returns inconclusive with confidence 0 when there are zero vouchers', () => {
    const result = computeWeightedVote([]);
    expect(result.recommendation).toBe('inconclusive');
    expect(result.confidence).toBe(0);
    expect(result.voucher_count).toBe(0);
    expect(result.uphold_fraction).toBeNull();
  });

  it('returns inconclusive when only one voucher participates (below MIN_VOUCHERS_FOR_DECISION)', () => {
    const voucherSentiments = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 10 },
    ];
    const result = computeWeightedVote(voucherSentiments);
    // Only 1 participating voucher — below the minimum of 2
    expect(result.recommendation).toBe('inconclusive');
  });

  it('single high-confidence voucher with negative sentiment → inconclusive (not enough participants)', () => {
    const voucherSentiments = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.05, receipt_count: 20 },
    ];
    const result = computeWeightedVote(voucherSentiments);
    // MIN_VOUCHERS_FOR_DECISION = 2, so single voucher cannot make a call
    expect(result.recommendation).toBe('inconclusive');
    expect(result.confidence).toBe(0);
  });

  it('vouchers with null sentiment are skipped (abstain, not penalised)', () => {
    const voucherSentiments = [
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: null, receipt_count: 0 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: null, receipt_count: 0 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 3 },
      { voucher: { confidence: 'confident', confidence_score: 1.0 }, sentiment: 0.1, receipt_count: 2 },
    ];
    const result = computeWeightedVote(voucherSentiments);
    // Only 2 participating vouchers, both upholding → uphold
    expect(result.recommendation).toBe('uphold_dispute');
    expect(result.participating_count).toBe(2);
  });
});

// ============================================================================
// adjudicateDispute — full flow with mocked supabase
// ============================================================================

describe('adjudicateDispute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeSupabaseMock({ disputeData, disputeError, receiptsDir1, receiptsDir2, entitiesData, sentimentDir1, sentimentDir2 } = {}) {
    let fromCallCount = 0;

    return {
      from: vi.fn((table) => {
        fromCallCount += 1;

        if (table === 'disputes') {
          // First call = select, last call = update
          if (fromCallCount === 1) {
            // SELECT dispute
            return {
              select: vi.fn().mockReturnThis(),
              eq: vi.fn().mockReturnThis(),
              single: vi.fn().mockResolvedValue({ data: disputeData ?? null, error: disputeError ?? null }),
            };
          }
          // UPDATE dispute (persist adjudication result)
          return {
            update: vi.fn().mockReturnThis(),
            eq: vi.fn().mockResolvedValue({ error: null }),
          };
        }

        if (table === 'receipts') {
          // Multiple receipts queries: findVouchers dir1, findVouchers dir2,
          // then sentiment queries per voucher
          const chain = makeChain({ data: receiptsDir1 ?? [], error: null });
          return chain;
        }

        if (table === 'entities') {
          return makeChain({ data: entitiesData ?? [], error: null });
        }

        return makeChain({ data: [], error: null });
      }),
    };
  }

  it('returns error when dispute is not found', async () => {
    const mockSupabase = {
      from: vi.fn(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: null, error: { message: 'not found' } }),
      })),
    };

    const result = await adjudicateDispute('ep_dispute_unknown', mockSupabase);
    expect(result.error).toBe('Dispute not found');
    expect(result.status).toBe(404);
  });

  it('returns 409 when dispute is in a terminal state', async () => {
    const mockSupabase = {
      from: vi.fn(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({
          data: {
            id: 'uuid-1',
            dispute_id: 'ep_dispute_1',
            receipt_id: 'receipt-uuid',
            entity_id: 'entity-uuid',
            filed_by: 'filer-uuid',
            status: 'resolved', // terminal state
            adjudication_result: null,
            adjudicated_at: null,
            created_at: new Date().toISOString(),
            response_deadline: null,
          },
          error: null,
        }),
      })),
    };

    const result = await adjudicateDispute('ep_dispute_1', mockSupabase);
    expect(result.status).toBe(409);
    expect(result.error).toContain('resolved');
  });

  it('returns inconclusive with vouchers:[] when no vouchers exist', async () => {
    let fromCallCount = 0;
    const disputeRecord = {
      id: 'uuid-1',
      dispute_id: 'ep_dispute_novouchers',
      receipt_id: 'receipt-uuid',
      entity_id: 'entity-uuid',
      filed_by: 'filer-uuid',
      status: 'open',
      adjudication_result: null,
      adjudicated_at: null,
      created_at: new Date().toISOString(),
      response_deadline: null,
    };

    const mockSupabase = {
      from: vi.fn((table) => {
        fromCallCount += 1;
        if (table === 'disputes' && fromCallCount === 1) {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: disputeRecord, error: null }),
          };
        }
        if (table === 'disputes') {
          // persist call
          return {
            update: vi.fn().mockReturnThis(),
            eq: vi.fn().mockResolvedValue({ error: null }),
          };
        }
        // receipts or entities — return empty
        return makeChain({ data: [], error: null });
      }),
    };

    const result = await adjudicateDispute('ep_dispute_novouchers', mockSupabase);
    expect(result.adjudication.recommendation).toBe('inconclusive');
    expect(result.adjudication.confidence).toBe(0);
    expect(result.vouchers).toEqual([]);
    expect(result.dispute_id).toBe('ep_dispute_novouchers');
  });

  it('full flow: vouchers with negative sentiment produce uphold recommendation', async () => {
    const disputeRecord = {
      id: 'uuid-2',
      dispute_id: 'ep_dispute_full',
      receipt_id: 'receipt-uuid',
      entity_id: 'disputed-entity-uuid',
      filed_by: 'filer-uuid',
      status: 'under_review',
      adjudication_result: null,
      adjudicated_at: null,
      created_at: new Date().toISOString(),
      response_deadline: null,
    };

    const voucher1Id = 'voucher-1-uuid';
    const voucher2Id = 'voucher-2-uuid';

    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn((table) => {
        fromCallCount += 1;

        // Call 1: SELECT dispute
        if (table === 'disputes' && fromCallCount === 1) {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: disputeRecord, error: null }),
          };
        }

        // Calls to 'receipts' — findVouchers (dir 1 & 2) + sentiment (2 vouchers × 2 dirs)
        if (table === 'receipts') {
          if (fromCallCount === 2) {
            // findVouchers direction 1: vouchers who submitted about disputed
            return makeChain({
              data: [
                { submitted_by: voucher1Id, entity_id: 'disputed-entity-uuid' },
                { submitted_by: voucher2Id, entity_id: 'disputed-entity-uuid' },
              ],
              error: null,
            });
          }
          if (fromCallCount === 3) {
            // findVouchers direction 2: disputed submitted about vouchers
            return makeChain({ data: [], error: null });
          }
          // Sentiment queries — very negative behavior (abandoned/disputed)
          return makeChain({
            data: [
              { agent_behavior: 'abandoned', composite_score: 20 },
              { agent_behavior: 'disputed', composite_score: 15 },
            ],
            error: null,
          });
        }

        // 'entities' — return both vouchers as 'confident'
        if (table === 'entities') {
          return makeChain({
            data: [
              {
                id: voucher1Id,
                entity_id: 'voucher-1-slug',
                display_name: 'Voucher 1',
                trust_snapshot: { confidence: 'confident' },
                emilia_score: 92,
                status: 'active',
              },
              {
                id: voucher2Id,
                entity_id: 'voucher-2-slug',
                display_name: 'Voucher 2',
                trust_snapshot: { confidence: 'confident' },
                emilia_score: 88,
                status: 'active',
              },
            ],
            error: null,
          });
        }

        // Final disputes UPDATE (persist)
        if (table === 'disputes') {
          return {
            update: vi.fn().mockReturnThis(),
            eq: vi.fn().mockResolvedValue({ error: null }),
          };
        }

        return makeChain({ data: [], error: null });
      }),
    };

    const result = await adjudicateDispute('ep_dispute_full', mockSupabase);

    expect(result.dispute_id).toBe('ep_dispute_full');
    expect(result.adjudication.recommendation).toBe('uphold_dispute');
    expect(result.adjudication.voucher_count).toBeGreaterThanOrEqual(2);
    expect(result.adjudicated_at).toBeDefined();
    expect(typeof result.adjudicated_at).toBe('string');
  });
});
