/**
 * sybil.js — Final coverage push.
 *
 * Targets uncovered lines:
 *   ~160  analyzeReceiptGraph: cluster check path where submitterIds.length === 0
 *          (submitterIds guard) — this branch is gated by submitterIds.length > 0
 *          so we instead cover the cluster check with exactly 1 submitter (edge)
 *   ~288  runReceiptFraudChecks: cluster_detected flag from graph analysis
 *   ~325-332  runReceiptFraudChecks: retroactive partial-failure console.error +
 *              inner fraud_flag insert inside the partial-failure block
 */

import { vi, describe, it, expect } from 'vitest';
import {
  analyzeReceiptGraph,
  runReceiptFraudChecks,
} from '../lib/sybil.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function buildChain(resolvedValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    gt: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue({ data: null, error: null }),
    then: undefined,
  };
  chain.then = (resolve, reject) =>
    Promise.resolve(resolvedValue).then(resolve, reject);
  return chain;
}

// ── analyzeReceiptGraph: cluster path with empty submitterIds guard ────────────
// The check `if (submitterIds.length > 0)` at line ~153 means when there are
// uniqueSubmitters 2-3 and 20+ receipts but after dedup the set is empty
// that guard won't fire. Let's force submitterIds.length > 0 but have
// intraGroupReceipts exactly at boundary (not flagged).

describe('analyzeReceiptGraph — cluster boundary edge cases', () => {
  it('handles 3 unique submitters with exactly 20 receipts but intra below 80%', async () => {
    // 20 receipts, 3 unique submitters → triggers cluster check
    const data = [
      ...Array(7).fill({ submitted_by: 'A' }),
      ...Array(7).fill({ submitted_by: 'B' }),
      ...Array(6).fill({ submitted_by: 'C' }),
    ];
    let callCount = 0;
    const supabase = {
      from: vi.fn(() => {
        callCount++;
        if (callCount === 1) return buildChain({ data, error: null });
        // intraGroupReceipts = 15, totalReceipts = 20, 15 <= 20*0.8 → no cluster
        return buildChain({ count: 15, data: null, error: null });
      }),
    };
    const result = await analyzeReceiptGraph(supabase, 'entity-3sub');
    expect(result.uniqueSubmitters).toBe(3);
    expect(result.flags).not.toContain('cluster_detected');
  });

  it('flags cluster_detected with 3 unique submitters and intra > 80%', async () => {
    const data = [
      ...Array(7).fill({ submitted_by: 'A' }),
      ...Array(7).fill({ submitted_by: 'B' }),
      ...Array(6).fill({ submitted_by: 'C' }),
    ];
    let callCount = 0;
    const supabase = {
      from: vi.fn(() => {
        callCount++;
        if (callCount === 1) return buildChain({ data, error: null });
        // intraGroupReceipts = 18 > 20 * 0.8 = 16 → cluster_detected
        return buildChain({ count: 18, data: null, error: null });
      }),
    };
    const result = await analyzeReceiptGraph(supabase, 'entity-cluster-3');
    expect(result.flags).toContain('cluster_detected');
  });
});

// ── runReceiptFraudChecks: cluster_detected flag ───────────────────────────────

describe('runReceiptFraudChecks — cluster_detected blocks receipt', () => {
  it('blocks receipt when graph has cluster_detected flag', async () => {
    // Need: no closed loop, no velocity spike, graph has cluster_detected
    // Receipt flow: closed-loop check → no reverse
    //               velocity check → below threshold
    //               analyzeReceiptGraph: 20+ receipts, 2 unique → first call returns submitters
    //                                   second call returns high intra count
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (table === 'receipts' && callCount === 1) {
          // detectClosedLoop — no reverse
          return buildChain({ data: [], error: null });
        }
        if (table === 'receipts' && callCount === 2) {
          // detectVelocitySpike — below 100
          return buildChain({ count: 5, data: null, error: null });
        }
        if (table === 'receipts' && callCount === 3) {
          // analyzeReceiptGraph first call: 22 receipts from 2 submitters
          const data = Array(22).fill(null).map((_, i) => ({
            submitted_by: `sub-${i % 2}`,
          }));
          return buildChain({ data, error: null });
        }
        if (table === 'receipts' && callCount === 4) {
          // analyzeReceiptGraph second call: intra-group count > 80%
          return buildChain({ count: 20, data: null, error: null });
        }
        if (table === 'fraud_flags') {
          return {
            insert: vi.fn().mockResolvedValue({ data: null, error: null }),
          };
        }
        return buildChain({ data: null, error: null });
      }),
    };

    const result = await runReceiptFraudChecks(supabase, 'entity-cl', 'sub-cl');
    expect(result.allowed).toBe(false);
    expect(result.flags).toContain('cluster_detected');
    expect(result.graphWeight).toBeLessThanOrEqual(0.1);
  });
});

// ── runReceiptFraudChecks: retroactive partial failure with inner audit insert ─
// Flow of from() calls when closed_loop detected:
//   from('receipts') #1 → detectClosedLoop (found reverse receipt)
//   from('receipts') #2 → detectVelocitySpike (below threshold)
//   from('receipts') #3 → analyzeReceiptGraph submitters fetch (clean)
//   from('fraud_flags') #4 → main fraud_flags insert (closed_loop flag logged)
//   from('receipts') #5 → retroactivelyApplyGraphWeight fetch (existing receipts)
//   from('receipts') #6 → retroactivelyApplyGraphWeight batch update (FAILS)
//   from('fraud_flags') #7 → retroactive audit trail insert (succeeds)
//   from('fraud_flags') #8 → runReceiptFraudChecks partial failure insert (throws)

describe('runReceiptFraudChecks — retroactive partial failure with audit insert', () => {
  it('succeeds even when inner fraud_flag insert for partial failure throws', async () => {
    let receiptsCallCount = 0;
    let fraudFlagsCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'receipts') {
          receiptsCallCount++;
          if (receiptsCallCount === 1) {
            // detectClosedLoop → found (triggers graphWeight reduction)
            return buildChain({ data: [{ id: 'r1' }], error: null });
          }
          if (receiptsCallCount === 2) {
            // detectVelocitySpike → below threshold
            return buildChain({ count: 5, data: null, error: null });
          }
          if (receiptsCallCount === 3) {
            // analyzeReceiptGraph → clean (no extra flags)
            return buildChain({ data: [], error: null });
          }
          if (receiptsCallCount === 4) {
            // retroactivelyApplyGraphWeight fetch → existing receipts found
            return buildChain({
              data: [{ id: 'old-r1', graph_weight: 1.0 }],
              error: null,
            });
          }
          // receiptsCallCount 5+: batch update FAILS
          return {
            update: vi.fn().mockReturnThis(),
            in: vi
              .fn()
              .mockResolvedValue({ data: null, error: { message: 'batch fail' } }),
          };
        }
        if (table === 'fraud_flags') {
          fraudFlagsCallCount++;
          if (fraudFlagsCallCount === 1) {
            // Main fraud log for closed_loop — succeeds
            return {
              insert: vi.fn().mockResolvedValue({ data: null, error: null }),
            };
          }
          if (fraudFlagsCallCount === 2) {
            // Retroactive audit trail insert (inside retroactivelyApplyGraphWeight) — succeeds
            return {
              insert: vi.fn().mockResolvedValue({ data: null, error: null }),
            };
          }
          // fraudFlagsCallCount 3+: partial failure audit in runReceiptFraudChecks — throws
          return {
            insert: vi.fn().mockRejectedValue(new Error('audit insert failed')),
          };
        }
        return buildChain({ data: null, error: null });
      }),
    };

    const result = await runReceiptFraudChecks(supabase, 'entity-pfx', 'sub-pfx');
    // Must not throw; returns a result even with partial failure
    expect(result).toBeDefined();
    expect(result.flags).toContain('closed_loop');
  });

  it('covers lines 237-260: successful retroactive batch update (updated > 0, failed = 0)', async () => {
    // Closed loop → graphWeight < 1.0 → retroactive runs
    // Fetch returns existing receipts, batch update SUCCEEDS → updated > 0
    // Lines 237-260: audit trail fires and returns { updated, failed }
    let receiptsCallCount = 0;
    let fraudFlagsCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'receipts') {
          receiptsCallCount++;
          if (receiptsCallCount === 1) {
            return buildChain({ data: [{ id: 'r1' }], error: null }); // closed loop found
          }
          if (receiptsCallCount === 2) {
            return buildChain({ count: 5, data: null, error: null }); // velocity ok
          }
          if (receiptsCallCount === 3) {
            return buildChain({ data: [], error: null }); // graph clean
          }
          if (receiptsCallCount === 4) {
            // retroactive fetch → existing receipts with higher weight
            return buildChain({
              data: [{ id: 'old-1', graph_weight: 1.0 }, { id: 'old-2', graph_weight: 0.9 }],
              error: null,
            });
          }
          // receiptsCallCount 5: batch update SUCCEEDS (no error)
          return {
            update: vi.fn().mockReturnThis(),
            in: vi.fn().mockResolvedValue({ data: null, error: null }),
          };
        }
        if (table === 'fraud_flags') {
          fraudFlagsCallCount++;
          return {
            insert: vi.fn().mockResolvedValue({ data: null, error: null }),
          };
        }
        return buildChain({ data: null, error: null });
      }),
    };

    const result = await runReceiptFraudChecks(supabase, 'entity-upd', 'sub-upd');
    expect(result).toBeDefined();
    expect(result.flags).toContain('closed_loop');
    // graphWeight = 0.4 (closed loop), no partial failure
    expect(result.graphWeight).toBeCloseTo(0.4);
  });
});

// ── runReceiptFraudChecks: retroactive fetch error path ──────────────────────

describe('runReceiptFraudChecks — retroactive fetch throws', () => {
  it('handles fetch error in retroactivelyApplyGraphWeight (returns updated:0 failed:-1)', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (table === 'receipts') {
          if (callCount === 1) return buildChain({ data: [{ id: 'r1' }], error: null }); // closed loop
          if (callCount === 2) return buildChain({ count: 5, data: null, error: null }); // velocity ok
          if (callCount === 3) return buildChain({ data: [], error: null }); // graph clean
          // callCount 4: retroactive fetch THROWS
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            gt: vi.fn().mockRejectedValue(new Error('db connection lost')),
          };
        }
        if (table === 'fraud_flags') {
          return {
            insert: vi.fn().mockResolvedValue({ data: null, error: null }),
          };
        }
        return buildChain({ data: null, error: null });
      }),
    };

    const result = await runReceiptFraudChecks(supabase, 'entity-fe', 'sub-fe');
    expect(result).toBeDefined();
    // graphWeight < 1 due to closed loop; retroactive failed silently
    expect(result.graphWeight).toBeCloseTo(0.4);
  });
});
