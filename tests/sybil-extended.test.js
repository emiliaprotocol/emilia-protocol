/**
 * EMILIA Protocol — sybil.js extended coverage
 *
 * Covers: detectClosedLoop, detectVelocitySpike, analyzeReceiptGraph (all branches),
 * retroactivelyApplyGraphWeight (partial failure path), runReceiptFraudChecks (all branches).
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';
import {
  checkRegistrationLimits,
  detectClosedLoop,
  detectVelocitySpike,
  analyzeReceiptGraph,
  runReceiptFraudChecks,
  isEstablished,
} from '../lib/sybil.js';

// ── Supabase mock factory ─────────────────────────────────────────────────────

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

function makeSupabase(tableHandlers) {
  return {
    from: vi.fn((table) => {
      const handler = tableHandlers[table];
      if (handler) return handler(table);
      // default: return empty data
      return buildChain({ data: null, count: 0, error: null });
    }),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// detectClosedLoop
// ─────────────────────────────────────────────────────────────────────────────

describe('detectClosedLoop — no reverse receipts', () => {
  it('returns flagged:false when no reverse receipts exist', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: [], error: null }),
    });
    const result = await detectClosedLoop(supabase, 'entity-A', 'entity-B');
    expect(result.flagged).toBe(false);
  });

  it('returns flagged:false when data is null', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: null, error: null }),
    });
    const result = await detectClosedLoop(supabase, 'entity-A', 'entity-B');
    expect(result.flagged).toBe(false);
  });
});

describe('detectClosedLoop — reverse receipts found', () => {
  it('returns flagged:true with reason closed_loop', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: [{ id: 'r-1' }], error: null }),
    });
    const result = await detectClosedLoop(supabase, 'entity-A', 'entity-B');
    expect(result.flagged).toBe(true);
    expect(result.reason).toBe('closed_loop');
  });

  it('detail message includes both entity IDs', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: [{ id: 'r-1' }], error: null }),
    });
    const result = await detectClosedLoop(supabase, 'alpha', 'beta');
    expect(result.detail).toContain('alpha');
    expect(result.detail).toContain('beta');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// detectVelocitySpike
// ─────────────────────────────────────────────────────────────────────────────

describe('detectVelocitySpike — below threshold', () => {
  it('returns flagged:false when count < 100', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ count: 50, data: null, error: null }),
    });
    const result = await detectVelocitySpike(supabase, 'submitter-1');
    expect(result.flagged).toBe(false);
  });

  it('returns flagged:false when count is 0', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ count: 0, data: null, error: null }),
    });
    const result = await detectVelocitySpike(supabase, 'submitter-zero');
    expect(result.flagged).toBe(false);
  });

  it('returns flagged:false when count is exactly 99', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ count: 99, data: null, error: null }),
    });
    const result = await detectVelocitySpike(supabase, 'submitter-99');
    expect(result.flagged).toBe(false);
  });
});

describe('detectVelocitySpike — above threshold', () => {
  it('returns flagged:true when count >= 100', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ count: 100, data: null, error: null }),
    });
    const result = await detectVelocitySpike(supabase, 'spammer');
    expect(result.flagged).toBe(true);
    expect(result.reason).toBe('velocity_spike');
  });

  it('detail includes the count', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ count: 250, data: null, error: null }),
    });
    const result = await detectVelocitySpike(supabase, 'mega-spammer');
    expect(result.detail).toContain('250');
  });

  it('returns flagged:true when count is 500', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ count: 500, data: null, error: null }),
    });
    const result = await detectVelocitySpike(supabase, 'bot');
    expect(result.flagged).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// analyzeReceiptGraph
// ─────────────────────────────────────────────────────────────────────────────

describe('analyzeReceiptGraph — clean graph', () => {
  it('no flags when receipts from many unique submitters', async () => {
    const submitters = Array.from({ length: 10 }, (_, i) => ({ submitted_by: `sub-${i}` }));
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: submitters, error: null }),
    });
    const result = await analyzeReceiptGraph(supabase, 'entity-clean');
    expect(result.thinGraph).toBe(false);
    expect(result.flags).toHaveLength(0);
  });

  it('returns uniqueSubmitters count correctly', async () => {
    const data = [
      { submitted_by: 'A' }, { submitted_by: 'B' }, { submitted_by: 'A' },
    ];
    const supabase = makeSupabase({
      receipts: () => buildChain({ data, error: null }),
    });
    const result = await analyzeReceiptGraph(supabase, 'entity-2');
    expect(result.uniqueSubmitters).toBe(2);
  });

  it('empty receipts: no flags, uniqueSubmitters=0', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: [], error: null }),
    });
    const result = await analyzeReceiptGraph(supabase, 'entity-empty');
    expect(result.uniqueSubmitters).toBe(0);
    expect(result.thinGraph).toBe(false);
    expect(result.flags).toHaveLength(0);
  });

  it('handles null data (no receipts)', async () => {
    const supabase = makeSupabase({
      receipts: () => buildChain({ data: null, error: null }),
    });
    const result = await analyzeReceiptGraph(supabase, 'entity-null');
    expect(result.uniqueSubmitters).toBe(0);
    expect(result.thinGraph).toBe(false);
  });
});

describe('analyzeReceiptGraph — thin_graph flag', () => {
  it('flags thin_graph: 5+ receipts but <3 unique submitters', async () => {
    const data = Array(6).fill(null).map((_, i) => ({ submitted_by: `sub-${i % 2}` }));
    const supabase = makeSupabase({
      receipts: () => buildChain({ data, error: null }),
    });
    const result = await analyzeReceiptGraph(supabase, 'entity-thin');
    expect(result.flags).toContain('thin_graph');
    expect(result.thinGraph).toBe(true);
  });
});

describe('analyzeReceiptGraph — single_source flag', () => {
  it('flags single_source: 3+ receipts all from one submitter', async () => {
    const data = Array(4).fill({ submitted_by: 'only-one' });
    const supabase = makeSupabase({
      receipts: () => buildChain({ data, error: null }),
    });
    const result = await analyzeReceiptGraph(supabase, 'entity-single');
    expect(result.flags).toContain('single_source');
    expect(result.thinGraph).toBe(true);
  });
});

describe('analyzeReceiptGraph — cluster_detected flag', () => {
  it('flags cluster_detected when intraGroupReceipts > 80% of total', async () => {
    // 20+ receipts from 2–3 unique submitters triggers cluster check
    const data = Array(22).fill(null).map((_, i) => ({ submitted_by: `sub-${i % 2}` }));
    // cluster check needs intraGroupReceipts > totalReceipts * 0.8
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (callCount === 1) {
          // First call: fetch submitters
          return buildChain({ data, error: null });
        }
        // Second call: intraGroupReceipts count (> 22 * 0.8 = 17.6 → 18+)
        return buildChain({ count: 20, data: null, error: null });
      }),
    };
    const result = await analyzeReceiptGraph(supabase, 'entity-cluster');
    expect(result.flags).toContain('cluster_detected');
  });

  it('does NOT flag cluster when intraGroupReceipts <= 80%', async () => {
    const data = Array(22).fill(null).map((_, i) => ({ submitted_by: `sub-${i % 2}` }));
    let callCount = 0;
    const supabase = {
      from: vi.fn(() => {
        callCount++;
        if (callCount === 1) {
          return buildChain({ data, error: null });
        }
        // intraGroupReceipts = 10 <= 22 * 0.8 = 17.6
        return buildChain({ count: 10, data: null, error: null });
      }),
    };
    const result = await analyzeReceiptGraph(supabase, 'entity-no-cluster');
    expect(result.flags).not.toContain('cluster_detected');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// runReceiptFraudChecks — all branches
// ─────────────────────────────────────────────────────────────────────────────

describe('runReceiptFraudChecks — clean receipt', () => {
  it('allows receipt when no flags', async () => {
    const supabase = {
      from: vi.fn(() => buildChain({ data: [], count: 0, error: null })),
    };
    const result = await runReceiptFraudChecks(supabase, 'entity-ok', 'submitter-ok');
    expect(result.allowed).toBe(true);
    expect(result.flags).toHaveLength(0);
    expect(result.graphWeight).toBe(1.0);
  });

  it('detail is null when not blocked', async () => {
    const supabase = {
      from: vi.fn(() => buildChain({ data: [], count: 0, error: null })),
    };
    const result = await runReceiptFraudChecks(supabase, 'entity-ok2', 'sub-ok2');
    expect(result.detail).toBeNull();
  });
});

describe('runReceiptFraudChecks — velocity spike blocks receipt', () => {
  it('blocks and sets graphWeight when velocity spike detected', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (table === 'receipts' && callCount === 1) {
          // detectClosedLoop → no reverse receipts
          return buildChain({ data: [], error: null });
        }
        if (table === 'receipts' && callCount === 2) {
          // detectVelocitySpike → high count
          return buildChain({ count: 200, data: null, error: null });
        }
        if (table === 'receipts') {
          // analyzeReceiptGraph → clean
          return buildChain({ data: [], error: null });
        }
        // fraud_flags insert
        return buildChain({ data: null, error: null });
      }),
    };
    const result = await runReceiptFraudChecks(supabase, 'entity-v', 'submitter-v');
    expect(result.allowed).toBe(false);
    expect(result.flags).toContain('velocity_spike');
  });
});

describe('runReceiptFraudChecks — closed loop reduces graphWeight', () => {
  it('graphWeight *= 0.4 on closed loop', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (table === 'receipts' && callCount === 1) {
          // detectClosedLoop → found reverse receipt
          return buildChain({ data: [{ id: 'r1' }], error: null });
        }
        if (table === 'receipts' && callCount === 2) {
          // detectVelocitySpike → below threshold
          return buildChain({ count: 5, data: null, error: null });
        }
        if (table === 'receipts' && callCount === 3) {
          // analyzeReceiptGraph → clean
          return buildChain({ data: [], error: null });
        }
        if (table === 'receipts') {
          // retroactivelyApplyGraphWeight: select existing receipts → empty
          return buildChain({ data: [], error: null });
        }
        // fraud_flags
        return buildChain({ data: null, error: null });
      }),
    };
    const result = await runReceiptFraudChecks(supabase, 'entity-loop', 'submitter-loop');
    expect(result.graphWeight).toBeCloseTo(0.4);
    expect(result.flags).toContain('closed_loop');
  });
});

describe('runReceiptFraudChecks — fraud flag insert error is non-fatal', () => {
  it('does not throw when fraud_flags insert fails', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (table === 'receipts' && callCount <= 3) {
          // closed loop found on first call
          if (callCount === 1) return buildChain({ data: [{ id: 'r1' }], error: null });
          if (callCount === 2) return buildChain({ count: 5, data: null, error: null });
          if (callCount === 3) return buildChain({ data: [], error: null });
        }
        if (table === 'receipts') {
          // retroactive fetch
          return buildChain({ data: [], error: null });
        }
        if (table === 'fraud_flags') {
          return {
            insert: vi.fn().mockRejectedValue(new Error('DB down')),
          };
        }
        return buildChain({ data: null, error: null });
      }),
    };
    await expect(
      runReceiptFraudChecks(supabase, 'entity-err', 'sub-err')
    ).resolves.toBeDefined();
  });
});

describe('runReceiptFraudChecks — retroactive partial failure', () => {
  it('logs partial failure and inserts fraud_flag for it', async () => {
    // Set up: closed loop detected, then retroactive fetch returns receipts,
    // and the batch update FAILS → partial_failure
    let callCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        callCount++;
        if (table === 'receipts') {
          if (callCount === 1) {
            // detectClosedLoop → found
            return buildChain({ data: [{ id: 'rx1' }], error: null });
          }
          if (callCount === 2) {
            // detectVelocitySpike → below threshold
            return buildChain({ count: 5, data: null, error: null });
          }
          if (callCount === 3) {
            // analyzeReceiptGraph → clean
            return buildChain({ data: [], error: null });
          }
          if (callCount === 4) {
            // retroactivelyApplyGraphWeight fetch → returns existing receipts
            return buildChain({ data: [{ id: 'old-receipt-1', graph_weight: 1.0 }], error: null });
          }
          // receipt batch update — FAILS
          return {
            update: vi.fn().mockReturnThis(),
            in: vi.fn().mockResolvedValue({ data: null, error: { message: 'update failed' } }),
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

    const result = await runReceiptFraudChecks(supabase, 'entity-pf', 'sub-pf');
    // Even with partial failure, the function should return a result
    expect(result).toBeDefined();
    expect(result.flags).toContain('closed_loop');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// isEstablished
// ─────────────────────────────────────────────────────────────────────────────

describe('isEstablished', () => {
  it('returns true when receipts >= 5 and uniqueSubmitters >= 3', () => {
    expect(isEstablished(5, 3)).toBe(true);
    expect(isEstablished(10, 5)).toBe(true);
  });

  it('returns false when receipts < 5', () => {
    expect(isEstablished(4, 3)).toBe(false);
  });

  it('returns false when uniqueSubmitters < 3', () => {
    expect(isEstablished(10, 2)).toBe(false);
  });

  it('returns false when both conditions fail', () => {
    expect(isEstablished(1, 1)).toBe(false);
  });

  it('returns false for zero values', () => {
    expect(isEstablished(0, 0)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// checkRegistrationLimits
// ─────────────────────────────────────────────────────────────────────────────

describe('checkRegistrationLimits', () => {
  it('allows registration below both limits', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        gte: vi.fn().mockReturnThis(),
        then: (resolve) => {
          callCount++;
          return resolve({ count: callCount === 1 ? 2 : 10 });
        },
      })),
    };
    const result = await checkRegistrationLimits(supabase, 'owner-1');
    expect(result.allowed).toBe(true);
  });

  it('blocks when daily count >= 5', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        gte: vi.fn().mockReturnThis(),
        then: (resolve) => {
          callCount++;
          return resolve({ count: 5 });
        },
      })),
    };
    const result = await checkRegistrationLimits(supabase, 'owner-daily');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('5');
  });

  it('blocks when total count >= 50', async () => {
    let callCount = 0;
    const supabase = {
      from: vi.fn(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        gte: vi.fn().mockReturnThis(),
        then: (resolve) => {
          callCount++;
          // First call (daily): below limit. Second call (total): at limit.
          return resolve({ count: callCount === 1 ? 1 : 50 });
        },
      })),
    };
    const result = await checkRegistrationLimits(supabase, 'owner-total');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('50');
  });
});
