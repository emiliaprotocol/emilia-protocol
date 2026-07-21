import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkAbuse, ABUSE_PATTERNS } from '../lib/procedural-justice.js';

// ============================================================================
// Abuse detection tests — verifies checkAbuse queries trust_reports for reports
// ============================================================================

/**
 * Build a mock Supabase client that tracks which table/columns are queried.
 * Returns configurable count or data results.
 */
function mockSupabase({ count = 0, data = [] } = {}) {
  const queries = [];

  const chainable = (tableName) => {
    const query = { table: tableName, filters: {} };
    queries.push(query);

    const chain = {
      select: (cols, opts) => {
        query.selectCols = cols;
        query.selectOpts = opts;
        // If head:true (count query), resolve with { count }
        if (opts?.head) {
          query.isCount = true;
        }
        return chain;
      },
      eq: (col, val) => {
        query.filters[col] = val;
        return chain;
      },
      gte: (col, val) => {
        query.filters[`${col}__gte`] = val;
        return chain;
      },
      in: (col, vals) => {
        query.filters[`${col}__in`] = vals;
        return chain;
      },
      limit: (n) => {
        query.limit = n;
        return chain;
      },
      single: () => {
        return { data: data[0] || null };
      },
      then: (resolve) => {
        if (query.isCount) {
          resolve({ count, data: null });
        } else {
          resolve({ data, count: data.length });
        }
      },
    };

    // Make chain thenable so await works
    chain[Symbol.toStringTag] = 'Promise';

    return chain;
  };

  const client = {
    from: (tableName) => chainable(tableName),
    _queries: queries,
  };

  return client;
}

// ============================================================================
// 1. Report abuse detection queries trust_reports, not disputes
// ============================================================================

describe('checkAbuse for reports', () => {
  it('queries trust_reports table (not disputes) for report abuse checks', async () => {
    const supabase = mockSupabase({ count: 0 });

    await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    // All queries should target trust_reports, never disputes
    const tables = supabase._queries.map(q => q.table);
    expect(tables).not.toContain('disputes');
    expect(tables).toContain('trust_reports');
  });

  it('uses report_type filter (not reason) when checking trust_reports', async () => {
    const supabase = mockSupabase({ count: 0 });

    await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    // The first query should filter on report_type
    const firstQuery = supabase._queries[0];
    expect(firstQuery.filters).toHaveProperty('report_type', 'fraudulent_entity');
    expect(firstQuery.filters).not.toHaveProperty('reason');
  });

  it('does not use reporter_ip column (trust_reports does not have it)', async () => {
    const supabase = mockSupabase({ count: 0 });

    await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    for (const query of supabase._queries) {
      expect(query.filters).not.toHaveProperty('reporter_ip');
    }
  });

  it('uses reporter_ip_hash for IP-based throttling', async () => {
    const supabase = mockSupabase({ count: 0 });

    await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    // One of the queries should filter on reporter_ip_hash
    const ipHashQuery = supabase._queries.find(q => q.filters.reporter_ip_hash);
    expect(ipHashQuery).toBeDefined();
    expect(ipHashQuery.filters.reporter_ip_hash).toBe('abcdef1234567890');
  });
});

// ============================================================================
// 2. Throttling thresholds
// ============================================================================

describe('checkAbuse throttling thresholds for reports', () => {
  it('allows reports under the repeated_identical_reports threshold', async () => {
    const supabase = mockSupabase({ count: ABUSE_PATTERNS.repeated_identical_reports.threshold - 1 });

    const result = await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    expect(result.allowed).toBe(true);
  });

  it('blocks when repeated_identical_reports threshold is met', async () => {
    const supabase = mockSupabase({ count: ABUSE_PATTERNS.repeated_identical_reports.threshold });

    const result = await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('repeated_identical_reports');
    expect(result.action).toBe('rate_limit');
  });

  it('blocks when brigading threshold is met', async () => {
    // First query (repeated_identical_reports) returns under threshold,
    // second query (brigading) returns at threshold
    let callCount = 0;
    const supabase = {
      from: (table) => {
        const query = {
          select: () => query,
          eq: () => query,
          gte: () => query,
          then: (resolve) => {
            callCount++;
            // First call: under repeated threshold; second call: at brigading threshold
            const count = callCount === 1
              ? ABUSE_PATTERNS.repeated_identical_reports.threshold - 1
              : ABUSE_PATTERNS.brigading.threshold;
            resolve({ count, data: null });
          },
        };
        query[Symbol.toStringTag] = 'Promise';
        return query;
      },
    };

    const result = await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('brigading');
    expect(result.action).toBe('flag_for_review');
  });
});

// ============================================================================
// 3. IP hash throttling
// ============================================================================

describe('checkAbuse IP hash flooding for reports', () => {
  it('blocks when IP hash flooding threshold is met', async () => {
    // First two queries (repeated + brigading) under threshold, third (IP flooding) at threshold
    let callCount = 0;
    const supabase = {
      from: (table) => {
        const query = {
          select: () => query,
          eq: () => query,
          gte: () => query,
          then: (resolve) => {
            callCount++;
            const count = callCount <= 2 ? 0 : ABUSE_PATTERNS.ip_report_flooding.threshold;
            resolve({ count, data: null });
          },
        };
        query[Symbol.toStringTag] = 'Promise';
        return query;
      },
    };

    const result = await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      reporter_ip_hash: 'abcdef1234567890',
    });

    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('ip_report_flooding');
    expect(result.action).toBe('rate_limit');
  });

  it('skips IP hash check when reporter_ip_hash is not provided', async () => {
    const supabase = mockSupabase({ count: 0 });

    const result = await checkAbuse(supabase, 'report', {
      entity_id: 'entity-123',
      report_type: 'fraudulent_entity',
      // no reporter_ip_hash
    });

    expect(result.allowed).toBe(true);
    // Should not query for reporter_ip_hash
    const ipHashQuery = supabase._queries.find(q => q.filters.reporter_ip_hash);
    expect(ipHashQuery).toBeUndefined();
  });
});

// ============================================================================
// 4. Dispute abuse detection still works (regression)
// ============================================================================

describe('checkAbuse for disputes (regression)', () => {
  it('still queries disputes table for dispute type', async () => {
    const supabase = mockSupabase({ count: 0 });

    await checkAbuse(supabase, 'dispute', {
      filer_entity_id: 'entity-A',
      target_entity_id: 'entity-B',
    });

    const tables = supabase._queries.map(q => q.table);
    expect(tables).toContain('disputes');
    expect(tables).not.toContain('trust_reports');
  });

  it('allows disputes when under threshold', async () => {
    const supabase = mockSupabase({ count: 0 });

    const result = await checkAbuse(supabase, 'dispute', {
      filer_entity_id: 'entity-A',
      target_entity_id: 'entity-B',
    });

    expect(result.allowed).toBe(true);
  });
});

// ============================================================================
// 5. ABUSE_PATTERNS configuration
// ============================================================================

describe('ABUSE_PATTERNS configuration', () => {
  it('has ip_report_flooding pattern defined', () => {
    expect(ABUSE_PATTERNS.ip_report_flooding).toBeDefined();
    expect(ABUSE_PATTERNS.ip_report_flooding.threshold).toBeGreaterThan(0);
    expect(ABUSE_PATTERNS.ip_report_flooding.action).toBe('rate_limit');
  });

  it('repeated_identical_reports references trust_reports not disputes', () => {
    expect(ABUSE_PATTERNS.repeated_identical_reports.detection).toContain('trust_reports');
  });

  it('brigading references trust_reports not disputes', () => {
    expect(ABUSE_PATTERNS.brigading.detection).toContain('trust_reports');
  });
});
