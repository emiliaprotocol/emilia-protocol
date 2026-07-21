import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock supabase before importing the module under test
vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(),
}));

import { getDomainScores } from '../lib/domain-scoring.js';
import { getServiceClient } from '@/lib/supabase';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSupabaseMock(data, error = null) {
  const query = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    not: vi.fn().mockResolvedValue({ data, error }),
  };
  return { from: vi.fn(() => query), _query: query };
}

function makeReceipt(overrides = {}) {
  return {
    id: overrides.id || 'r-1',
    agent_behavior: overrides.agent_behavior || 'completed',
    graph_weight: overrides.graph_weight ?? 1.0,
    provenance_tier: overrides.provenance_tier || 'bilateral',
    context: overrides.context || null,
    created_at: overrides.created_at || new Date().toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('getDomainScores', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // === Empty / error cases ================================================

  it('returns empty domains when supabase returns an error', async () => {
    const mock = makeSupabaseMock(null, { message: 'db down' });
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.entity_id).toBe('entity-1');
    expect(result.domains).toEqual({});
  });

  it('returns empty domains when there are no receipts', async () => {
    const mock = makeSupabaseMock([]);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.entity_id).toBe('entity-1');
    expect(result.domains).toEqual({});
  });

  it('returns empty domains when receipts is null', async () => {
    const mock = makeSupabaseMock(null);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.entity_id).toBe('entity-1');
    expect(result.domains).toEqual({});
  });

  // === Single-domain scoring ==============================================

  it('computes scores for a single domain with completed receipts', async () => {
    const receipts = Array(10).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        agent_behavior: 'completed',
        provenance_tier: 'bilateral',
        graph_weight: 1.0,
        context: { task_type: 'financial' },
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial).toBeDefined();
    expect(result.domains.financial.evidence_count).toBe(10);
    expect(result.domains.financial.completion_rate).toBe(100);
    expect(result.domains.financial.dispute_rate).toBe(0);
  });

  it('computes correct completion_rate and dispute_rate', async () => {
    const receipts = [
      makeReceipt({ agent_behavior: 'completed', context: { task_type: 'code_execution' } }),
      makeReceipt({ agent_behavior: 'completed', context: { task_type: 'code_execution' } }),
      makeReceipt({ agent_behavior: 'disputed', context: { task_type: 'code_execution' } }),
      makeReceipt({ agent_behavior: 'abandoned', context: { task_type: 'code_execution' } }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.code_execution.evidence_count).toBe(4);
    expect(result.domains.code_execution.completion_rate).toBe(50); // 2/4
    expect(result.domains.code_execution.dispute_rate).toBe(25);    // 1/4
  });

  // === Domain filtering ===================================================

  it('only returns requested domains when domains param is provided', async () => {
    const receipts = [
      makeReceipt({ context: { task_type: 'financial' } }),
      makeReceipt({ context: { task_type: 'code_execution' } }),
      makeReceipt({ context: { task_type: 'communication' } }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['financial']);

    expect(result.domains.financial).toBeDefined();
    expect(result.domains.code_execution).toBeUndefined();
    expect(result.domains.communication).toBeUndefined();
  });

  it('skips domains with zero receipts', async () => {
    const receipts = [
      makeReceipt({ context: { task_type: 'financial' } }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial).toBeDefined();
    expect(result.domains.code_execution).toBeUndefined();
    expect(result.domains.infrastructure).toBeUndefined();
  });

  // === Receipts with no task_type / unknown domains =======================

  it('ignores receipts with no context', async () => {
    const receipts = [
      makeReceipt({ context: null }),
      makeReceipt({ context: {} }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains).toEqual({});
  });

  it('ignores receipts with unknown task_type', async () => {
    const receipts = [
      makeReceipt({ context: { task_type: 'unknown_domain' } }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains).toEqual({});
  });

  // === Confidence levels ==================================================

  it('assigns "pending" confidence for very low effective evidence', async () => {
    // 1 completed receipt with bilateral provenance: 1.0 * 1.0 * 1.0 = 1.0 effective
    const receipts = [
      makeReceipt({ context: { task_type: 'financial' }, provenance_tier: 'bilateral' }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial.confidence).toBe('pending');
  });

  it('assigns "low" confidence for effective evidence >= 5', async () => {
    // 5 completed bilateral receipts: 5 * 1.0 * 1.0 * 1.0 = 5.0
    const receipts = Array(5).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial.confidence).toBe('low');
  });

  it('assigns "moderate" confidence for effective evidence >= 15', async () => {
    const receipts = Array(15).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial.confidence).toBe('moderate');
  });

  it('assigns "high" confidence for effective evidence >= 40', async () => {
    const receipts = Array(40).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial.confidence).toBe('high');
  });

  it('assigns "established" confidence for effective evidence >= 100', async () => {
    const receipts = Array(100).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial.confidence).toBe('established');
  });

  // === Provenance weights =================================================

  it('provenance_tier affects effective_evidence', async () => {
    const unilateralReceipts = Array(10).fill(null).map((_, i) =>
      makeReceipt({
        id: `u-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'unilateral', // weight 0.6
      })
    );
    const verifiedReceipts = Array(10).fill(null).map((_, i) =>
      makeReceipt({
        id: `v-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'verified', // weight 1.3
      })
    );

    const uniMock = makeSupabaseMock(unilateralReceipts);
    getServiceClient.mockReturnValue(uniMock);
    const uniResult = await getDomainScores('entity-1', ['financial']);

    const verMock = makeSupabaseMock(verifiedReceipts);
    getServiceClient.mockReturnValue(verMock);
    const verResult = await getDomainScores('entity-1', ['financial']);

    expect(verResult.domains.financial.effective_evidence)
      .toBeGreaterThan(uniResult.domains.financial.effective_evidence);
  });

  it('unknown provenance_tier defaults to 0.6 weight', async () => {
    const receipts = Array(10).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        context: { task_type: 'financial' },
        provenance_tier: 'some_future_tier',
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['financial']);

    // 10 * 1.0 * 0.6 * 1.0 = 6.0
    expect(result.domains.financial.effective_evidence).toBe(6);
  });

  // === Behavior weights ===================================================

  it('disputed receipts contribute 0.0 behavior weight', async () => {
    const receipts = Array(5).fill(null).map((_, i) =>
      makeReceipt({
        id: `r-${i}`,
        agent_behavior: 'disputed',
        context: { task_type: 'delegation' },
        provenance_tier: 'bilateral',
      })
    );
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['delegation']);

    expect(result.domains.delegation.effective_evidence).toBe(0);
  });

  it('abandoned receipts contribute 0.1 behavior weight', async () => {
    const receipts = [
      makeReceipt({
        agent_behavior: 'abandoned',
        context: { task_type: 'delegation' },
        provenance_tier: 'bilateral',
        graph_weight: 1.0,
      }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['delegation']);

    // 1.0 * 1.0 * 0.1 = 0.1
    expect(result.domains.delegation.effective_evidence).toBe(0.1);
  });

  it('unknown behavior defaults to 0.5 weight', async () => {
    const receipts = [
      makeReceipt({
        agent_behavior: 'some_future_behavior',
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
        graph_weight: 1.0,
      }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['financial']);

    // 1.0 * 1.0 * 0.5 = 0.5
    expect(result.domains.financial.effective_evidence).toBe(0.5);
  });

  // === graph_weight =======================================================

  it('graph_weight scales effective evidence', async () => {
    const receipts = [
      makeReceipt({
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
        graph_weight: 0.5,
      }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['financial']);

    // 0.5 * 1.0 * 1.0 = 0.5
    expect(result.domains.financial.effective_evidence).toBe(0.5);
  });

  it('null graph_weight defaults to 1.0', async () => {
    const receipts = [
      makeReceipt({
        context: { task_type: 'financial' },
        provenance_tier: 'bilateral',
        graph_weight: null,
      }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['financial']);

    // 1.0 * 1.0 * 1.0 = 1.0
    expect(result.domains.financial.effective_evidence).toBe(1);
  });

  // === Multi-domain =======================================================

  it('correctly separates receipts across multiple domains', async () => {
    const receipts = [
      makeReceipt({ context: { task_type: 'financial' } }),
      makeReceipt({ context: { task_type: 'financial' } }),
      makeReceipt({ context: { task_type: 'code_execution' } }),
      makeReceipt({ context: { task_type: 'communication' } }),
      makeReceipt({ context: { task_type: 'communication' } }),
      makeReceipt({ context: { task_type: 'communication' } }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1');

    expect(result.domains.financial.evidence_count).toBe(2);
    expect(result.domains.code_execution.evidence_count).toBe(1);
    expect(result.domains.communication.evidence_count).toBe(3);
  });

  // === Rounding ===========================================================

  it('effective_evidence is rounded to 2 decimal places', async () => {
    const receipts = [
      makeReceipt({
        context: { task_type: 'financial' },
        provenance_tier: 'verified', // 1.3
        graph_weight: 0.33,          // 0.33 * 1.3 * 1.0 = 0.429
      }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    const result = await getDomainScores('entity-1', ['financial']);

    const ee = result.domains.financial.effective_evidence;
    const decimals = ee.toString().split('.')[1];
    expect(!decimals || decimals.length <= 2).toBe(true);
  });

  // === Empty domains param ================================================

  it('empty array for domains computes all known domains', async () => {
    const receipts = [
      makeReceipt({ context: { task_type: 'financial' } }),
      makeReceipt({ context: { task_type: 'data_access' } }),
    ];
    const mock = makeSupabaseMock(receipts);
    getServiceClient.mockReturnValue(mock);

    // Empty array should fall through to KNOWN_DOMAINS
    const result = await getDomainScores('entity-1', []);

    expect(result.domains.financial).toBeDefined();
    expect(result.domains.data_access).toBeDefined();
  });
});
