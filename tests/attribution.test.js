import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  buildAttributionChain,
  applyAttributionChain,
  getDelegationJudgmentScore,
} from '../lib/attribution.js';

// ============================================================================
// Supabase mock helpers
// ============================================================================

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(),
}));

/**
 * makeChain builds a fluent Supabase query builder mock.
 */
function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ============================================================================
// buildAttributionChain
// ============================================================================

describe('buildAttributionChain', () => {
  it('returns [agent] when no delegation_id is present', () => {
    const receipt = {
      entity_id: 'agent-entity-1',
      agent_behavior: 'completed',
      composite_score: 90,
    };
    const chain = buildAttributionChain(receipt);

    expect(chain).toHaveLength(1);
    expect(chain[0].role).toBe('agent');
    expect(chain[0].entity_id).toBe('agent-entity-1');
  });

  it('returns [agent] only when delegation_id present but no principal_id in context', () => {
    const receipt = {
      entity_id: 'agent-entity-2',
      delegation_id: 'deleg_abc123',
      context: {}, // no principal_id
    };
    const chain = buildAttributionChain(receipt);

    expect(chain).toHaveLength(1);
    expect(chain[0].role).toBe('agent');
  });

  it('returns [agent, principal] when delegation_id AND context.principal_id are present', () => {
    const receipt = {
      entity_id: 'agent-entity-3',
      delegation_id: 'deleg_xyz789',
      context: { principal_id: 'human-principal-1' },
    };
    const chain = buildAttributionChain(receipt);

    expect(chain).toHaveLength(2);
    expect(chain[0].role).toBe('agent');
    expect(chain[1].role).toBe('principal');
    expect(chain[1].entity_id).toBe('human-principal-1');
  });

  it('agent weight is 1.0 (full attribution)', () => {
    const receipt = { entity_id: 'agent-entity-4' };
    const chain = buildAttributionChain(receipt);

    expect(chain[0].weight).toBe(1.0);
  });

  it('principal weight is 0.15 (weak delegation authority signal)', () => {
    const receipt = {
      entity_id: 'agent-entity-5',
      delegation_id: 'deleg_001',
      context: { principal_id: 'human-principal-2' },
    };
    const chain = buildAttributionChain(receipt);

    const principal = chain.find(e => e.role === 'principal');
    expect(principal.weight).toBe(0.15);
  });

  it('principal entry includes delegation_id for traceability', () => {
    const receipt = {
      entity_id: 'agent-entity-6',
      delegation_id: 'deleg_trace_001',
      context: { principal_id: 'human-principal-3' },
    };
    const chain = buildAttributionChain(receipt);

    const principal = chain.find(e => e.role === 'principal');
    expect(principal.delegation_id).toBe('deleg_trace_001');
  });

  it('returns [agent] only when principal_id exists but delegation_id is absent', () => {
    // A bare context.principal_id with no delegation_id is not sufficient to
    // create principal accountability — anyone could claim they acted on behalf
    // of someone. The delegation record is the proof.
    const receipt = {
      entity_id: 'agent-entity-7',
      // No delegation_id
      context: { principal_id: 'claimed-principal' },
    };
    const chain = buildAttributionChain(receipt);

    expect(chain).toHaveLength(1);
    expect(chain[0].role).toBe('agent');
  });

  it('handles null context gracefully', () => {
    const receipt = {
      entity_id: 'agent-entity-8',
      delegation_id: 'deleg_002',
      context: null,
    };
    const chain = buildAttributionChain(receipt);
    // context is null → no principal_id → chain has only agent
    expect(chain).toHaveLength(1);
    expect(chain[0].role).toBe('agent');
  });
});

// ============================================================================
// getDelegationJudgmentScore
// ============================================================================

describe('getDelegationJudgmentScore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns judgment_score 1.0 when all agents have excellent (positive) outcomes', async () => {
    const signals = [
      { agent_entity_id: 'agent-a', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-b', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-c', outcome_positive: true,  weight: 0.15 },
    ];
    const mockSupabase = {
      from: vi.fn(() => makeChain({ data: signals, error: null })),
    };

    const result = await getDelegationJudgmentScore('principal-1', mockSupabase);

    expect(result.judgment_score).toBe(1.0);
    expect(result.good_outcome_rate).toBe(1.0);
    expect(result.positive_signals).toBe(3);
    expect(result.negative_signals).toBe(0);
  });

  it('returns judgment_score 0.0 when all agents have poor (negative) outcomes', async () => {
    const signals = [
      { agent_entity_id: 'agent-x', outcome_positive: false, weight: 0.15 },
      { agent_entity_id: 'agent-y', outcome_positive: false, weight: 0.15 },
    ];
    const mockSupabase = {
      from: vi.fn(() => makeChain({ data: signals, error: null })),
    };

    const result = await getDelegationJudgmentScore('principal-2', mockSupabase);

    expect(result.judgment_score).toBe(0);
    expect(result.good_outcome_rate).toBe(0);
    expect(result.positive_signals).toBe(0);
    expect(result.negative_signals).toBe(2);
  });

  it('returns null judgment_score when principal has no delegation signals', async () => {
    const mockSupabase = {
      from: vi.fn(() => makeChain({ data: [], error: null })),
    };

    const result = await getDelegationJudgmentScore('principal-no-agents', mockSupabase);

    expect(result.judgment_score).toBeNull();
    expect(result.agents_authorized).toBe(0);
    expect(result.good_outcome_rate).toBeNull();
    expect(result.total_signals).toBe(0);
  });

  it('counts unique agents_authorized correctly across multiple signals from same agent', async () => {
    // Agent A produced 3 signals, Agent B produced 2 signals
    const signals = [
      { agent_entity_id: 'agent-a', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-a', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-a', outcome_positive: false, weight: 0.15 },
      { agent_entity_id: 'agent-b', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-b', outcome_positive: true,  weight: 0.15 },
    ];
    const mockSupabase = {
      from: vi.fn(() => makeChain({ data: signals, error: null })),
    };

    const result = await getDelegationJudgmentScore('principal-multi-agent', mockSupabase);

    expect(result.agents_authorized).toBe(2); // 2 unique agents
    expect(result.total_signals).toBe(5);
  });

  it('handles mixed positive and negative outcomes proportionally', async () => {
    // 3 positive, 1 negative → judgment_score = 3/4 = 0.75
    const signals = [
      { agent_entity_id: 'agent-a', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-b', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-c', outcome_positive: true,  weight: 0.15 },
      { agent_entity_id: 'agent-d', outcome_positive: false, weight: 0.15 },
    ];
    const mockSupabase = {
      from: vi.fn(() => makeChain({ data: signals, error: null })),
    };

    const result = await getDelegationJudgmentScore('principal-mixed', mockSupabase);

    expect(result.judgment_score).toBeCloseTo(0.75, 2);
    expect(result.good_outcome_rate).toBeCloseTo(0.75, 2);
  });

  it('returns null-safe defaults when the DB returns an error', async () => {
    const mockSupabase = {
      from: vi.fn(() => makeChain({ data: null, error: { message: 'DB error', code: '500' } })),
    };

    const result = await getDelegationJudgmentScore('principal-db-error', mockSupabase);

    expect(result.judgment_score).toBeNull();
    expect(result.total_signals).toBe(0);
    expect(result.agents_authorized).toBe(0);
  });

  it('returns null-safe defaults when table does not exist (42P01)', async () => {
    const mockSupabase = {
      from: vi.fn(() =>
        makeChain({ data: null, error: { message: 'relation does not exist', code: '42P01' } })
      ),
    };

    const result = await getDelegationJudgmentScore('principal-no-table', mockSupabase);

    expect(result.judgment_score).toBeNull();
    expect(result.total_signals).toBe(0);
  });
});

// ============================================================================
// applyAttributionChain
// ============================================================================

describe('applyAttributionChain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('writes a principal signal when delegation is present', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-1',
      agent_behavior: 'completed',
      composite_score: 90,
    };
    const chain = [
      { role: 'agent',     entity_id: 'agent-entity',   weight: 1.0 },
      { role: 'principal', entity_id: 'human-principal', weight: 0.15, delegation_id: 'deleg_001' },
    ];

    const insertMock = vi.fn().mockResolvedValue({ error: null });
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    const result = await applyAttributionChain(receipt, chain, mockSupabase);

    expect(result.principal_attributed).toBe(true);
    expect(result.agent_attributed).toBe(true);
    expect(result.signals_written).toBe(2);
    expect(insertMock).toHaveBeenCalledTimes(1);

    // Verify the insert payload contains the right principal_id and outcome
    const insertArg = insertMock.mock.calls[0][0];
    expect(insertArg.principal_id).toBe('human-principal');
    expect(insertArg.outcome_positive).toBe(true); // 'completed' is positive
    expect(insertArg.weight).toBe(0.15);
  });

  it('skips principal signal when no delegation entry is in the chain', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-2',
      agent_behavior: 'completed',
    };
    const chain = [
      { role: 'agent', entity_id: 'agent-entity', weight: 1.0 },
    ];

    const insertMock = vi.fn();
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    const result = await applyAttributionChain(receipt, chain, mockSupabase);

    expect(result.principal_attributed).toBe(false);
    expect(insertMock).not.toHaveBeenCalled();
  });

  it('marks outcome_positive as false when agent_behavior is "abandoned"', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-3',
      agent_behavior: 'abandoned',
    };
    const chain = [
      { role: 'agent',     entity_id: 'agent-entity',   weight: 1.0 },
      { role: 'principal', entity_id: 'human-principal', weight: 0.15 },
    ];

    const insertMock = vi.fn().mockResolvedValue({ error: null });
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    await applyAttributionChain(receipt, chain, mockSupabase);

    const insertArg = insertMock.mock.calls[0][0];
    expect(insertArg.outcome_positive).toBe(false);
  });

  it('marks outcome_positive as false when agent_behavior is "disputed"', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-4',
      agent_behavior: 'disputed',
    };
    const chain = [
      { role: 'agent',     entity_id: 'agent-entity',   weight: 1.0 },
      { role: 'principal', entity_id: 'human-principal', weight: 0.15 },
    ];

    const insertMock = vi.fn().mockResolvedValue({ error: null });
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    await applyAttributionChain(receipt, chain, mockSupabase);

    const insertArg = insertMock.mock.calls[0][0];
    expect(insertArg.outcome_positive).toBe(false);
  });

  it('marks outcome_positive as true when agent_behavior is "completed"', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-5',
      agent_behavior: 'completed',
    };
    const chain = [
      { role: 'agent',     entity_id: 'agent-entity',   weight: 1.0 },
      { role: 'principal', entity_id: 'human-principal', weight: 0.15 },
    ];

    const insertMock = vi.fn().mockResolvedValue({ error: null });
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    await applyAttributionChain(receipt, chain, mockSupabase);

    const insertArg = insertMock.mock.calls[0][0];
    expect(insertArg.outcome_positive).toBe(true);
  });

  it('falls back to composite_score when agent_behavior is absent', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-6',
      composite_score: 30, // below 70 → negative
    };
    const chain = [
      { role: 'agent',     entity_id: 'agent-entity',   weight: 1.0 },
      { role: 'principal', entity_id: 'human-principal', weight: 0.15 },
    ];

    const insertMock = vi.fn().mockResolvedValue({ error: null });
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    await applyAttributionChain(receipt, chain, mockSupabase);

    const insertArg = insertMock.mock.calls[0][0];
    expect(insertArg.outcome_positive).toBe(false);
  });

  it('does not throw when principal_delegation_signals table does not exist (42P01)', async () => {
    const receipt = {
      entity_id: 'agent-entity',
      receipt_id: 'receipt-uuid-7',
      agent_behavior: 'completed',
    };
    const chain = [
      { role: 'agent',     entity_id: 'agent-entity',   weight: 1.0 },
      { role: 'principal', entity_id: 'human-principal', weight: 0.15 },
    ];

    const insertMock = vi.fn().mockResolvedValue({
      error: { code: '42P01', message: 'relation "principal_delegation_signals" does not exist' },
    });
    const mockSupabase = {
      from: vi.fn(() => ({ insert: insertMock })),
    };

    // Must NOT throw — attribution is best-effort
    const result = await applyAttributionChain(receipt, chain, mockSupabase);
    expect(result.principal_attributed).toBe(false); // insert failed gracefully
  });
});
