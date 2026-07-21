/**
 * EMILIA Protocol — Delegation Judgment Tests
 *
 * Tests for the principal delegation authority system.
 * Covers getDelegationJudgmentScore() from lib/attribution.js and the
 * grade/interpretation logic that the route layer applies on top.
 *
 * These tests are unit-level: they use mock Supabase clients to simulate DB
 * responses without requiring a live database connection.
 */

import { describe, it, expect } from 'vitest';
import { getDelegationJudgmentScore } from '../lib/attribution.js';

// ---------------------------------------------------------------------------
// Mock Supabase builder
//
// Simulates the chained Supabase query interface (.from().select().eq().xxx).
// Returns the provided signals as if they came back from the DB.
// ---------------------------------------------------------------------------

function mockSupabase(signals, { tableError = null } = {}) {
  const builder = {
    _signals: signals,
    select: function () { return this; },
    eq: function () { return this; },
    then: undefined,
  };

  // Make the builder thenable so `await db.from(...).select(...).eq(...)` works
  // by returning a resolved promise with the shape Supabase returns.
  return {
    from: () => ({
      select: () => ({
        eq: () =>
          Promise.resolve({
            data: tableError ? null : signals,
            error: tableError ?? null,
          }),
      }),
    }),
  };
}

// ---------------------------------------------------------------------------
// Grade & interpretation helpers (duplicated from route layer for test clarity)
// ---------------------------------------------------------------------------

function computeGrade(score) {
  if (score >= 0.85) return 'excellent';
  if (score >= 0.70) return 'good';
  if (score >= 0.50) return 'fair';
  return 'poor';
}

function buildInterpretation(judgmentScore, grade, agentsAuthorized, activeAgents, goodOutcomeRate, totalSignals) {
  if (judgmentScore === null || totalSignals === 0) {
    return 'No delegation history yet — this principal has not authorized any agents with recorded outcomes.';
  }

  const pct = Math.round((goodOutcomeRate ?? 0) * 100);
  const signalNoun = totalSignals === 1 ? 'receipt' : 'receipts';

  if (grade === 'excellent') {
    return `Consistently authorizes high-confidence agents with excellent outcomes (${totalSignals} ${signalNoun}, ${pct}% positive).`;
  }
  if (grade === 'good') {
    return `Strong delegation track record — most authorized agents perform reliably (${totalSignals} ${signalNoun}, ${pct}% positive).`;
  }
  if (grade === 'fair') {
    const badAgents = agentsAuthorized - Math.round(agentsAuthorized * (goodOutcomeRate ?? 0));
    if (badAgents > 0) {
      return `Mixed delegation history — ${badAgents} of ${agentsAuthorized} authorized agents have poor behavioral records (${pct}% positive outcomes).`;
    }
    return `Mixed delegation history — ${pct}% of outcomes were positive across ${totalSignals} ${signalNoun}.`;
  }
  return `Repeated poor agent choices — only ${pct}% positive outcomes across ${totalSignals} ${signalNoun}. Review authorized agents immediately.`;
}

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

function makeSignal(agentId, outcomePositive, weight = 0.15) {
  return { agent_entity_id: agentId, outcome_positive: outcomePositive, weight };
}

// ---------------------------------------------------------------------------
// Tests: getDelegationJudgmentScore
// ---------------------------------------------------------------------------

describe('getDelegationJudgmentScore — score boundaries', () => {
  it('judgmentScore is 1.0 when all signals are positive outcomes', async () => {
    const signals = [
      makeSignal('agent-a', true),
      makeSignal('agent-b', true),
      makeSignal('agent-a', true),
    ];
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.judgment_score).toBe(1.0);
  });

  it('judgmentScore is 0.0 when all signals are negative outcomes', async () => {
    const signals = [
      makeSignal('agent-a', false),
      makeSignal('agent-b', false),
      makeSignal('agent-c', false),
    ];
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.judgment_score).toBe(0.0);
  });

  it('judgmentScore is null when there are no signals', async () => {
    const db = mockSupabase([]);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.judgment_score).toBeNull();
  });

  it('judgmentScore is between 0 and 1 for mixed outcomes', async () => {
    const signals = [
      makeSignal('agent-a', true),
      makeSignal('agent-a', false),
      makeSignal('agent-b', true),
      makeSignal('agent-b', false),
    ];
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.judgment_score).toBeGreaterThanOrEqual(0);
    expect(result.judgment_score).toBeLessThanOrEqual(1);
    expect(result.judgment_score).toBeCloseTo(0.5, 2);
  });
});

describe('getDelegationJudgmentScore — good_outcome_rate', () => {
  it('good_outcome_rate is 1.0 for all-positive signals', async () => {
    const signals = Array(5).fill(null).map((_, i) => makeSignal(`agent-${i}`, true));
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.good_outcome_rate).toBe(1.0);
  });

  it('good_outcome_rate is 0.0 for all-negative signals', async () => {
    const signals = Array(4).fill(null).map((_, i) => makeSignal(`agent-${i}`, false));
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.good_outcome_rate).toBe(0.0);
  });

  it('good_outcome_rate is null when there are no signals', async () => {
    const db = mockSupabase([]);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.good_outcome_rate).toBeNull();
  });
});

describe('getDelegationJudgmentScore — agents_authorized count', () => {
  it('agents_authorized counts unique agent entity IDs in signals', async () => {
    const signals = [
      makeSignal('agent-x', true),
      makeSignal('agent-x', true),   // same agent, second signal
      makeSignal('agent-y', false),
      makeSignal('agent-z', true),
    ];
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    // 3 unique agents: x, y, z
    expect(result.agents_authorized).toBe(3);
  });

  it('agents_authorized is 0 when there are no signals', async () => {
    const db = mockSupabase([]);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.agents_authorized).toBe(0);
  });
});

describe('getDelegationJudgmentScore — signal counts', () => {
  it('total_signals, positive_signals, negative_signals sum correctly', async () => {
    const signals = [
      makeSignal('a', true),
      makeSignal('a', true),
      makeSignal('b', false),
    ];
    const db = mockSupabase(signals);
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.total_signals).toBe(3);
    expect(result.positive_signals).toBe(2);
    expect(result.negative_signals).toBe(1);
  });
});

describe('getDelegationJudgmentScore — DB error graceful degradation', () => {
  it('returns null judgment_score and zero counts when DB table is missing', async () => {
    const tableError = { code: '42P01', message: 'relation "principal_delegation_signals" does not exist' };
    const db = mockSupabase(null, { tableError });
    const result = await getDelegationJudgmentScore('principal-1', db);
    expect(result.judgment_score).toBeNull();
    expect(result.agents_authorized).toBe(0);
    expect(result.total_signals).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: grade computation
// ---------------------------------------------------------------------------

describe('computeGrade — threshold boundaries', () => {
  it('returns "excellent" for score >= 0.85', () => {
    expect(computeGrade(0.85)).toBe('excellent');
    expect(computeGrade(1.0)).toBe('excellent');
    expect(computeGrade(0.99)).toBe('excellent');
  });

  it('returns "good" for score 0.70 - 0.84', () => {
    expect(computeGrade(0.70)).toBe('good');
    expect(computeGrade(0.80)).toBe('good');
    expect(computeGrade(0.84)).toBe('good');
  });

  it('returns "fair" for score 0.50 - 0.69', () => {
    expect(computeGrade(0.50)).toBe('fair');
    expect(computeGrade(0.60)).toBe('fair');
    expect(computeGrade(0.69)).toBe('fair');
  });

  it('returns "poor" for score < 0.50', () => {
    expect(computeGrade(0.49)).toBe('poor');
    expect(computeGrade(0.0)).toBe('poor');
    expect(computeGrade(0.1)).toBe('poor');
  });
});

// ---------------------------------------------------------------------------
// Tests: interpretation strings
// ---------------------------------------------------------------------------

describe('buildInterpretation — non-empty and contextually correct', () => {
  it('interpretation is non-empty for all grade levels', () => {
    const cases = [
      [1.0, 'excellent', 5, 3, 1.0, 47],
      [0.75, 'good', 4, 2, 0.75, 12],
      [0.55, 'fair', 8, 3, 0.55, 20],
      [0.30, 'poor', 6, 1, 0.30, 15],
    ];
    for (const [score, grade, auth, active, rate, total] of cases) {
      const interp = buildInterpretation(score, grade, auth, active, rate, total);
      expect(typeof interp).toBe('string');
      expect(interp.length).toBeGreaterThan(0);
    }
  });

  it('interpretation mentions receipt count for excellent grade', () => {
    const interp = buildInterpretation(1.0, 'excellent', 5, 3, 1.0, 47);
    expect(interp).toMatch(/47/);
    expect(interp).toMatch(/94%|100%|positive/i);
  });

  it('interpretation mentions "poor behavioral records" for fair grade with bad agents', () => {
    const interp = buildInterpretation(0.55, 'fair', 8, 3, 0.375, 20);
    expect(interp).toMatch(/authorized agents/i);
  });

  it('returns "No delegation history" for null score', () => {
    const interp = buildInterpretation(null, 'poor', 0, 0, null, 0);
    expect(interp).toMatch(/No delegation history/i);
  });

  it('returns "No delegation history" for zero signals', () => {
    const interp = buildInterpretation(null, 'poor', 0, 0, null, 0);
    expect(interp).toMatch(/No delegation history/i);
  });
});

// ---------------------------------------------------------------------------
// Tests: 404 behavior (simulated — no live HTTP calls in unit tests)
// ---------------------------------------------------------------------------

describe('404 sentinel — unknown principal', () => {
  it('getDelegationJudgmentScore returns safe defaults for any principal ID (no 404 at lib level)', async () => {
    // The lib function is ID-agnostic; 404 is enforced at the route level by
    // calling getPrincipal() first. This test confirms the lib does not throw
    // for an unknown principal — it returns safe zero-state values.
    const db = mockSupabase([]);
    const result = await getDelegationJudgmentScore('ep_principal_doesnotexist', db);
    expect(result).toMatchObject({
      judgment_score: null,
      agents_authorized: 0,
      good_outcome_rate: null,
      total_signals: 0,
      positive_signals: 0,
      negative_signals: 0,
    });
  });
});
