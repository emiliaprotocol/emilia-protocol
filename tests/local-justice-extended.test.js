/**
 * local-justice-extended.test.js
 *
 * Extended coverage for lib/procedural-justice.js (reported as "local-justice.js")
 * targeting uncovered lines ~232, 445, 461-474:
 *   - filterByVisibility with operator/appeal_reviewer bypass
 *   - filterByVisibility with "everything" includes key
 *   - filterByVisibility for unknown tier
 *   - validateTransition for all state machines
 *   - checkAbuse: retaliatory_filing path, dispute flooding, IP flooding
 *   - requireDualControl: all branches
 *   - recordOperatorAction coverage
 *   - OPERATOR_ROLES permissions coverage
 *   - ABUSE_PATTERNS definitions
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock ep-ix so the module loads without the full dependency chain
vi.mock('@/lib/ep-ix', () => ({
  emitAudit: vi.fn().mockResolvedValue(undefined),
}));

import {
  OPERATOR_ROLES,
  DUAL_CONTROL_ACTIONS,
  hasPermission,
  requireDualControl,
  VISIBILITY_TIERS,
  filterByVisibility,
  DISPUTE_STATES,
  CONTINUITY_STATES,
  validateTransition,
  ABUSE_PATTERNS,
  checkAbuse,
  recordOperatorAction,
} from '../lib/procedural-justice.js';

import { emitAudit } from '@/lib/ep-ix';

// =============================================================================
// hasPermission
// =============================================================================

describe('hasPermission', () => {
  it('returns true for a permission the role has', () => {
    expect(hasPermission('operator', 'dispute.resolve')).toBe(true);
  });

  it('returns false for a permission the role lacks', () => {
    expect(hasPermission('reporter', 'dispute.resolve')).toBe(false);
  });

  it('returns false for unknown role', () => {
    expect(hasPermission('unknown_role', 'dispute.resolve')).toBe(false);
  });

  it('reporter can file reports', () => {
    expect(hasPermission('reporter', 'report.file')).toBe(true);
  });

  it('disputant can file disputes', () => {
    expect(hasPermission('disputant', 'dispute.file')).toBe(true);
  });

  it('reviewer can view restricted evidence', () => {
    expect(hasPermission('reviewer', 'evidence.view_restricted')).toBe(true);
  });
});

// =============================================================================
// requireDualControl — all branches
// =============================================================================

describe('requireDualControl', () => {
  it('returns authorized=false when first operator lacks permission', () => {
    const result = requireDualControl('entity.suspend', 'op1', 'op2', 'reporter', 'operator');
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/reporter/);
  });

  it('non-dual-control action: authorized with single operator', () => {
    // 'dispute.resolve' is not in DUAL_CONTROL_ACTIONS
    const result = requireDualControl('dispute.resolve', 'op1', null, 'operator', null);
    expect(result.authorized).toBe(true);
  });

  it('dual-control action: fails without second operator', () => {
    const result = requireDualControl('entity.suspend', 'op1', null, 'operator', null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/dual-control/i);
  });

  it('dual-control action: fails when both operators are the same', () => {
    const result = requireDualControl('entity.suspend', 'op1', 'op1', 'operator', 'operator');
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/same operator/i);
  });

  it('dual-control action: fails when second operator lacks permission', () => {
    const result = requireDualControl('entity.suspend', 'op1', 'op2', 'operator', 'reporter');
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/reporter/);
  });

  it('dual-control action: authorized when both operators are distinct and qualified', () => {
    const result = requireDualControl('entity.suspend', 'op1', 'op2', 'operator', 'operator');
    expect(result.authorized).toBe(true);
  });

  it('DUAL_CONTROL_ACTIONS contains entity.suspend', () => {
    expect(DUAL_CONTROL_ACTIONS.has('entity.suspend')).toBe(true);
  });

  it('DUAL_CONTROL_ACTIONS contains evidence.redact', () => {
    expect(DUAL_CONTROL_ACTIONS.has('evidence.redact')).toBe(true);
  });
});

// =============================================================================
// filterByVisibility — line ~232 + "everything" key
// =============================================================================

describe('filterByVisibility', () => {
  const evidence = {
    entity_id: 'e1',
    status: 'open',
    reason: 'fraud',
    proof_types: ['email'],
    full_evidence: { raw: 'data' },
    internal_notes: 'sensitive',
    raw_evidence: 'raw',
    outcome: 'upheld',
    timeline: ['step1'],
    reasoning: 'clear cut',
    created_at: '2025-01-01',
  };

  it('operators see everything (bypass tier filtering)', () => {
    const result = filterByVisibility(evidence, 'public_summary', 'operator');
    expect(result).toBe(evidence);
  });

  it('appeal_reviewers see everything (bypass tier filtering)', () => {
    const result = filterByVisibility(evidence, 'restricted', 'appeal_reviewer');
    expect(result).toBe(evidence);
  });

  it('public_summary tier returns only public fields', () => {
    const result = filterByVisibility(evidence, 'public_summary', 'anonymous');
    expect(result.entity_id).toBe('e1');
    expect(result.internal_notes).toBeUndefined();
    expect(result.raw_evidence).toBeUndefined();
  });

  it('restricted tier returns full_evidence and reasoning', () => {
    const result = filterByVisibility(evidence, 'restricted', 'disputant');
    expect(result.full_evidence).toBeDefined();
    expect(result.reasoning).toBeDefined();
    expect(result.internal_notes).toBeUndefined();
  });

  it('operator_only tier with "everything" key returns all evidence', () => {
    const result = filterByVisibility(evidence, 'operator_only', 'reviewer');
    expect(result).toBe(evidence);
  });

  it('returns {} for unknown tier', () => {
    const result = filterByVisibility(evidence, 'nonexistent_tier', 'reviewer');
    expect(result).toEqual({});
  });

  it('redacted_public tier includes reason and proof_types', () => {
    const result = filterByVisibility(evidence, 'redacted_public', 'disputant');
    expect(result.reason).toBe('fraud');
    expect(result.proof_types).toEqual(['email']);
    expect(result.raw_evidence).toBeUndefined();
  });
});

// =============================================================================
// validateTransition — DISPUTE_STATES state machine
// =============================================================================

describe('validateTransition — DISPUTE_STATES', () => {
  it('valid transition: open → under_review', () => {
    const result = validateTransition(DISPUTE_STATES, 'open', 'under_review');
    expect(result.valid).toBe(true);
  });

  it('valid transition: open → withdrawn', () => {
    const result = validateTransition(DISPUTE_STATES, 'open', 'withdrawn');
    expect(result.valid).toBe(true);
  });

  it('invalid transition: open → upheld (not in valid_transitions)', () => {
    const result = validateTransition(DISPUTE_STATES, 'open', 'upheld');
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/Invalid transition/);
  });

  it('terminal state blocks all transitions', () => {
    const result = validateTransition(DISPUTE_STATES, 'appeal_upheld', 'open');
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/terminal/);
  });

  it('unknown current state returns error', () => {
    const result = validateTransition(DISPUTE_STATES, 'nonexistent', 'open');
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/Unknown current state/);
  });

  it('withdrawn is terminal', () => {
    const result = validateTransition(DISPUTE_STATES, 'withdrawn', 'open');
    expect(result.valid).toBe(false);
  });
});

// =============================================================================
// validateTransition — CONTINUITY_STATES state machine
// =============================================================================

describe('validateTransition — CONTINUITY_STATES', () => {
  it('valid transition: pending → approved_full', () => {
    const result = validateTransition(CONTINUITY_STATES, 'pending', 'approved_full');
    expect(result.valid).toBe(true);
  });

  it('valid transition: pending → under_challenge', () => {
    const result = validateTransition(CONTINUITY_STATES, 'pending', 'under_challenge');
    expect(result.valid).toBe(true);
  });

  it('terminal state approved_full blocks transitions', () => {
    const result = validateTransition(CONTINUITY_STATES, 'approved_full', 'pending');
    expect(result.valid).toBe(false);
  });

  it('invalid transition: under_challenge → pending', () => {
    const result = validateTransition(CONTINUITY_STATES, 'under_challenge', 'pending');
    expect(result.valid).toBe(false);
  });
});

// =============================================================================
// checkAbuse — detailed paths (lines 445, 461-474)
// =============================================================================

function makeSupabaseMock(countsByCall = []) {
  let callIndex = 0;
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    then: (resolve) => Promise.resolve({ count: countsByCall[callIndex++] ?? 0 }).then(resolve),
  };
  return {
    from: vi.fn().mockReturnValue(chain),
    _chain: chain,
  };
}

describe('checkAbuse — report action', () => {
  it('allows report when counts are below all thresholds', async () => {
    const db = makeSupabaseMock([0, 0, 0]);
    const result = await checkAbuse(db, 'report', { entity_id: 'e1', report_type: 'fraud' });
    expect(result.allowed).toBe(true);
  });

  it('blocks on repeated identical reports (>= 5)', async () => {
    const db = makeSupabaseMock([5, 0, 0]);
    const result = await checkAbuse(db, 'report', { entity_id: 'e1', report_type: 'fraud' });
    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('repeated_identical_reports');
  });

  it('blocks on brigading (>= 10 total reports)', async () => {
    const db = makeSupabaseMock([0, 10, 0]);
    const result = await checkAbuse(db, 'report', { entity_id: 'e1', report_type: 'fraud' });
    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('brigading');
  });

  it('blocks on IP flooding when reporter_ip_hash provided (>= 10)', async () => {
    const db = makeSupabaseMock([0, 0, 10]);
    const result = await checkAbuse(db, 'report', {
      entity_id: 'e1',
      report_type: 'fraud',
      reporter_ip_hash: 'abc123',
    });
    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('ip_report_flooding');
  });

  it('skips IP check when reporter_ip_hash is absent', async () => {
    const db = makeSupabaseMock([0, 0]);
    const result = await checkAbuse(db, 'report', { entity_id: 'e1', report_type: 'fraud' });
    expect(result.allowed).toBe(true);
  });
});

describe('checkAbuse — dispute action', () => {
  it('allows dispute when counts are below thresholds', async () => {
    const db = makeSupabaseMock([0, 0]);
    const result = await checkAbuse(db, 'dispute', {
      filer_entity_id: 'e1',
      target_entity_id: 'e2',
    });
    expect(result.allowed).toBe(true);
  });

  it('blocks on retaliatory filing (>= 1)', async () => {
    const db = makeSupabaseMock([1, 0]);
    const result = await checkAbuse(db, 'dispute', {
      filer_entity_id: 'e1',
      target_entity_id: 'e2',
    });
    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('retaliatory_filing');
  });

  it('blocks on dispute flooding (>= 10)', async () => {
    const db = makeSupabaseMock([0, 10]);
    const result = await checkAbuse(db, 'dispute', {
      filer_entity_id: 'e1',
      target_entity_id: 'e2',
    });
    expect(result.allowed).toBe(false);
    expect(result.pattern).toBe('dispute_flooding');
  });

  it('allows unknown action type (returns allowed=true)', async () => {
    const db = makeSupabaseMock([]);
    const result = await checkAbuse(db, 'unknown_action', {});
    expect(result.allowed).toBe(true);
  });
});

// =============================================================================
// checkAbuse — graceful degradation when DB throws
// =============================================================================

describe('checkAbuse — graceful DB error handling', () => {
  it('continues and returns allowed=true when DB throws on report', async () => {
    // The checkAbuse code catches errors in try/catch. We make .gte() return a
    // rejected-promise-shaped object so the await inside the try block throws.
    const rejectingChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnValue(Promise.reject(new Error('DB error'))),
    };
    const db = { from: vi.fn().mockReturnValue(rejectingChain) };
    const result = await checkAbuse(db, 'report', { entity_id: 'e1', report_type: 'fraud' });
    expect(result.allowed).toBe(true);
  });
});

// =============================================================================
// recordOperatorAction
// =============================================================================

describe('recordOperatorAction', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls emitAudit with correct action prefix', async () => {
    const db = {};
    await recordOperatorAction(db, {
      operatorId: 'op-1',
      operatorRole: 'operator',
      targetType: 'entity',
      targetId: 'e-1',
      action: 'suspend',
      beforeState: { status: 'active' },
      afterState: { status: 'suspended' },
      reasoning: 'Policy violation',
    });

    expect(emitAudit).toHaveBeenCalledWith(
      'operator.suspend',
      'op-1',
      'operator',
      'entity',
      'e-1',
      'suspend',
      { status: 'active' },
      expect.objectContaining({
        status: 'suspended',
        reasoning: 'Policy violation',
        operator_role: 'operator',
      })
    );
  });

  it('returns { recorded: true }', async () => {
    const result = await recordOperatorAction({}, {
      operatorId: 'op-1', operatorRole: 'reviewer',
      targetType: 'dispute', targetId: 'd-1',
      action: 'resolve', beforeState: {}, afterState: {}, reasoning: '',
    });
    expect(result).toEqual({ recorded: true });
  });
});

// =============================================================================
// ABUSE_PATTERNS — constant correctness
// =============================================================================

describe('ABUSE_PATTERNS', () => {
  it('repeated_identical_reports has threshold 5', () => {
    expect(ABUSE_PATTERNS.repeated_identical_reports.threshold).toBe(5);
  });

  it('brigading has threshold 10', () => {
    expect(ABUSE_PATTERNS.brigading.threshold).toBe(10);
  });

  it('dispute_flooding has threshold 10', () => {
    expect(ABUSE_PATTERNS.dispute_flooding.threshold).toBe(10);
  });

  it('retaliatory_filing has threshold 1', () => {
    expect(ABUSE_PATTERNS.retaliatory_filing.threshold).toBe(1);
  });

  it('all patterns have action field', () => {
    for (const pattern of Object.values(ABUSE_PATTERNS)) {
      expect(pattern.action).toBeDefined();
    }
  });
});
