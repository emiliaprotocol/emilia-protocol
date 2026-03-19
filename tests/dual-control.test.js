import { describe, it, expect } from 'vitest';
import {
  requireDualControl,
  DUAL_CONTROL_ACTIONS,
  hasPermission,
  OPERATOR_ROLES,
} from '../lib/procedural-justice.js';

// ============================================================================
// Dual-control tests — verifies two-operator authorization for sensitive actions
// ============================================================================

describe('DUAL_CONTROL_ACTIONS constant', () => {
  it('contains the five trust-sensitive actions', () => {
    expect(DUAL_CONTROL_ACTIONS.has('entity.suspend')).toBe(true);
    expect(DUAL_CONTROL_ACTIONS.has('entity.unsuspend')).toBe(true);
    expect(DUAL_CONTROL_ACTIONS.has('dispute.override')).toBe(true);
    expect(DUAL_CONTROL_ACTIONS.has('evidence.redact')).toBe(true);
    expect(DUAL_CONTROL_ACTIONS.has('redaction.manage')).toBe(true);
  });

  it('does not include non-sensitive actions', () => {
    expect(DUAL_CONTROL_ACTIONS.has('report.file')).toBe(false);
    expect(DUAL_CONTROL_ACTIONS.has('audit.view')).toBe(false);
    expect(DUAL_CONTROL_ACTIONS.has('dispute.file')).toBe(false);
  });
});

// ============================================================================
// 1. Dual-control action with two different operators → authorized
// ============================================================================

describe('requireDualControl with two different operators', () => {
  it('authorizes dual-control action when two distinct operators both have permission', () => {
    const result = requireDualControl(
      'entity.suspend',
      'operator-alice',
      'operator-bob',
      'operator',
      'operator',
    );
    expect(result.authorized).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('authorizes entity.unsuspend with two different operators', () => {
    const result = requireDualControl(
      'entity.unsuspend',
      'operator-1',
      'operator-2',
      'operator',
      'operator',
    );
    expect(result.authorized).toBe(true);
  });

  it('authorizes dispute.override with operator + appeal_reviewer', () => {
    const result = requireDualControl(
      'dispute.override',
      'operator-1',
      'appeal-reviewer-1',
      'operator',
      'appeal_reviewer',
    );
    expect(result.authorized).toBe(true);
  });

  it('authorizes evidence.redact with two operators', () => {
    const result = requireDualControl(
      'evidence.redact',
      'op-a',
      'op-b',
      'operator',
      'operator',
    );
    expect(result.authorized).toBe(true);
  });

  it('authorizes redaction.manage with two appeal_reviewers', () => {
    const result = requireDualControl(
      'redaction.manage',
      'rev-a',
      'rev-b',
      'appeal_reviewer',
      'appeal_reviewer',
    );
    expect(result.authorized).toBe(true);
  });
});

// ============================================================================
// 2. Dual-control action with same operator twice → denied
// ============================================================================

describe('requireDualControl with same operator twice', () => {
  it('denies when the same operator ID is used for both confirmations', () => {
    const result = requireDualControl(
      'entity.suspend',
      'operator-alice',
      'operator-alice',
      'operator',
      'operator',
    );
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('two different operators');
  });

  it('denies same-operator for all dual-control actions', () => {
    for (const action of DUAL_CONTROL_ACTIONS) {
      const result = requireDualControl(
        action,
        'same-op',
        'same-op',
        'operator',
        'operator',
      );
      expect(result.authorized).toBe(false);
    }
  });
});

// ============================================================================
// 3. Non-dual-control action with single operator → authorized
// ============================================================================

describe('requireDualControl with non-dual-control actions', () => {
  it('authorizes dispute.review with a single operator', () => {
    const result = requireDualControl(
      'dispute.review',
      'operator-alice',
      null,
      'operator',
    );
    expect(result.authorized).toBe(true);
  });

  it('authorizes audit.view with a single operator', () => {
    const result = requireDualControl(
      'audit.view',
      'operator-alice',
      null,
      'operator',
    );
    expect(result.authorized).toBe(true);
  });

  it('authorizes report.review with a reviewer role', () => {
    const result = requireDualControl(
      'report.review',
      'reviewer-1',
      null,
      'reviewer',
    );
    expect(result.authorized).toBe(true);
  });
});

// ============================================================================
// 4. Operator without required permission → denied
// ============================================================================

describe('requireDualControl with insufficient permissions', () => {
  it('denies when first operator lacks permission for dual-control action', () => {
    const result = requireDualControl(
      'entity.suspend',
      'reviewer-1',
      'operator-1',
      'reviewer',      // reviewers cannot suspend entities
      'operator',
    );
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('First operator');
    expect(result.reason).toContain('lacks permission');
  });

  it('denies when second operator lacks permission for dual-control action', () => {
    const result = requireDualControl(
      'entity.suspend',
      'operator-1',
      'reviewer-1',
      'operator',
      'reviewer',      // reviewers cannot suspend entities
    );
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('Second operator');
    expect(result.reason).toContain('lacks permission');
  });

  it('denies when first operator lacks permission for non-dual-control action', () => {
    const result = requireDualControl(
      'audit.view',
      'reporter-1',
      null,
      'reporter',      // reporters cannot view audits
    );
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('lacks permission');
  });

  it('denies when an invalid role is provided', () => {
    const result = requireDualControl(
      'entity.suspend',
      'unknown-1',
      'operator-1',
      'nonexistent_role',
      'operator',
    );
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('lacks permission');
  });

  it('denies dual-control action when second operator is missing', () => {
    const result = requireDualControl(
      'entity.suspend',
      'operator-1',
      null,
      'operator',
    );
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('dual-control');
  });
});
