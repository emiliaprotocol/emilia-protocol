/**
 * Tests for lib/constants.js and lib/design-tokens.js
 *
 * These files are 100% branch-covered but 0% statement-covered.
 * Importing and asserting the exported values flips them to full coverage.
 */

import { describe, it, expect } from 'vitest';

// ── constants.js ──────────────────────────────────────────────────────────

import {
  ENTITY_STATUS,
  COMMIT_STATUS,
  COMMIT_TERMINAL_STATUSES,
  COMMIT_ACTIONS,
  COMMIT_DECISIONS,
  BILATERAL_STATUS,
  AGENT_BEHAVIOR,
  PROVENANCE_TIER,
  CONFIDENCE_LEVEL,
  CONFIDENCE_LEVEL_ORDER,
  DELEGATION_STATUS,
  AUTHORITY_STATUS,
  HANDSHAKE_OUTCOME,
  RECEIPT_DISPUTE_STATUS,
  CONTINUITY_STATUS,
  NEED_STATUS,
  OPERATOR_APPLICATION_STATUS,
} from '@/lib/constants.js';


// =============================================================================
// ENTITY_STATUS
// =============================================================================

describe('ENTITY_STATUS', () => {
  it('is a frozen object', () => {
    expect(Object.isFrozen(ENTITY_STATUS)).toBe(true);
  });

  it('has ACTIVE = "active"', () => {
    expect(ENTITY_STATUS.ACTIVE).toBe('active');
  });

  it('has INACTIVE = "inactive"', () => {
    expect(ENTITY_STATUS.INACTIVE).toBe('inactive');
  });

  it('has SUSPENDED = "suspended"', () => {
    expect(ENTITY_STATUS.SUSPENDED).toBe('suspended');
  });

  it('has exactly 3 keys', () => {
    expect(Object.keys(ENTITY_STATUS).length).toBe(3);
  });
});

// =============================================================================
// COMMIT_STATUS
// =============================================================================

describe('COMMIT_STATUS', () => {
  it('is a frozen object', () => {
    expect(Object.isFrozen(COMMIT_STATUS)).toBe(true);
  });

  it('has ACTIVE = "active"', () => {
    expect(COMMIT_STATUS.ACTIVE).toBe('active');
  });

  it('has FULFILLED = "fulfilled"', () => {
    expect(COMMIT_STATUS.FULFILLED).toBe('fulfilled');
  });

  it('has REVOKED = "revoked"', () => {
    expect(COMMIT_STATUS.REVOKED).toBe('revoked');
  });

  it('has EXPIRED = "expired"', () => {
    expect(COMMIT_STATUS.EXPIRED).toBe('expired');
  });
});

// =============================================================================
// COMMIT_TERMINAL_STATUSES
// =============================================================================

describe('COMMIT_TERMINAL_STATUSES', () => {
  it('is a frozen array', () => {
    expect(Object.isFrozen(COMMIT_TERMINAL_STATUSES)).toBe(true);
    expect(Array.isArray(COMMIT_TERMINAL_STATUSES)).toBe(true);
  });

  it('contains fulfilled, revoked, expired', () => {
    expect(COMMIT_TERMINAL_STATUSES).toContain('fulfilled');
    expect(COMMIT_TERMINAL_STATUSES).toContain('revoked');
    expect(COMMIT_TERMINAL_STATUSES).toContain('expired');
  });

  it('does not contain "active"', () => {
    expect(COMMIT_TERMINAL_STATUSES).not.toContain('active');
  });

  it('has exactly 3 entries', () => {
    expect(COMMIT_TERMINAL_STATUSES.length).toBe(3);
  });
});

// =============================================================================
// COMMIT_ACTIONS
// =============================================================================

describe('COMMIT_ACTIONS', () => {
  it('is a frozen object', () => {
    expect(Object.isFrozen(COMMIT_ACTIONS)).toBe(true);
  });

  it('has INSTALL = "install"', () => {
    expect(COMMIT_ACTIONS.INSTALL).toBe('install');
  });

  it('has CONNECT = "connect"', () => {
    expect(COMMIT_ACTIONS.CONNECT).toBe('connect');
  });

  it('has DELEGATE = "delegate"', () => {
    expect(COMMIT_ACTIONS.DELEGATE).toBe('delegate');
  });

  it('has TRANSACT = "transact"', () => {
    expect(COMMIT_ACTIONS.TRANSACT).toBe('transact');
  });
});

// =============================================================================
// COMMIT_DECISIONS
// =============================================================================

describe('COMMIT_DECISIONS', () => {
  it('has ALLOW = "allow"', () => {
    expect(COMMIT_DECISIONS.ALLOW).toBe('allow');
  });

  it('has REVIEW = "review"', () => {
    expect(COMMIT_DECISIONS.REVIEW).toBe('review');
  });

  it('has DENY = "deny"', () => {
    expect(COMMIT_DECISIONS.DENY).toBe('deny');
  });
});

// =============================================================================
// BILATERAL_STATUS
// =============================================================================

describe('BILATERAL_STATUS', () => {
  it('is a frozen object', () => {
    expect(Object.isFrozen(BILATERAL_STATUS)).toBe(true);
  });

  it('has PENDING_CONFIRMATION = "pending_confirmation"', () => {
    expect(BILATERAL_STATUS.PENDING_CONFIRMATION).toBe('pending_confirmation');
  });

  it('has CONFIRMED = "confirmed"', () => {
    expect(BILATERAL_STATUS.CONFIRMED).toBe('confirmed');
  });

  it('has DISPUTED = "disputed"', () => {
    expect(BILATERAL_STATUS.DISPUTED).toBe('disputed');
  });

  it('has EXPIRED = "expired"', () => {
    expect(BILATERAL_STATUS.EXPIRED).toBe('expired');
  });
});

// =============================================================================
// AGENT_BEHAVIOR
// =============================================================================

describe('AGENT_BEHAVIOR', () => {
  it('has COMPLETED = "completed"', () => {
    expect(AGENT_BEHAVIOR.COMPLETED).toBe('completed');
  });

  it('has RETRIED_SAME = "retried_same"', () => {
    expect(AGENT_BEHAVIOR.RETRIED_SAME).toBe('retried_same');
  });

  it('has RETRIED_DIFFERENT = "retried_different"', () => {
    expect(AGENT_BEHAVIOR.RETRIED_DIFFERENT).toBe('retried_different');
  });

  it('has ABANDONED = "abandoned"', () => {
    expect(AGENT_BEHAVIOR.ABANDONED).toBe('abandoned');
  });

  it('has DISPUTED = "disputed"', () => {
    expect(AGENT_BEHAVIOR.DISPUTED).toBe('disputed');
  });
});

// =============================================================================
// PROVENANCE_TIER
// =============================================================================

describe('PROVENANCE_TIER', () => {
  it('has SELF_ATTESTED = "self_attested"', () => {
    expect(PROVENANCE_TIER.SELF_ATTESTED).toBe('self_attested');
  });

  it('has IDENTIFIED_SIGNED = "identified_signed"', () => {
    expect(PROVENANCE_TIER.IDENTIFIED_SIGNED).toBe('identified_signed');
  });

  it('has BILATERAL = "bilateral"', () => {
    expect(PROVENANCE_TIER.BILATERAL).toBe('bilateral');
  });

  it('has PLATFORM_ORIGINATED = "platform_originated"', () => {
    expect(PROVENANCE_TIER.PLATFORM_ORIGINATED).toBe('platform_originated');
  });

  it('has CARRIER_VERIFIED = "carrier_verified"', () => {
    expect(PROVENANCE_TIER.CARRIER_VERIFIED).toBe('carrier_verified');
  });

  it('has ORACLE_VERIFIED = "oracle_verified"', () => {
    expect(PROVENANCE_TIER.ORACLE_VERIFIED).toBe('oracle_verified');
  });
});

// =============================================================================
// CONFIDENCE_LEVEL
// =============================================================================

describe('CONFIDENCE_LEVEL', () => {
  it('has PENDING = "pending"', () => {
    expect(CONFIDENCE_LEVEL.PENDING).toBe('pending');
  });

  it('has INSUFFICIENT = "insufficient"', () => {
    expect(CONFIDENCE_LEVEL.INSUFFICIENT).toBe('insufficient');
  });

  it('has PROVISIONAL = "provisional"', () => {
    expect(CONFIDENCE_LEVEL.PROVISIONAL).toBe('provisional');
  });

  it('has EMERGING = "emerging"', () => {
    expect(CONFIDENCE_LEVEL.EMERGING).toBe('emerging');
  });

  it('has CONFIDENT = "confident"', () => {
    expect(CONFIDENCE_LEVEL.CONFIDENT).toBe('confident');
  });
});

// =============================================================================
// CONFIDENCE_LEVEL_ORDER
// =============================================================================

describe('CONFIDENCE_LEVEL_ORDER', () => {
  it('is a frozen array with 5 elements in ascending rank order', () => {
    expect(Object.isFrozen(CONFIDENCE_LEVEL_ORDER)).toBe(true);
    expect(CONFIDENCE_LEVEL_ORDER.length).toBe(5);
  });

  it('starts with pending and ends with confident', () => {
    expect(CONFIDENCE_LEVEL_ORDER[0]).toBe('pending');
    expect(CONFIDENCE_LEVEL_ORDER[4]).toBe('confident');
  });

  it('rank of emerging is higher than provisional', () => {
    const emerIdx = CONFIDENCE_LEVEL_ORDER.indexOf('emerging');
    const provIdx = CONFIDENCE_LEVEL_ORDER.indexOf('provisional');
    expect(emerIdx).toBeGreaterThan(provIdx);
  });
});

// =============================================================================
// DELEGATION_STATUS
// =============================================================================

describe('DELEGATION_STATUS', () => {
  it('has ACTIVE, REVOKED, EXPIRED', () => {
    expect(DELEGATION_STATUS.ACTIVE).toBe('active');
    expect(DELEGATION_STATUS.REVOKED).toBe('revoked');
    expect(DELEGATION_STATUS.EXPIRED).toBe('expired');
  });
});

// =============================================================================
// AUTHORITY_STATUS
// =============================================================================

describe('AUTHORITY_STATUS', () => {
  it('has ACTIVE = "active"', () => {
    expect(AUTHORITY_STATUS.ACTIVE).toBe('active');
  });

  it('has REVOKED = "revoked"', () => {
    expect(AUTHORITY_STATUS.REVOKED).toBe('revoked');
  });

  it('has RETIRED = "retired"', () => {
    expect(AUTHORITY_STATUS.RETIRED).toBe('retired');
  });
});

// =============================================================================
// HANDSHAKE_OUTCOME
// =============================================================================

describe('HANDSHAKE_OUTCOME', () => {
  it('has ACCEPTED = "accepted"', () => {
    expect(HANDSHAKE_OUTCOME.ACCEPTED).toBe('accepted');
  });

  it('has REJECTED = "rejected"', () => {
    expect(HANDSHAKE_OUTCOME.REJECTED).toBe('rejected');
  });

  it('has EXPIRED = "expired"', () => {
    expect(HANDSHAKE_OUTCOME.EXPIRED).toBe('expired');
  });
});

// =============================================================================
// RECEIPT_DISPUTE_STATUS
// =============================================================================

describe('RECEIPT_DISPUTE_STATUS', () => {
  it('has CHALLENGED = "challenged"', () => {
    expect(RECEIPT_DISPUTE_STATUS.CHALLENGED).toBe('challenged');
  });
});

// =============================================================================
// CONTINUITY_STATUS
// =============================================================================

describe('CONTINUITY_STATUS', () => {
  it('has PENDING = "pending"', () => {
    expect(CONTINUITY_STATUS.PENDING).toBe('pending');
  });

  it('has UNDER_CHALLENGE = "under_challenge"', () => {
    expect(CONTINUITY_STATUS.UNDER_CHALLENGE).toBe('under_challenge');
  });

  it('has APPROVED_FULL = "approved_full"', () => {
    expect(CONTINUITY_STATUS.APPROVED_FULL).toBe('approved_full');
  });

  it('has APPROVED_PARTIAL = "approved_partial"', () => {
    expect(CONTINUITY_STATUS.APPROVED_PARTIAL).toBe('approved_partial');
  });

  it('has REJECTED = "rejected"', () => {
    expect(CONTINUITY_STATUS.REJECTED).toBe('rejected');
  });

  it('has EXPIRED = "expired"', () => {
    expect(CONTINUITY_STATUS.EXPIRED).toBe('expired');
  });
});

// =============================================================================
// NEED_STATUS
// =============================================================================

describe('NEED_STATUS', () => {
  it('has COMPLETED = "completed"', () => {
    expect(NEED_STATUS.COMPLETED).toBe('completed');
  });

  it('has EXPIRED = "expired"', () => {
    expect(NEED_STATUS.EXPIRED).toBe('expired');
  });
});

// =============================================================================
// OPERATOR_APPLICATION_STATUS
// =============================================================================

describe('OPERATOR_APPLICATION_STATUS', () => {
  it('has PENDING = "pending"', () => {
    expect(OPERATOR_APPLICATION_STATUS.PENDING).toBe('pending');
  });
});

// (lib/design-tokens.js was deleted — duplicate of lib/tokens.js with no
// callers in app/ or components/. Tests that exercised it are removed
// alongside the module so the test suite doesn't import a non-existent
// file.)
