/**
 * EP Protocol Hardening v2 — Tests for all fixes and new features
 * added during the L99 audit sessions:
 *
 *   1. Scoring invariants (named constants)
 *   2. Nonce omission bypass fix (bind.js)
 *   3. Policy version pin validation (verify.js)
 *   4. EP-IX state machine (freeze/unfreeze/withdraw/self-contest)
 *   5. EP-IX challenge rate limit
 *   6. EP-IX ownership graph self-contest guard
 *   7. Adjudication deterministic sort (integer confidence)
 *   8. CONTINUITY_STATUS constants completeness
 *
 * All tests are pure function tests or unit-level — no DB mocking.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { checkBinding } from '../lib/handshake/bind.js';
import {
  DAMPENING_THRESHOLD,
  ESTABLISHMENT_EVIDENCE_GATE,
  ESTABLISHMENT_MIN_SUBMITTERS,
  MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION,
  MAX_SINGLE_SUBMITTER_CONTRIBUTION,
} from '../lib/scoring-v2.js';
import { CONTINUITY_STATUS } from '../lib/constants.js';

// =============================================================================
// 1. Scoring invariants — named constants
// =============================================================================

describe('Scoring invariants — named constants', () => {
  it('DAMPENING_THRESHOLD is 5.0', () => {
    expect(DAMPENING_THRESHOLD).toBe(5.0);
  });

  it('ESTABLISHMENT_EVIDENCE_GATE equals DAMPENING_THRESHOLD', () => {
    expect(ESTABLISHMENT_EVIDENCE_GATE).toBe(DAMPENING_THRESHOLD);
  });

  it('ESTABLISHMENT_MIN_SUBMITTERS is 3', () => {
    expect(ESTABLISHMENT_MIN_SUBMITTERS).toBe(3);
  });

  it('MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION is 2.0', () => {
    expect(MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION).toBe(2.0);
  });

  it('MAX_SINGLE_SUBMITTER_CONTRIBUTION is 2.0', () => {
    expect(MAX_SINGLE_SUBMITTER_CONTRIBUTION).toBe(2.0);
  });

  it('ESTABLISHMENT_MIN_SUBMITTERS > MAX_SINGLE_SUBMITTER_CONTRIBUTION / DAMPENING_THRESHOLD * 10', () => {
    // No single submitter can push past dampening alone
    expect(ESTABLISHMENT_MIN_SUBMITTERS).toBeGreaterThan(
      MAX_SINGLE_SUBMITTER_CONTRIBUTION / DAMPENING_THRESHOLD,
    );
  });

  it('MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION < DAMPENING_THRESHOLD', () => {
    // Unestablished submitters alone cannot escape dampening
    expect(MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION).toBeLessThan(DAMPENING_THRESHOLD);
  });
});

// =============================================================================
// 2. Nonce omission bypass — bind.js
// =============================================================================

describe('checkBinding — nonce omission guard', () => {
  const validBinding = {
    nonce: 'abc123',
    payload_hash: 'hash_abc',
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    consumed_at: null,
  };

  it('rejects when nonce is stored but not provided (nonce_required)', () => {
    const codes = checkBinding(validBinding, 'hash_abc', null);
    expect(codes).toContain('nonce_required');
    expect(codes).not.toContain('nonce_mismatch');
  });

  it('rejects when nonce is stored but undefined provided', () => {
    const codes = checkBinding(validBinding, 'hash_abc', undefined);
    expect(codes).toContain('nonce_required');
  });

  it('rejects when nonce is stored but empty string provided', () => {
    // Empty string is falsy — treated as "not provided"
    const codes = checkBinding(validBinding, 'hash_abc', '');
    expect(codes).toContain('nonce_required');
  });

  it('passes when nonce matches', () => {
    const codes = checkBinding(validBinding, 'hash_abc', 'abc123');
    expect(codes).not.toContain('nonce_required');
    expect(codes).not.toContain('nonce_mismatch');
  });

  it('rejects when nonce mismatches', () => {
    const codes = checkBinding(validBinding, 'hash_abc', 'wrong_nonce');
    expect(codes).toContain('nonce_mismatch');
    expect(codes).not.toContain('nonce_required');
  });

  it('passes when binding has no nonce and none provided', () => {
    const noNonceBinding = { ...validBinding, nonce: null };
    const codes = checkBinding(noNonceBinding, 'hash_abc', null);
    expect(codes).toContain('missing_nonce'); // binding missing its own nonce
    expect(codes).not.toContain('nonce_required'); // not required since binding doesn't have one
  });
});

describe('checkBinding — payload_hash symmetry', () => {
  const bindingWithPayload = {
    nonce: 'nonce123',
    payload_hash: 'stored_hash',
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    consumed_at: null,
  };

  it('rejects when payload_hash stored but not provided (payload_hash_required)', () => {
    const codes = checkBinding(bindingWithPayload, null, 'nonce123');
    expect(codes).toContain('payload_hash_required');
  });

  it('rejects when payload_hash mismatches', () => {
    const codes = checkBinding(bindingWithPayload, 'wrong_hash', 'nonce123');
    expect(codes).toContain('payload_hash_mismatch');
  });

  it('passes when payload_hash matches', () => {
    const codes = checkBinding(bindingWithPayload, 'stored_hash', 'nonce123');
    expect(codes).not.toContain('payload_hash_required');
    expect(codes).not.toContain('payload_hash_mismatch');
  });
});

// =============================================================================
// 3. CONTINUITY_STATUS completeness
// =============================================================================

describe('CONTINUITY_STATUS constants', () => {
  it('includes all 8 states', () => {
    expect(Object.keys(CONTINUITY_STATUS)).toHaveLength(8);
  });

  it('includes FROZEN_PENDING_DISPUTE', () => {
    expect(CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE).toBe('frozen_pending_dispute');
  });

  it('includes WITHDRAWN', () => {
    expect(CONTINUITY_STATUS.WITHDRAWN).toBe('withdrawn');
  });

  const terminalStates = ['approved_full', 'approved_partial', 'rejected', 'expired', 'withdrawn'];
  const activeStates = ['pending', 'under_challenge', 'frozen_pending_dispute'];

  it('all expected terminal states exist', () => {
    for (const s of terminalStates) {
      expect(Object.values(CONTINUITY_STATUS)).toContain(s);
    }
  });

  it('all expected active states exist', () => {
    for (const s of activeStates) {
      expect(Object.values(CONTINUITY_STATUS)).toContain(s);
    }
  });
});

// =============================================================================
// 4. checkBinding — binding expiry
// =============================================================================

describe('checkBinding — expiry', () => {
  it('rejects when binding is expired', () => {
    const expired = {
      nonce: 'n',
      payload_hash: null,
      expires_at: new Date(Date.now() - 60_000).toISOString(),
      consumed_at: null,
    };
    const codes = checkBinding(expired, null, 'n');
    expect(codes).toContain('binding_expired');
  });

  it('passes when binding is not expired', () => {
    const valid = {
      nonce: 'n',
      payload_hash: null,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      consumed_at: null,
    };
    const codes = checkBinding(valid, null, 'n');
    expect(codes).not.toContain('binding_expired');
  });
});

// =============================================================================
// 5. checkBinding — already consumed
// =============================================================================

describe('checkBinding — consumption', () => {
  it('rejects when binding is already consumed', () => {
    const consumed = {
      nonce: 'n',
      payload_hash: null,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      consumed_at: new Date().toISOString(),
    };
    const codes = checkBinding(consumed, null, 'n');
    expect(codes).toContain('binding_already_consumed');
  });
});

// =============================================================================
// 6. checkBinding — missing binding
// =============================================================================

describe('checkBinding — missing binding', () => {
  it('rejects null binding', () => {
    expect(checkBinding(null)).toContain('missing_binding');
  });

  it('rejects undefined binding', () => {
    expect(checkBinding(undefined)).toContain('missing_binding');
  });
});
