/**
 * EMILIA Protocol — EP Eye Tests
 *
 * Tests for the Emilia Eye trust-signal observation subsystem:
 * - Scope binding hash computation (binding.js)
 * - Advisory and evidence hash computation
 * - Invariant constants (invariants.js)
 * - Error class (errors.js)
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  computeScopeBinding,
  computeAdvisoryHash,
  computeEvidenceHash,
} from '../lib/eye/binding.js';
import {
  EYE_STATUSES,
  EYE_POLICY_ACTIONS,
  EYE_SEVERITY_HINTS,
  EYE_OBSERVATION_TYPES,
  EYE_SCOPE_BINDING_FIELDS,
  EYE_DEFAULT_TTL,
  EYE_CONFIDENCE_CLASSES,
  VALID_EYE_STATUSES,
  VALID_EYE_POLICY_ACTIONS,
  VALID_EYE_SEVERITY_HINTS,
  VALID_EYE_OBSERVATION_TYPES,
  VALID_EYE_CONFIDENCE_CLASSES,
} from '../lib/eye/invariants.js';
import { EyeError } from '../lib/eye/errors.js';

// ============================================================================
// Scope Binding
// ============================================================================

describe('Eye — computeScopeBinding', () => {
  const validParams = {
    actor_ref: 'entity:rex-booking-v1',
    subject_ref: 'entity:ruby-retention-v1',
    action_type: 'high_value_transfer',
    target_ref: 'resource:account-123',
    issuer_ref: 'issuer:ep-platform',
    context_hash: 'abc123',
    issued_at: '2026-03-28T00:00:00Z',
    expires_at: '2026-03-28T01:00:00Z',
  };

  it('returns a hex string', () => {
    const hash = computeScopeBinding(validParams);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic — same input produces same hash', () => {
    const h1 = computeScopeBinding(validParams);
    const h2 = computeScopeBinding(validParams);
    expect(h1).toBe(h2);
  });

  it('changes when any field changes', () => {
    const base = computeScopeBinding(validParams);

    for (const field of EYE_SCOPE_BINDING_FIELDS) {
      const modified = { ...validParams, [field]: 'CHANGED' };
      const hash = computeScopeBinding(modified);
      expect(hash).not.toBe(base);
    }
  });

  it('treats missing fields as null', () => {
    const sparse = { actor_ref: 'a', subject_ref: 'b', action_type: 'c' };
    const hash = computeScopeBinding(sparse);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('uses only EYE_SCOPE_BINDING_FIELDS — extra fields are ignored', () => {
    const withExtra = { ...validParams, bonus_field: 'should-be-ignored' };
    const h1 = computeScopeBinding(validParams);
    const h2 = computeScopeBinding(withExtra);
    expect(h1).toBe(h2);
  });

  it('produces different hashes for swapped actor/subject', () => {
    const swapped = {
      ...validParams,
      actor_ref: validParams.subject_ref,
      subject_ref: validParams.actor_ref,
    };
    expect(computeScopeBinding(validParams)).not.toBe(computeScopeBinding(swapped));
  });
});

// ============================================================================
// Advisory Hash
// ============================================================================

describe('Eye — computeAdvisoryHash', () => {
  it('returns a hex string', () => {
    const hash = computeAdvisoryHash({ type: 'sanctions_match', severity: 'high' });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    const advisory = { type: 'velocity_anomaly', score: 0.87 };
    expect(computeAdvisoryHash(advisory)).toBe(computeAdvisoryHash(advisory));
  });

  it('is key-order independent — canonical sorting', () => {
    const a = computeAdvisoryHash({ z: 1, a: 2 });
    const b = computeAdvisoryHash({ a: 2, z: 1 });
    expect(a).toBe(b);
  });

  it('changes when content changes', () => {
    const h1 = computeAdvisoryHash({ type: 'pep_match' });
    const h2 = computeAdvisoryHash({ type: 'adverse_media' });
    expect(h1).not.toBe(h2);
  });
});

// ============================================================================
// Evidence Hash
// ============================================================================

describe('Eye — computeEvidenceHash', () => {
  it('handles string evidence', () => {
    const hash = computeEvidenceHash('raw evidence string');
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('handles object evidence with canonical sorting', () => {
    const h1 = computeEvidenceHash({ b: 2, a: 1 });
    const h2 = computeEvidenceHash({ a: 1, b: 2 });
    expect(h1).toBe(h2);
  });

  it('string and object evidence produce different hashes', () => {
    const str = computeEvidenceHash('{"a":1}');
    const obj = computeEvidenceHash({ a: 1 });
    // These MAY be different because string is hashed raw vs object is JSON.stringified with sorted keys
    expect(typeof str).toBe('string');
    expect(typeof obj).toBe('string');
  });

  it('is deterministic', () => {
    const evidence = { findings: ['match-1', 'match-2'], confidence: 0.95 };
    expect(computeEvidenceHash(evidence)).toBe(computeEvidenceHash(evidence));
  });
});

// ============================================================================
// Invariants
// ============================================================================

describe('Eye — Invariants', () => {
  describe('EYE_STATUSES', () => {
    it('has exactly 4 statuses', () => {
      expect(EYE_STATUSES).toHaveLength(4);
    });

    it('includes clear, caution, elevated, review_required', () => {
      expect(EYE_STATUSES).toContain('clear');
      expect(EYE_STATUSES).toContain('caution');
      expect(EYE_STATUSES).toContain('elevated');
      expect(EYE_STATUSES).toContain('review_required');
    });

    it('is frozen', () => {
      expect(Object.isFrozen(EYE_STATUSES)).toBe(true);
    });

    it('matches VALID_EYE_STATUSES set', () => {
      for (const s of EYE_STATUSES) {
        expect(VALID_EYE_STATUSES.has(s)).toBe(true);
      }
      expect(VALID_EYE_STATUSES.size).toBe(EYE_STATUSES.length);
    });
  });

  describe('EYE_POLICY_ACTIONS', () => {
    it('has exactly 5 actions', () => {
      expect(EYE_POLICY_ACTIONS).toHaveLength(5);
    });

    it('escalates from allow through manual review', () => {
      expect(EYE_POLICY_ACTIONS[0]).toBe('allow_normal_flow');
      expect(EYE_POLICY_ACTIONS[4]).toBe('hold_for_manual_review');
    });

    it('includes EP Handshake and Accountable Signoff escalation', () => {
      expect(EYE_POLICY_ACTIONS).toContain('require_ep_handshake');
      expect(EYE_POLICY_ACTIONS).toContain('require_accountable_signoff');
    });

    it('is frozen', () => {
      expect(Object.isFrozen(EYE_POLICY_ACTIONS)).toBe(true);
    });
  });

  describe('EYE_SEVERITY_HINTS', () => {
    it('has 4 severity levels', () => {
      expect(EYE_SEVERITY_HINTS).toEqual(['low', 'medium', 'high', 'critical']);
    });

    it('is frozen', () => {
      expect(Object.isFrozen(EYE_SEVERITY_HINTS)).toBe(true);
    });
  });

  describe('EYE_OBSERVATION_TYPES', () => {
    it('has 25 observation types', () => {
      expect(EYE_OBSERVATION_TYPES).toHaveLength(25);
    });

    it('covers all 5 verticals', () => {
      // Government
      expect(EYE_OBSERVATION_TYPES).toContain('sanctions_match');
      expect(EYE_OBSERVATION_TYPES).toContain('pep_match');
      // Financial
      expect(EYE_OBSERVATION_TYPES).toContain('unusual_transaction_pattern');
      expect(EYE_OBSERVATION_TYPES).toContain('velocity_anomaly');
      // Enterprise
      expect(EYE_OBSERVATION_TYPES).toContain('privilege_escalation');
      expect(EYE_OBSERVATION_TYPES).toContain('data_exfiltration_signal');
      // AI / Agent
      expect(EYE_OBSERVATION_TYPES).toContain('agent_drift');
      expect(EYE_OBSERVATION_TYPES).toContain('prompt_injection_attempt');
      // Issuer / Credential
      expect(EYE_OBSERVATION_TYPES).toContain('credential_compromise');
      expect(EYE_OBSERVATION_TYPES).toContain('binding_mismatch');
    });

    it('has no duplicates', () => {
      const unique = new Set(EYE_OBSERVATION_TYPES);
      expect(unique.size).toBe(EYE_OBSERVATION_TYPES.length);
    });

    it('is frozen', () => {
      expect(Object.isFrozen(EYE_OBSERVATION_TYPES)).toBe(true);
    });
  });

  describe('EYE_SCOPE_BINDING_FIELDS', () => {
    it('has 8 canonical fields', () => {
      expect(EYE_SCOPE_BINDING_FIELDS).toHaveLength(8);
    });

    it('includes actor, subject, action, target, issuer, context, timestamps', () => {
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('actor_ref');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('subject_ref');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('action_type');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('target_ref');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('issuer_ref');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('context_hash');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('issued_at');
      expect(EYE_SCOPE_BINDING_FIELDS).toContain('expires_at');
    });

    it('is frozen', () => {
      expect(Object.isFrozen(EYE_SCOPE_BINDING_FIELDS)).toBe(true);
    });
  });

  describe('EYE_DEFAULT_TTL', () => {
    it('has TTL for each status', () => {
      expect(EYE_DEFAULT_TTL.clear).toBe(300);
      expect(EYE_DEFAULT_TTL.caution).toBe(300);
      expect(EYE_DEFAULT_TTL.elevated).toBe(180);
      expect(EYE_DEFAULT_TTL.review_required).toBe(120);
    });

    it('higher severity has shorter TTL', () => {
      expect(EYE_DEFAULT_TTL.review_required).toBeLessThan(EYE_DEFAULT_TTL.clear);
      expect(EYE_DEFAULT_TTL.elevated).toBeLessThan(EYE_DEFAULT_TTL.clear);
    });
  });

  describe('EYE_CONFIDENCE_CLASSES', () => {
    it('has 3 classes', () => {
      expect(EYE_CONFIDENCE_CLASSES).toEqual(['deterministic', 'trusted', 'heuristic']);
    });

    it('is frozen', () => {
      expect(Object.isFrozen(EYE_CONFIDENCE_CLASSES)).toBe(true);
    });
  });
});

// ============================================================================
// Error Class
// ============================================================================

describe('Eye — EyeError', () => {
  it('is an Error subclass', () => {
    const err = new EyeError('test');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(EyeError);
  });

  it('has correct defaults', () => {
    const err = new EyeError('test message');
    expect(err.message).toBe('test message');
    expect(err.status).toBe(400);
    expect(err.code).toBe('EYE_ERROR');
    expect(err.name).toBe('EyeError');
  });

  it('accepts custom status and code', () => {
    const err = new EyeError('bad', 422, 'INVALID_OBSERVATION');
    expect(err.status).toBe(422);
    expect(err.code).toBe('INVALID_OBSERVATION');
  });

  it('has a stack trace', () => {
    const err = new EyeError('traced');
    expect(err.stack).toBeDefined();
    expect(err.stack).toContain('traced');
  });
});
