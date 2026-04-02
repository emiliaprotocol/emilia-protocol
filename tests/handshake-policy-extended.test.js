/**
 * Extended tests for lib/handshake/policy.js
 *
 * Covers remaining gaps after handshake-policy.test.js:
 *   - validatePolicyRules edge cases (array/non-object party defs, non-string claims items,
 *     missing minimum_assurance, non-string minimum_assurance, non-object required_parties)
 *   - loadPolicy with undefined version (vs null)
 *   - resolvePolicy with policy_key only (no version)
 *   - POLICY_SCHEMA structure
 *   - checkClaimsAgainstPolicy with no required_claims property
 *   - getRequiredPartiesForMode with empty required_parties object
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi } from 'vitest';
import {
  POLICY_SCHEMA,
  validatePolicyRules,
  loadPolicy,
  loadPolicyById,
  resolvePolicy,
  getRequiredPartiesForMode,
  checkClaimsAgainstPolicy,
} from '../lib/handshake/policy.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function validRules(overrides = {}) {
  return {
    required_parties: {
      initiator: {
        required_claims: ['email'],
        minimum_assurance: 'medium',
      },
    },
    binding: {
      payload_hash_required: true,
      nonce_required: true,
      expiry_minutes: 30,
    },
    storage: {
      store_raw_payload: false,
      store_normalized_claims: true,
    },
    ...overrides,
  };
}

function makeSupabaseMock({ data = null, error = null } = {}) {
  const maybeSingle = vi.fn().mockResolvedValue({ data, error });
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    maybeSingle,
  };
  return { from: vi.fn().mockReturnValue(chain), chain };
}

// ── POLICY_SCHEMA structure ───────────────────────────────────────────────────

describe('POLICY_SCHEMA', () => {
  it('has required top-level keys: required_parties, binding, storage', () => {
    expect(POLICY_SCHEMA.required).toContain('required_parties');
    expect(POLICY_SCHEMA.required).toContain('binding');
    expect(POLICY_SCHEMA.required).toContain('storage');
  });

  it('binding schema requires payload_hash_required, nonce_required, expiry_minutes', () => {
    const bindingSchema = POLICY_SCHEMA.properties.binding;
    expect(bindingSchema.required).toContain('payload_hash_required');
    expect(bindingSchema.required).toContain('nonce_required');
    expect(bindingSchema.required).toContain('expiry_minutes');
  });

  it('storage schema requires store_raw_payload and store_normalized_claims', () => {
    const storageSchema = POLICY_SCHEMA.properties.storage;
    expect(storageSchema.required).toContain('store_raw_payload');
    expect(storageSchema.required).toContain('store_normalized_claims');
  });
});

// ── validatePolicyRules — deeper edge cases ───────────────────────────────────

describe('validatePolicyRules — party definition edge cases', () => {
  it('returns error when a party definition is an array (not object)', () => {
    const rules = validRules({
      required_parties: { initiator: [] },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('initiator'))).toBe(true);
  });

  it('returns error when a party definition is null', () => {
    const rules = validRules({
      required_parties: { initiator: null },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
  });

  it('returns error when required_claims item is not a string', () => {
    const rules = validRules({
      required_parties: {
        initiator: { required_claims: [123, 'email'], minimum_assurance: 'low' },
      },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('required_claims[0]'))).toBe(true);
  });

  it('returns error when required_claims is not an array', () => {
    const rules = validRules({
      required_parties: {
        initiator: { required_claims: 'email', minimum_assurance: 'low' },
      },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('required_claims'))).toBe(true);
  });

  it('returns error when minimum_assurance is not a string', () => {
    const rules = validRules({
      required_parties: {
        initiator: { required_claims: [], minimum_assurance: 42 },
      },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('minimum_assurance'))).toBe(true);
  });

  it('returns error when required_parties is an array', () => {
    const rules = validRules({ required_parties: ['initiator'] });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('required_parties'))).toBe(true);
  });

  it('returns error for undefined input', () => {
    const result = validatePolicyRules(undefined);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('rules must be a non-null object');
  });

  it('handles party missing both required_claims and minimum_assurance', () => {
    const rules = validRules({
      required_parties: { actor: {} },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(2);
  });
});

describe('validatePolicyRules — binding edge cases', () => {
  it('returns error when binding is an array', () => {
    const rules = validRules({ binding: [] });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('binding'))).toBe(true);
  });

  it('returns error when binding is null', () => {
    const rules = validRules({ binding: null });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
  });

  it('returns error when binding.nonce_required is not boolean', () => {
    const rules = validRules();
    rules.binding.nonce_required = 'true';
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('nonce_required'))).toBe(true);
  });

  it('returns error when binding is missing nonce_required', () => {
    const rules = validRules();
    delete rules.binding.nonce_required;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('nonce_required'))).toBe(true);
  });

  it('returns error when binding is missing expiry_minutes', () => {
    const rules = validRules();
    delete rules.binding.expiry_minutes;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('expiry_minutes'))).toBe(true);
  });

  it('returns error when binding is missing payload_hash_required', () => {
    const rules = validRules();
    delete rules.binding.payload_hash_required;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('payload_hash_required'))).toBe(true);
  });
});

describe('validatePolicyRules — storage edge cases', () => {
  it('returns error when storage is null', () => {
    const rules = validRules({ storage: null });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
  });

  it('returns error when storage is an array', () => {
    const rules = validRules({ storage: [] });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('storage'))).toBe(true);
  });

  it('returns error when storage.store_normalized_claims is not boolean', () => {
    const rules = validRules();
    rules.storage.store_normalized_claims = 1;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('store_normalized_claims'))).toBe(true);
  });

  it('returns error when storage is missing store_normalized_claims', () => {
    const rules = validRules();
    delete rules.storage.store_normalized_claims;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('store_normalized_claims'))).toBe(true);
  });

  it('returns error when storage is missing store_raw_payload', () => {
    const rules = validRules();
    delete rules.storage.store_raw_payload;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('store_raw_payload'))).toBe(true);
  });
});

// ── loadPolicy — version undefined path ──────────────────────────────────────

describe('loadPolicy — undefined version loads latest active', () => {
  it('loads latest active when version is undefined (not just null)', async () => {
    const policyRow = { policy_id: 'pol-latest', policy_key: 'default', version: 7, status: 'active' };
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: policyRow, error: null }),
    };
    const mockSupa = { from: vi.fn().mockReturnValue(chain) };

    const result = await loadPolicy(mockSupa, 'default', undefined);
    expect(result).not.toBeNull();
    expect(result.version).toBe(7);
    // Should filter by status = 'active'
    expect(chain.eq).toHaveBeenCalledWith('status', 'active');
  });
});

// ── resolvePolicy — all branches ─────────────────────────────────────────────

describe('resolvePolicy — all identifier branches', () => {
  it('uses loadPolicyById path when policy_id is provided (ignores policy_key)', async () => {
    const policyRow = { policy_id: 'pol-by-id' };
    const { from: supabaseFrom } = makeSupabaseMock({ data: policyRow });
    const result = await resolvePolicy({ from: supabaseFrom }, {
      policy_id: 'pol-by-id',
      policy_key: 'default', // should be ignored
    });
    expect(result.policy_id).toBe('pol-by-id');
  });

  it('uses loadPolicy path when only policy_key is provided (no version)', async () => {
    const policyRow = { policy_id: 'pol-key', policy_key: 'strict', version: 3 };
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: policyRow, error: null }),
    };
    const mockSupa = { from: vi.fn().mockReturnValue(chain) };
    const result = await resolvePolicy(mockSupa, { policy_key: 'strict' });
    expect(result.policy_key).toBe('strict');
  });

  it('returns null when neither policy_id nor policy_key are provided', async () => {
    const result = await resolvePolicy({}, { policy_version: 1 });
    expect(result).toBeNull();
  });
});

// ── getRequiredPartiesForMode — edge cases ────────────────────────────────────

describe('getRequiredPartiesForMode — extended', () => {
  it('returns empty array when required_parties is empty object', () => {
    const policy = { rules: { required_parties: {} } };
    expect(getRequiredPartiesForMode(policy)).toEqual([]);
  });

  it('returns all role keys from required_parties', () => {
    const policy = {
      rules: {
        required_parties: {
          initiator: { required_claims: [], minimum_assurance: 'low' },
          responder: { required_claims: [], minimum_assurance: 'medium' },
          delegate: { required_claims: [], minimum_assurance: 'high' },
        },
      },
    };
    const roles = getRequiredPartiesForMode(policy);
    expect(roles).toHaveLength(3);
    expect(roles).toContain('initiator');
    expect(roles).toContain('responder');
    expect(roles).toContain('delegate');
  });
});

// ── checkClaimsAgainstPolicy — extended ──────────────────────────────────────

describe('checkClaimsAgainstPolicy — extended', () => {
  it('returns satisfied: true when policyRequirements has no required_claims property', () => {
    // If required_claims is absent (not an array), the function returns satisfied: true
    const result = checkClaimsAgainstPolicy({ email: 'x' }, { minimum_assurance: 'low' });
    expect(result.satisfied).toBe(true);
  });

  it('returns satisfied: true with empty normalizedClaims and empty required_claims', () => {
    const result = checkClaimsAgainstPolicy({}, { required_claims: [] });
    expect(result.satisfied).toBe(true);
    expect(result.missing).toHaveLength(0);
  });

  it('returns all missing claims when normalizedClaims is empty', () => {
    const result = checkClaimsAgainstPolicy({}, { required_claims: ['a', 'b', 'c'] });
    expect(result.satisfied).toBe(false);
    expect(result.missing).toEqual(['a', 'b', 'c']);
  });

  it('handles normalizedClaims as null gracefully', () => {
    const result = checkClaimsAgainstPolicy(null, { required_claims: ['email'] });
    expect(result.satisfied).toBe(false);
    expect(result.missing).toContain('email');
  });

  it('returns satisfied: true when claim value is 0 (falsy but present)', () => {
    // 0 is a valid claim value (not null/undefined) — should not be missing
    const result = checkClaimsAgainstPolicy({ count: 0 }, { required_claims: ['count'] });
    // 0 is not null/undefined, so it should be satisfied
    expect(result.missing).not.toContain('count');
  });

  it('returns satisfied: true when claim value is false (falsy but present)', () => {
    const result = checkClaimsAgainstPolicy({ verified: false }, { required_claims: ['verified'] });
    expect(result.missing).not.toContain('verified');
  });
});
