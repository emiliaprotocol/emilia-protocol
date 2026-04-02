/**
 * Tests for lib/handshake/policy.js
 *
 * Covers: validatePolicyRules, loadPolicy, loadPolicyById, resolvePolicy,
 * getRequiredPartiesForMode, checkClaimsAgainstPolicy
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Import under test (pure functions — no Supabase mock needed for most) ────

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
        required_claims: ['email', 'name'],
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
  const from = vi.fn().mockReturnValue(chain);
  return { from, chain };
}

// ── validatePolicyRules tests ─────────────────────────────────────────────────

describe('validatePolicyRules — valid rules', () => {
  it('returns valid: true for well-formed rules', () => {
    const result = validatePolicyRules(validRules());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('accepts multiple required_parties', () => {
    const rules = validRules({
      required_parties: {
        initiator: { required_claims: ['email'], minimum_assurance: 'low' },
        responder: { required_claims: ['org_id'], minimum_assurance: 'high' },
      },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(true);
  });

  it('accepts empty required_claims array', () => {
    const rules = validRules({
      required_parties: {
        initiator: { required_claims: [], minimum_assurance: 'low' },
      },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(true);
  });

  it('accepts all valid assurance levels', () => {
    for (const level of ['low', 'medium', 'substantial', 'high']) {
      const rules = validRules({
        required_parties: {
          actor: { required_claims: [], minimum_assurance: level },
        },
      });
      const result = validatePolicyRules(rules);
      expect(result.valid).toBe(true);
    }
  });
});

describe('validatePolicyRules — invalid rules', () => {
  it('returns error for null input', () => {
    const result = validatePolicyRules(null);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('rules must be a non-null object');
  });

  it('returns error for array input', () => {
    const result = validatePolicyRules([]);
    expect(result.valid).toBe(false);
  });

  it('returns error when required_parties is missing', () => {
    const { required_parties, ...noRP } = validRules();
    const result = validatePolicyRules(noRP);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('required_parties'))).toBe(true);
  });

  it('returns error when binding is missing', () => {
    const { binding, ...noBinding } = validRules();
    const result = validatePolicyRules(noBinding);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('binding'))).toBe(true);
  });

  it('returns error when storage is missing', () => {
    const { storage, ...noStorage } = validRules();
    const result = validatePolicyRules(noStorage);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('storage'))).toBe(true);
  });

  it('returns error when party missing required_claims', () => {
    const rules = validRules({
      required_parties: { actor: { minimum_assurance: 'low' } },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('required_claims'))).toBe(true);
  });

  it('returns error when party minimum_assurance is invalid', () => {
    const rules = validRules({
      required_parties: { actor: { required_claims: [], minimum_assurance: 'ultra' } },
    });
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('minimum_assurance'))).toBe(true);
  });

  it('returns error when binding.payload_hash_required is not boolean', () => {
    const rules = validRules();
    rules.binding.payload_hash_required = 'yes';
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('payload_hash_required'))).toBe(true);
  });

  it('returns error when binding.expiry_minutes is not a number', () => {
    const rules = validRules();
    rules.binding.expiry_minutes = 'thirty';
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('expiry_minutes'))).toBe(true);
  });

  it('returns error when storage.store_raw_payload is not boolean', () => {
    const rules = validRules();
    rules.storage.store_raw_payload = 1;
    const result = validatePolicyRules(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('store_raw_payload'))).toBe(true);
  });

  it('accumulates multiple errors', () => {
    const result = validatePolicyRules({});
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(1);
  });
});

// ── loadPolicy tests ──────────────────────────────────────────────────────────

describe('loadPolicy', () => {
  it('returns policy data when found', async () => {
    const policyRow = { policy_id: 'pol-1', policy_key: 'default', version: 1 };
    const { from: supabaseFrom, chain } = makeSupabaseMock({ data: policyRow });
    const mockSupa = { from: supabaseFrom };

    const result = await loadPolicy(mockSupa, 'default', 1);
    expect(result).toEqual(policyRow);
  });

  it('returns null when no policy found', async () => {
    const { from: supabaseFrom } = makeSupabaseMock({ data: null });
    const result = await loadPolicy({ from: supabaseFrom }, 'unknown', 1);
    expect(result).toBeNull();
  });

  it('throws when DB error occurs', async () => {
    const { from: supabaseFrom } = makeSupabaseMock({ error: { message: 'db error' } });
    await expect(loadPolicy({ from: supabaseFrom }, 'key', 1))
      .rejects.toThrow('Failed to load policy');
  });

  it('loads latest active version when version is null', async () => {
    const policyRow = { policy_id: 'pol-latest', policy_key: 'default', version: 5, status: 'active' };
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: policyRow, error: null }),
    };
    const mockSupa = { from: vi.fn().mockReturnValue(chain) };

    const result = await loadPolicy(mockSupa, 'default', null);
    expect(result.version).toBe(5);
    expect(chain.eq).toHaveBeenCalledWith('status', 'active');
  });
});

// ── loadPolicyById tests ──────────────────────────────────────────────────────

describe('loadPolicyById', () => {
  it('returns policy when found by ID', async () => {
    const policyRow = { policy_id: 'pol-abc', policy_key: 'strict' };
    const { from: supabaseFrom } = makeSupabaseMock({ data: policyRow });
    const result = await loadPolicyById({ from: supabaseFrom }, 'pol-abc');
    expect(result.policy_id).toBe('pol-abc');
  });

  it('returns null when policy not found', async () => {
    const { from: supabaseFrom } = makeSupabaseMock({ data: null });
    const result = await loadPolicyById({ from: supabaseFrom }, 'nonexistent');
    expect(result).toBeNull();
  });

  it('throws when DB error occurs', async () => {
    const { from: supabaseFrom } = makeSupabaseMock({ error: { message: 'query failed' } });
    await expect(loadPolicyById({ from: supabaseFrom }, 'pol-1'))
      .rejects.toThrow('Failed to load policy by ID');
  });
});

// ── resolvePolicy tests ───────────────────────────────────────────────────────

describe('resolvePolicy', () => {
  it('returns null when no identifier provided', async () => {
    const result = await resolvePolicy({}, {});
    expect(result).toBeNull();
  });

  it('loads by policy_id when provided', async () => {
    const policyRow = { policy_id: 'pol-direct' };
    const { from: supabaseFrom } = makeSupabaseMock({ data: policyRow });
    const mockSupa = { from: supabaseFrom };

    const result = await resolvePolicy(mockSupa, { policy_id: 'pol-direct' });
    expect(result.policy_id).toBe('pol-direct');
  });

  it('loads by policy_key+version when both provided', async () => {
    const policyRow = { policy_id: 'pol-kv', policy_key: 'default', version: 2 };
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: policyRow, error: null }),
    };
    const mockSupa = { from: vi.fn().mockReturnValue(chain) };

    const result = await resolvePolicy(mockSupa, { policy_key: 'default', policy_version: 2 });
    expect(result.version).toBe(2);
  });

  it('loads latest version when only policy_key provided', async () => {
    const policyRow = { policy_id: 'pol-latest', policy_key: 'default', version: 10 };
    const chain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: policyRow, error: null }),
    };
    const mockSupa = { from: vi.fn().mockReturnValue(chain) };

    const result = await resolvePolicy(mockSupa, { policy_key: 'default' });
    expect(result.version).toBe(10);
  });
});

// ── getRequiredPartiesForMode tests ──────────────────────────────────────────

describe('getRequiredPartiesForMode', () => {
  it('returns role names from policy required_parties', () => {
    const policy = {
      rules: {
        required_parties: { initiator: {}, responder: {} },
      },
    };
    const result = getRequiredPartiesForMode(policy);
    expect(result).toContain('initiator');
    expect(result).toContain('responder');
    expect(result).toHaveLength(2);
  });

  it('returns empty array when policy is null', () => {
    expect(getRequiredPartiesForMode(null)).toEqual([]);
  });

  it('returns empty array when policy has no rules', () => {
    expect(getRequiredPartiesForMode({})).toEqual([]);
  });

  it('returns empty array when required_parties is absent', () => {
    expect(getRequiredPartiesForMode({ rules: {} })).toEqual([]);
  });
});

// ── checkClaimsAgainstPolicy tests ───────────────────────────────────────────

describe('checkClaimsAgainstPolicy', () => {
  it('returns satisfied: true when all required claims are present', () => {
    const result = checkClaimsAgainstPolicy(
      { email: 'alice@example.com', name: 'Alice' },
      { required_claims: ['email', 'name'] },
    );
    expect(result.satisfied).toBe(true);
    expect(result.missing).toHaveLength(0);
  });

  it('returns satisfied: false when claims are missing', () => {
    const result = checkClaimsAgainstPolicy(
      { email: 'alice@example.com' },
      { required_claims: ['email', 'phone'] },
    );
    expect(result.satisfied).toBe(false);
    expect(result.missing).toContain('phone');
  });

  it('returns satisfied: true when required_claims is empty', () => {
    const result = checkClaimsAgainstPolicy({}, { required_claims: [] });
    expect(result.satisfied).toBe(true);
  });

  it('returns satisfied: true when policyRequirements is null', () => {
    const result = checkClaimsAgainstPolicy({ email: 'x' }, null);
    expect(result.satisfied).toBe(true);
  });

  it('treats null claim values as missing', () => {
    const result = checkClaimsAgainstPolicy(
      { email: null },
      { required_claims: ['email'] },
    );
    expect(result.satisfied).toBe(false);
    expect(result.missing).toContain('email');
  });

  it('treats undefined claim values as missing', () => {
    const result = checkClaimsAgainstPolicy(
      { email: undefined },
      { required_claims: ['email'] },
    );
    expect(result.satisfied).toBe(false);
    expect(result.missing).toContain('email');
  });
});
