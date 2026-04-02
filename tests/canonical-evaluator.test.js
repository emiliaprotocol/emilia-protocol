/**
 * EP Canonical Evaluator — Unit Tests
 *
 * Covers: resolveEntity, fetchReceipts, fetchEstablishment, fetchDisputeSummary,
 * resolvePolicy, evaluateSoftwareChecks, and canonicalEvaluate (the main function).
 *
 * All external deps (supabase, scoring-v2) are fully mocked.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Supabase chain helper ────────────────────────────────────────────────────

function makeChain(resolveValue = { data: null, error: null }) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    contains: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    rpc: vi.fn().mockResolvedValue(resolveValue),
    // make the chain itself awaitable
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ── Mock declarations ────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();
const mockComputeTrustProfile = vi.fn();
const mockEvaluateTrustPolicy = vi.fn();
const mockValidateScoringWeights = vi.fn();

const MOCK_TRUST_POLICIES = {
  standard: { min_score: 0, min_confidence: 'none' },
  github_private_repo_safe_v1: { min_score: 70, min_confidence: 'medium', software_requirements: { publisher_verified: true } },
  npm_buildtime_safe_v1: { min_score: 75, min_confidence: 'medium', software_requirements: { registry_listed: true } },
  browser_extension_safe_v1: { min_score: 80, min_confidence: 'high' },
  mcp_server_safe_v1: { min_score: 85, min_confidence: 'high', software_requirements: { server_card_present: true } },
};

const MOCK_EP_WEIGHTS_V2 = { delivery: 0.2, behavioral: 0.4, consistency: 0.2, sentiment: 0.1, integrity: 0.1 };

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/scoring-v2.js', () => ({
  computeTrustProfile: (...args) => mockComputeTrustProfile(...args),
  evaluateTrustPolicy: (...args) => mockEvaluateTrustPolicy(...args),
  validateScoringWeights: (...args) => mockValidateScoringWeights(...args),
  TRUST_POLICIES: {
    standard: { min_score: 0, min_confidence: 'none' },
    github_private_repo_safe_v1: { min_score: 70, min_confidence: 'medium', software_requirements: { publisher_verified: true } },
    npm_buildtime_safe_v1: { min_score: 75, min_confidence: 'medium', software_requirements: { registry_listed: true } },
    browser_extension_safe_v1: { min_score: 80, min_confidence: 'high' },
    mcp_server_safe_v1: { min_score: 85, min_confidence: 'high', software_requirements: { server_card_present: true } },
  },
  EP_WEIGHTS_V2: { delivery: 0.2, behavioral: 0.4, consistency: 0.2, sentiment: 0.1, integrity: 0.1 },
}));

vi.mock('../lib/errors.js', () => ({
  TrustEvaluationError: class TrustEvaluationError extends Error {
    constructor(message, opts = {}) {
      super(message);
      this.name = 'TrustEvaluationError';
      this.code = opts.code || 'TRUST_EVALUATION_FAILED';
      this.status = opts.status || 500;
      if (opts.cause) this.cause = opts.cause;
    }
  },
}));

// Import after mocks
import {
  resolveEntity,
  fetchReceipts,
  fetchEstablishment,
  fetchDisputeSummary,
  resolvePolicy,
  evaluateSoftwareChecks,
  canonicalEvaluate,
} from '../lib/canonical-evaluator.js';

// ── Active entity fixture ────────────────────────────────────────────────────

function makeEntity(overrides = {}) {
  return {
    id: 'db-uuid-001',
    entity_id: 'acme-corp',
    display_name: 'ACME Corp',
    entity_type: 'organization',
    category: 'vendor',
    status: 'active',
    principal_id: null,
    software_meta: null,
    trust_snapshot: null,
    trust_materialized_at: null,
    ...overrides,
  };
}

function makeTrustProfile(overrides = {}) {
  return {
    profile: { delivery: 90, behavioral: { completion_rate: 0.95, dispute_rate: 0.02, total_observed: 20 } },
    score: 82,
    confidence: 'high',
    effectiveEvidence: 15.4,
    qualityGatedEvidence: 12.1,
    uniqueSubmitters: 8,
    receiptCount: 20,
    anomaly: null,
    dispute_dampened_count: 0,
    weights_version: 'ep-v2-default',
    ...overrides,
  };
}

// ── Setup ────────────────────────────────────────────────────────────────────

let mockSupabase;

beforeEach(() => {
  vi.clearAllMocks();

  mockSupabase = {
    from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
    rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
  };
  mockGetServiceClient.mockReturnValue(mockSupabase);

  // Default trust profile
  mockComputeTrustProfile.mockReturnValue(makeTrustProfile());
  mockEvaluateTrustPolicy.mockReturnValue({ pass: true, failures: [], warnings: [] });
  mockValidateScoringWeights.mockReturnValue({ valid: true, weights: {}, errors: [] });
});

// ── resolveEntity ────────────────────────────────────────────────────────────

describe('resolveEntity', () => {
  it('resolves by UUID (uses "id" column)', async () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const entity = makeEntity({ id: uuid });
    const chain = makeChain({ data: entity, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await resolveEntity(uuid);
    expect(result).toEqual(entity);
    expect(chain.eq).toHaveBeenCalledWith('id', uuid);
  });

  it('resolves by slug (uses "entity_id" column)', async () => {
    const entity = makeEntity();
    const chain = makeChain({ data: entity, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await resolveEntity('acme-corp');
    expect(result).toEqual(entity);
    expect(chain.eq).toHaveBeenCalledWith('entity_id', 'acme-corp');
  });

  it('returns null when entity is not found', async () => {
    const chain = makeChain({ data: null, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await resolveEntity('nonexistent');
    expect(result).toBeNull();
  });

  it('returns null when entity status is not active', async () => {
    const entity = makeEntity({ status: 'suspended' });
    const chain = makeChain({ data: entity, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await resolveEntity('acme-corp');
    expect(result).toBeNull();
  });

  it('correctly identifies UUID format (v4 style)', async () => {
    const uuid = 'a1b2c3d4-1234-4abc-8def-aabbccddeeff';
    const entity = makeEntity({ id: uuid });
    const chain = makeChain({ data: entity, error: null });
    mockSupabase.from.mockReturnValue(chain);

    await resolveEntity(uuid);
    expect(chain.eq).toHaveBeenCalledWith('id', uuid);
  });
});

// ── fetchReceipts ────────────────────────────────────────────────────────────

describe('fetchReceipts', () => {
  it('fetches global receipts when no context provided', async () => {
    const receipts = [{ receipt_id: 'r1' }, { receipt_id: 'r2' }];
    const chain = makeChain({ data: receipts, error: null });
    chain.then = (resolve) => Promise.resolve({ data: receipts, error: null }).then(resolve);
    mockSupabase.from.mockReturnValue(chain);

    const result = await fetchReceipts('db-uuid-001');
    expect(result.receipts).toEqual(receipts);
    expect(result.contextUsed).toBe('global');
  });

  it('uses context filter when context object provided', async () => {
    const receipts = [{ receipt_id: 'r1' }, { receipt_id: 'r2' }, { receipt_id: 'r3' }];
    const chain = makeChain({ data: receipts, error: null });
    chain.then = (resolve) => Promise.resolve({ data: receipts, error: null }).then(resolve);
    mockSupabase.from.mockReturnValue(chain);

    const result = await fetchReceipts('db-uuid-001', { domain: 'ecommerce' });
    expect(chain.contains).toHaveBeenCalledWith('context', { domain: 'ecommerce' });
    expect(result.receipts).toEqual(receipts);
  });

  it('falls back to global when context receipts < 3', async () => {
    const contextReceipts = [{ receipt_id: 'r1' }];
    const globalReceipts = [{ receipt_id: 'r1' }, { receipt_id: 'r2' }, { receipt_id: 'r3' }, { receipt_id: 'r4' }];

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      const receiptsToReturn = callCount === 0 ? contextReceipts : globalReceipts;
      callCount++;
      const chain = makeChain({ data: receiptsToReturn, error: null });
      chain.then = (resolve) => Promise.resolve({ data: receiptsToReturn, error: null }).then(resolve);
      return chain;
    });

    const result = await fetchReceipts('db-uuid-001', { domain: 'ecommerce' });
    expect(result.receipts).toEqual(globalReceipts);
    expect(result.contextUsed).toBe('global_fallback');
  });

  it('does not fall back when context receipts >= 3', async () => {
    const contextReceipts = [{ receipt_id: 'r1' }, { receipt_id: 'r2' }, { receipt_id: 'r3' }];
    const chain = makeChain({ data: contextReceipts, error: null });
    chain.then = (resolve) => Promise.resolve({ data: contextReceipts, error: null }).then(resolve);
    mockSupabase.from.mockReturnValue(chain);

    const result = await fetchReceipts('db-uuid-001', { domain: 'ecommerce' });
    expect(result.receipts).toEqual(contextReceipts);
    expect(result.contextUsed).not.toBe('global_fallback');
  });

  it('returns empty array when DB returns null', async () => {
    const chain = makeChain({ data: null, error: null });
    chain.then = (resolve) => Promise.resolve({ data: null, error: null }).then(resolve);
    mockSupabase.from.mockReturnValue(chain);

    const result = await fetchReceipts('db-uuid-001');
    expect(result.receipts).toEqual([]);
  });
});

// ── fetchEstablishment ────────────────────────────────────────────────────────

describe('fetchEstablishment', () => {
  it('returns establishment data from RPC', async () => {
    const estRow = { established: true, unique_submitters: 5, effective_evidence: 12, total_receipts: 25 };
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: [estRow], error: null });

    const result = await fetchEstablishment('db-uuid-001');
    expect(result).toEqual(estRow);
    expect(mockSupabase.rpc).toHaveBeenCalledWith('is_entity_established', { p_entity_id: 'db-uuid-001' });
  });

  it('throws TrustEvaluationError when RPC fails', async () => {
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: { message: 'connection timeout' } });

    await expect(fetchEstablishment('db-uuid-001')).rejects.toThrow('Establishment lookup failed');
  });

  it('returns default when RPC returns empty array', async () => {
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: [], error: null });

    const result = await fetchEstablishment('db-uuid-001');
    expect(result).toEqual({ established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 });
  });

  it('returns default when RPC returns null data', async () => {
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await fetchEstablishment('db-uuid-001');
    expect(result).toEqual({ established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 });
  });
});

// ── fetchDisputeSummary ───────────────────────────────────────────────────────

describe('fetchDisputeSummary', () => {
  it('returns dispute counts and recent disputes', async () => {
    const recentDisputes = [{ dispute_id: 'd1', status: 'open', reason: 'fraud' }];

    // Mock from() calls in order: total count, active count, reversed count, recent list
    let callIndex = 0;
    mockSupabase.from.mockImplementation(() => {
      callIndex++;
      if (callIndex <= 3) {
        // count queries
        const chain = makeChain({ count: callIndex, error: null });
        chain.then = (resolve) => Promise.resolve({ count: callIndex * 2, error: null }).then(resolve);
        return chain;
      } else {
        // recent disputes query
        const chain = makeChain({ data: recentDisputes, error: null });
        chain.then = (resolve) => Promise.resolve({ data: recentDisputes, error: null }).then(resolve);
        return chain;
      }
    });

    const result = await fetchDisputeSummary('db-uuid-001');
    expect(result).toHaveProperty('total');
    expect(result).toHaveProperty('active');
    expect(result).toHaveProperty('reversed');
    expect(result).toHaveProperty('recent');
    expect(Array.isArray(result.recent)).toBe(true);
  });

  it('handles zero disputes gracefully', async () => {
    mockSupabase.from.mockImplementation(() => {
      const chain = makeChain({ count: 0, data: [], error: null });
      chain.then = (resolve) => Promise.resolve({ count: 0, data: [], error: null }).then(resolve);
      return chain;
    });

    const result = await fetchDisputeSummary('db-uuid-001');
    expect(result.total).toBe(0);
    expect(result.active).toBe(0);
    expect(result.reversed).toBe(0);
    expect(result.recent).toEqual([]);
  });
});

// ── resolvePolicy ─────────────────────────────────────────────────────────────

describe('resolvePolicy', () => {
  it('returns standard policy when no input provided', () => {
    const result = resolvePolicy(null);
    expect(result).toEqual(MOCK_TRUST_POLICIES.standard);
  });

  it('resolves named policy from TRUST_POLICIES', () => {
    const result = resolvePolicy('github_private_repo_safe_v1');
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.github_private_repo_safe_v1);
    expect(result.name).toBe('github_private_repo_safe_v1');
  });

  it('resolves named policy from SOFTWARE_POLICIES', () => {
    const result = resolvePolicy('mcp_server_safe_v1');
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.mcp_server_safe_v1);
    expect(result.name).toBe('mcp_server_safe_v1');
  });

  it('parses valid JSON string as custom policy', () => {
    const custom = { min_score: 60, custom: true };
    const result = resolvePolicy(JSON.stringify(custom));
    expect(result.resolved).toEqual(custom);
    expect(result.name).toBe('custom');
  });

  it('falls back to standard for invalid JSON string', () => {
    const result = resolvePolicy('not-valid-json');
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.standard);
    expect(result.name).toBe('standard');
  });

  it('falls back to standard for JSON that is an array', () => {
    const result = resolvePolicy(JSON.stringify([1, 2, 3]));
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.standard);
    expect(result.name).toBe('standard');
  });

  it('falls back to standard for JSON that is null', () => {
    const result = resolvePolicy('null');
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.standard);
    expect(result.name).toBe('standard');
  });

  it('passes through custom policy object directly', () => {
    const custom = { min_score: 55, special: true };
    const result = resolvePolicy(custom);
    expect(result.resolved).toEqual(custom);
    expect(result.name).toBe('custom');
  });

  it('returns standard for non-string non-object input (number)', () => {
    const result = resolvePolicy(42);
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.standard);
    expect(result.name).toBe('standard');
  });

  it('rejects JSON strings longer than 4096 chars', () => {
    const longString = JSON.stringify({ data: 'x'.repeat(5000) });
    const result = resolvePolicy(longString);
    // Over 4096 chars — JSON parse is skipped, so falls back to standard
    expect(result.resolved).toEqual(MOCK_TRUST_POLICIES.standard);
  });
});

// ── evaluateSoftwareChecks ────────────────────────────────────────────────────

describe('evaluateSoftwareChecks', () => {
  it('returns empty passed/failed when no software_requirements in policy', () => {
    const entity = makeEntity();
    const policy = { min_score: 70 };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result).toEqual({ passed: [], failed: [] });
  });

  it('fails when publisher_verified required but not set', () => {
    const entity = makeEntity({ software_meta: { publisher_verified: false } });
    const policy = { software_requirements: { publisher_verified: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('publisher_not_verified');
  });

  it('passes when publisher_verified required and present', () => {
    const entity = makeEntity({ software_meta: { publisher_verified: true } });
    const policy = { software_requirements: { publisher_verified: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.passed).toContain('publisher_verified');
    expect(result.failed).not.toContain('publisher_not_verified');
  });

  it('fails when registry_listed required but not set', () => {
    const entity = makeEntity({ software_meta: { registry_listed: false } });
    const policy = { software_requirements: { registry_listed: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('not_registry_listed');
  });

  it('fails when server_card_present required but missing', () => {
    const entity = makeEntity({ software_meta: { server_card_present: false } });
    const policy = { software_requirements: { server_card_present: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('no_server_card');
  });

  it('fails when permission_class exceeds max', () => {
    const entity = makeEntity({ software_meta: { permission_class: 'admin' } });
    const policy = { software_requirements: { max_permission_class: 'read_only' } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed.some(f => f.includes('permission_class_too_high'))).toBe(true);
  });

  it('passes when permission_class is within max', () => {
    const entity = makeEntity({ software_meta: { permission_class: 'read_only' } });
    const policy = { software_requirements: { max_permission_class: 'admin' } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.passed.some(p => p.includes('permission_class_acceptable'))).toBe(true);
  });

  it('fails install_scope too broad', () => {
    const entity = makeEntity({ software_meta: { install_scope: 'all_repos' } });
    const policy = { software_requirements: { install_scope: 'selected_repos' } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('install_scope_too_broad');
  });

  it('fails listing_review_passed when required but missing', () => {
    const entity = makeEntity({ software_meta: { listing_review_passed: false } });
    const policy = { software_requirements: { listing_review_passed: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('listing_review_not_passed');
  });

  it('handles missing software_meta gracefully (defaults to {})', () => {
    const entity = makeEntity({ software_meta: null });
    const policy = { software_requirements: { publisher_verified: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('publisher_not_verified');
  });
});

// ── canonicalEvaluate ─────────────────────────────────────────────────────────

describe('canonicalEvaluate — entity resolution', () => {
  it('returns 404 when entity not found', async () => {
    // Make entity chain return null
    const entityChain = makeChain({ data: null, error: null });
    mockSupabase.from.mockReturnValue(entityChain);

    const result = await canonicalEvaluate('nonexistent');
    expect(result.error).toBe('Entity not found');
    expect(result.status).toBe(404);
  });

  it('returns basic trust profile fields for found entity', async () => {
    const entity = makeEntity();

    // Entity lookup
    const entityChain = makeChain({ data: entity, error: null });
    // All other from() calls (disputes, etc.)
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: [{ established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 }], error: null });

    const result = await canonicalEvaluate('acme-corp');
    expect(result.entity_id).toBe('acme-corp');
    expect(result.display_name).toBe('ACME Corp');
    expect(result).toHaveProperty('score');
    expect(result).toHaveProperty('confidence');
    expect(result._protocol_version).toBe('EP/1.1-v2');
  });
});

describe('canonicalEvaluate — snapshot fast path', () => {
  it('uses materialized snapshot when fresh and no context', async () => {
    const freshSnapshot = makeTrustProfile();
    const entity = makeEntity({
      trust_snapshot: freshSnapshot,
      trust_materialized_at: new Date().toISOString(), // just now
    });

    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: [{ established: true, unique_submitters: 5, effective_evidence: 10, total_receipts: 20 }], error: null });

    const result = await canonicalEvaluate('acme-corp');
    // computeTrustProfile should NOT have been called (used snapshot)
    expect(mockComputeTrustProfile).not.toHaveBeenCalled();
    expect(result.contextUsed).toBe('global_materialized');
  });

  it('recomputes when context is provided (bypasses snapshot)', async () => {
    const freshSnapshot = makeTrustProfile();
    const entity = makeEntity({
      trust_snapshot: freshSnapshot,
      trust_materialized_at: new Date().toISOString(),
    });

    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: [{ established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 }], error: null });

    await canonicalEvaluate('acme-corp', { context: { domain: 'ecommerce' } });
    expect(mockComputeTrustProfile).toHaveBeenCalled();
  });

  it('recomputes when snapshot is stale (> 5 min)', async () => {
    const staleTime = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 min ago
    const entity = makeEntity({
      trust_snapshot: makeTrustProfile(),
      trust_materialized_at: staleTime,
    });

    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    await canonicalEvaluate('acme-corp');
    expect(mockComputeTrustProfile).toHaveBeenCalled();
  });
});

describe('canonicalEvaluate — invalid scoring weights', () => {
  it('returns 400 when custom scoring weights are invalid', async () => {
    mockValidateScoringWeights.mockReturnValue({ valid: false, errors: ['weight sum != 1'], weights: null });

    const result = await canonicalEvaluate('acme-corp', { scoringWeights: { delivery: 0.5 } });
    expect(result.error).toBe('Invalid scoring weights');
    expect(result.status).toBe(400);
    expect(result.details).toEqual(['weight sum != 1']);
  });
});

describe('canonicalEvaluate — policy evaluation', () => {
  it('evaluates policy and includes policyResult in response', async () => {
    const entity = makeEntity();
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    mockEvaluateTrustPolicy.mockReturnValue({ pass: true, failures: [], warnings: [] });

    const result = await canonicalEvaluate('acme-corp', { policy: 'standard' });
    expect(result.policyResult).not.toBeNull();
    expect(result.policyResult.pass).toBe(true);
    expect(result.policyResult.policyName).toBe('standard');
  });

  it('includes policyResult.pass=false when trust policy fails', async () => {
    const entity = makeEntity();
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    mockEvaluateTrustPolicy.mockReturnValue({ pass: false, failures: ['score_too_low'], warnings: [] });

    const result = await canonicalEvaluate('acme-corp', { policy: 'standard' });
    expect(result.policyResult.pass).toBe(false);
    expect(result.policyResult.failures).toContain('score_too_low');
  });

  it('policyResult is null when no policy provided', async () => {
    const entity = makeEntity();
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp');
    expect(result.policyResult).toBeNull();
  });
});

describe('canonicalEvaluate — software checks', () => {
  it('runs software checks for github_app entity with software_requirements policy', async () => {
    const entity = makeEntity({
      entity_type: 'github_app',
      software_meta: { publisher_verified: true, permission_class: 'read_only' },
    });
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    mockEvaluateTrustPolicy.mockReturnValue({ pass: true, failures: [], warnings: [] });

    const result = await canonicalEvaluate('acme-corp', { policy: 'github_private_repo_safe_v1' });
    expect(result.policyResult.softwareChecks).not.toBeNull();
  });

  it('includes severe anomaly in softwareChecks failure when policy rejects it', async () => {
    const entity = makeEntity({ entity_type: 'mcp_server', software_meta: { server_card_present: true } });
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    // Make profile have severe anomaly
    mockComputeTrustProfile.mockReturnValue(makeTrustProfile({ anomaly: { alert: 'severe', reason: 'spike' } }));
    mockEvaluateTrustPolicy.mockReturnValue({ pass: true, failures: [], warnings: [] });

    const policy = { software_requirements: { server_card_present: true, reject_severe_anomaly: true } };
    const result = await canonicalEvaluate('acme-corp', { policy });
    expect(result.policyResult.softwareChecks.failed).toContain('severe_anomaly_detected');
    expect(result.policyResult.softwarePass).toBe(false);
  });
});

describe('canonicalEvaluate — options flags', () => {
  it('omits establishment when includeEstablishment=false', async () => {
    const entity = makeEntity();
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', { includeEstablishment: false });
    expect(result.establishment).toBeNull();
    expect(mockSupabase.rpc).not.toHaveBeenCalled();
  });

  it('omits disputes when includeDisputes=false', async () => {
    const entity = makeEntity();
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', { includeDisputes: false, includeEstablishment: false });
    expect(result.disputes).toBeNull();
  });
});

describe('canonicalEvaluate — EP-IX continuity', () => {
  it('continuity is null when entity has no principal_id', async () => {
    const entity = makeEntity({ principal_id: null });
    const entityChain = makeChain({ data: entity, error: null });
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return entityChain;
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', { includeDisputes: false, includeEstablishment: false });
    expect(result.continuity).toBeNull();
  });

  it('returns _unavailable continuity when EP-IX tables not deployed', async () => {
    const entity = makeEntity({ principal_id: 'db-principal-001' });
    const entityChain = makeChain({ data: entity, error: null });

    // Receipts chain (needed for full recompute since no fresh snapshot)
    const receiptsChain = makeChain({ data: [], error: null });
    receiptsChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // Active disputes chain for dampening
    const activeDisputesChain = makeChain({ data: [], error: null });
    activeDisputesChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // All subsequent EP-IX queries throw "relation does not exist"
    const errorChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockRejectedValue(new Error('relation "principals" does not exist')),
      then: (resolve, reject) => Promise.reject(new Error('relation "principals" does not exist')).then(resolve, reject),
    };

    let callCount = 0;
    mockSupabase.from.mockImplementation((table) => {
      callCount++;
      if (callCount === 1) return entityChain;  // entities lookup
      if (callCount === 2) return receiptsChain; // receipts fetch
      if (callCount === 3) return activeDisputesChain; // active disputes for dampening
      return errorChain; // all EP-IX table queries
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', { includeDisputes: false, includeEstablishment: false });
    expect(result.continuity?._unavailable).toBe(true);
    expect(result.continuity?.reason).toBe('ep_ix_tables_not_deployed');
  });
});
