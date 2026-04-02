/**
 * lib/canonical-evaluator.js — extended coverage.
 *
 * Targets uncovered lines:
 *   ~351   canonicalEvaluate: max_active_disputes check — count exceeds max
 *   ~391-437 canonicalEvaluate: EP-IX continuity block with principal_id set
 *              (principals lookup, lineage, inherited disputes, whitewashing)
 *   ~452   canonicalEvaluate: continuity lookup non-schema error → throws TrustEvaluationError
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Supabase chain helper ─────────────────────────────────────────────────────

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
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ── Mock declarations ─────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();
const mockComputeTrustProfile = vi.fn();
const mockEvaluateTrustPolicy = vi.fn();
const mockValidateScoringWeights = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/scoring-v2.js', () => ({
  computeTrustProfile: (...args) => mockComputeTrustProfile(...args),
  evaluateTrustPolicy: (...args) => mockEvaluateTrustPolicy(...args),
  validateScoringWeights: (...args) => mockValidateScoringWeights(...args),
  TRUST_POLICIES: {
    standard: { min_score: 0, min_confidence: 'none' },
    github_private_repo_safe_v1: {
      min_score: 70,
      min_confidence: 'medium',
      software_requirements: { publisher_verified: true },
    },
    mcp_server_safe_v1: {
      min_score: 85,
      min_confidence: 'high',
      software_requirements: { server_card_present: true },
    },
  },
  EP_WEIGHTS_V2: {},
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

import { canonicalEvaluate, evaluateSoftwareChecks } from '../lib/canonical-evaluator.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

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
    profile: {},
    score: 80,
    confidence: 'high',
    effectiveEvidence: 10,
    qualityGatedEvidence: 8,
    uniqueSubmitters: 5,
    receiptCount: 15,
    anomaly: null,
    dispute_dampened_count: 0,
    weights_version: 'ep-v2-default',
    ...overrides,
  };
}

let mockSupabase;

beforeEach(() => {
  vi.clearAllMocks();

  mockSupabase = {
    from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
    rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
  };
  mockGetServiceClient.mockReturnValue(mockSupabase);
  mockComputeTrustProfile.mockReturnValue(makeTrustProfile());
  mockEvaluateTrustPolicy.mockReturnValue({ pass: true, failures: [], warnings: [] });
  mockValidateScoringWeights.mockReturnValue({ valid: true, weights: {}, errors: [] });
});

// Helper: set up standard entity + receipts + disputes chain sequence
function setupEntityFlow(entity, extraFromImpl) {
  // Default chain for most calls
  const defaultChain = makeChain({ data: [], error: null, count: 0 });
  defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

  let callCount = 0;
  mockSupabase.from.mockImplementation((table) => {
    callCount++;
    if (callCount === 1) {
      // Entity lookup
      return makeChain({ data: entity, error: null });
    }
    if (extraFromImpl) {
      return extraFromImpl(table, callCount, defaultChain);
    }
    return defaultChain;
  });

  mockSupabase.rpc = vi.fn().mockResolvedValue({
    data: [{ established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 }],
    error: null,
  });
}

// ── max_active_disputes software check (line ~351) ────────────────────────────

describe('canonicalEvaluate — max_active_disputes software check', () => {
  it('adds active_disputes failure when count exceeds policy max', async () => {
    const entity = makeEntity({
      entity_type: 'github_app',
      software_meta: { publisher_verified: true },
    });

    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation((table) => {
      callCount++;
      if (callCount === 1) return makeChain({ data: entity, error: null }); // entity

      // receipts fetch (call 2) — context receipts
      if (callCount === 2) {
        const rc = makeChain({ data: [], error: null });
        rc.then = (r) => Promise.resolve({ data: [], error: null }).then(r);
        return rc;
      }

      // active disputes for dampening (call 3)
      if (callCount === 3) {
        const dc = makeChain({ data: [], error: null });
        dc.then = (r) => Promise.resolve({ data: [], error: null }).then(r);
        return dc;
      }

      // active disputes count check inside software checks (call 4+)
      // return count: 5, which exceeds max_active_disputes: 2
      const countChain = makeChain({ count: 5, data: null, error: null });
      countChain.then = (r) => Promise.resolve({ count: 5, data: null, error: null }).then(r);
      return countChain;
    });

    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    // Policy with max_active_disputes: 2 and software_requirements
    const policy = {
      software_requirements: {
        publisher_verified: true,
        max_active_disputes: 2,
      },
    };

    const result = await canonicalEvaluate('acme-corp', {
      policy,
      includeEstablishment: false,
      includeDisputes: false,
    });

    expect(result.policyResult).not.toBeNull();
    expect(
      result.policyResult.softwareChecks.failed.some(f => f.includes('active_disputes'))
    ).toBe(true);
    expect(result.policyResult.softwarePass).toBe(false);
  });

  it('does not add failure when active disputes are within policy max', async () => {
    const entity = makeEntity({
      entity_type: 'github_app',
      software_meta: { publisher_verified: true },
    });

    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation((table) => {
      callCount++;
      if (callCount === 1) return makeChain({ data: entity, error: null });

      const rc = makeChain({ data: [], error: null, count: 1 });
      rc.then = (r) => Promise.resolve({ data: [], error: null, count: 1 }).then(r);
      return rc;
    });

    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const policy = {
      software_requirements: {
        publisher_verified: true,
        max_active_disputes: 5,
      },
    };

    const result = await canonicalEvaluate('acme-corp', {
      policy,
      includeEstablishment: false,
      includeDisputes: false,
    });

    expect(
      result.policyResult.softwareChecks.failed.some(f => f.includes('active_disputes'))
    ).toBe(false);
  });
});

// ── EP-IX continuity block with principal_id (lines 391-437) ─────────────────

describe('canonicalEvaluate — EP-IX continuity with principal_id', () => {
  it('returns continuity data when entity has principal_id and EP-IX tables exist', async () => {
    const entity = makeEntity({ principal_id: 'db-principal-001' });

    const receiptsChain = makeChain({ data: [], error: null });
    receiptsChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const activeDisputesChain = makeChain({ data: [], error: null });
    activeDisputesChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // principals table
    const principalChain = makeChain({
      data: {
        principal_id: 'p-001',
        principal_type: 'individual',
        display_name: 'Alice',
        status: 'active',
      },
      error: null,
    });

    // continuity_claims as successor
    const successorChain = makeChain({ data: [], error: null });
    successorChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // continuity_claims as predecessor
    const predecessorChain = makeChain({ data: [], error: null });
    predecessorChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // continuity_claims count for whitewashing
    const rejectedClaimsChain = makeChain({ count: 0, data: null, error: null });
    rejectedClaimsChain.then = (r) => Promise.resolve({ count: 0, data: null, error: null }).then(r);

    // dispute count for inherited disputes (won't be called since asSuccessor is empty)
    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation((table) => {
      callCount++;
      if (callCount === 1) return makeChain({ data: entity, error: null }); // entity
      if (callCount === 2) return receiptsChain; // receipts
      if (callCount === 3) return activeDisputesChain; // active disputes for dampening
      if (table === 'principals') return principalChain;
      if (table === 'continuity_claims') {
        // Three continuity_claims calls: asSuccessor, asPredecessor, rejectedClaims
        const claimsCalls = [successorChain, predecessorChain, rejectedClaimsChain];
        const idx = Math.min(callCount - 4, claimsCalls.length - 1);
        return claimsCalls[idx] || defaultChain;
      }
      return defaultChain;
    });

    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', {
      includeEstablishment: false,
      includeDisputes: false,
    });

    expect(result.continuity).not.toBeNull();
    expect(result.continuity).toHaveProperty('mode');
    expect(result.continuity.mode).toBe('standalone'); // no successor or predecessor
  });

  it('computes inherited disputes when entity is a successor', async () => {
    const entity = makeEntity({ principal_id: 'db-principal-002' });

    const receiptsChain = makeChain({ data: [], error: null });
    receiptsChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const activeDisputesChain = makeChain({ data: [], error: null });
    activeDisputesChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const principalChain = makeChain({
      data: {
        principal_id: 'p-002',
        principal_type: 'organization',
        display_name: 'Acme Old',
        status: 'active',
      },
      error: null,
    });

    // asSuccessor has one predecessor entry
    const successorData = [
      { old_entity_id: 'old-entity-001', reason: 'rebrand', status: 'approved_full', transfer_policy: 'full' },
    ];
    const successorChain = makeChain({ data: successorData, error: null });
    successorChain.then = (r) => Promise.resolve({ data: successorData, error: null }).then(r);

    const predecessorChain = makeChain({ data: [], error: null });
    predecessorChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const rejectedClaimsChain = makeChain({ count: 1, data: null, error: null });
    rejectedClaimsChain.then = (r) => Promise.resolve({ count: 1, data: null, error: null }).then(r);

    // inherited disputes count from predecessor entity
    const inheritedDisputesChain = makeChain({ count: 3, data: null, error: null });
    inheritedDisputesChain.then = (r) =>
      Promise.resolve({ count: 3, data: null, error: null }).then(r);

    let continuityClaimsCallIdx = 0;
    mockSupabase.from.mockImplementation((table, callIdx) => {
      if (table === 'entities') return makeChain({ data: entity, error: null });
      if (table === 'receipts') {
        const rc = makeChain({ data: [], error: null });
        rc.then = (r) => Promise.resolve({ data: [], error: null }).then(r);
        return rc;
      }
      if (table === 'disputes') {
        // active disputes for dampening OR inherited disputes count
        const dc = makeChain({ data: [], error: null, count: 3 });
        dc.then = (r) => Promise.resolve({ data: [], error: null, count: 3 }).then(r);
        return dc;
      }
      if (table === 'principals') return principalChain;
      if (table === 'continuity_claims') {
        continuityClaimsCallIdx++;
        if (continuityClaimsCallIdx === 1) return successorChain;
        if (continuityClaimsCallIdx === 2) return predecessorChain;
        return rejectedClaimsChain;
      }
      const dc = makeChain({ data: [], error: null, count: 0 });
      dc.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);
      return dc;
    });

    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', {
      includeEstablishment: false,
      includeDisputes: false,
    });

    expect(result.continuity).not.toBeNull();
    expect(result.continuity.mode).toBe('successor');
    expect(result.continuity.whitewashing_risk).toBe(true); // rejectedClaims=1 > 0
    expect(result.continuity.inherits_historical_establishment).toBe(true); // transfer_policy=full
  });
});

// ── EP-IX continuity non-schema error throws TrustEvaluationError (line ~452) ─

describe('canonicalEvaluate — EP-IX non-schema error throws', () => {
  it('throws TrustEvaluationError when continuity lookup fails with non-schema error', async () => {
    const entity = makeEntity({ principal_id: 'db-principal-003' });

    const receiptsChain = makeChain({ data: [], error: null });
    receiptsChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const activeDisputesChain = makeChain({ data: [], error: null });
    activeDisputesChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // principals query THROWS with a non-schema error (not "does not exist")
    const errorChain = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockRejectedValue(new Error('connection refused')),
      then: (_resolve, reject) =>
        Promise.reject(new Error('connection refused')).then(_resolve, reject),
    };

    let callCount = 0;
    mockSupabase.from.mockImplementation((table) => {
      callCount++;
      if (callCount === 1) return makeChain({ data: entity, error: null }); // entity
      if (callCount === 2) return receiptsChain; // receipts
      if (callCount === 3) return activeDisputesChain; // active disputes
      return errorChain; // principal lookup throws non-schema error
    });

    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    await expect(
      canonicalEvaluate('acme-corp', {
        includeEstablishment: false,
        includeDisputes: false,
      })
    ).rejects.toThrow('EP-IX continuity lookup failed');
  });
});

// ── canonicalEvaluate: custom scoringWeights with policyProfile ───────────────

describe('canonicalEvaluate — custom scoringWeights', () => {
  it('computes policyProfile when valid scoringWeights provided', async () => {
    const entity = makeEntity();

    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return makeChain({ data: entity, error: null });
      return defaultChain;
    });
    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const customWeights = { delivery: 0.5, behavioral: 0.5 };
    mockValidateScoringWeights.mockReturnValue({
      valid: true,
      weights: customWeights,
      errors: [],
    });

    // computeTrustProfile is called twice (canonical + policy-weighted)
    const policyProfile = makeTrustProfile({ score: 75 });
    mockComputeTrustProfile
      .mockReturnValueOnce(makeTrustProfile({ score: 80 })) // canonical
      .mockReturnValueOnce(policyProfile); // policy-weighted

    const result = await canonicalEvaluate('acme-corp', {
      scoringWeights: customWeights,
      includeEstablishment: false,
      includeDisputes: false,
    });

    expect(mockComputeTrustProfile).toHaveBeenCalledTimes(2);
    expect(result.policyScoring).not.toBeNull();
    expect(result.policyScoring.policy_score).toBe(75);
    expect(result.policyScoring.canonical_score).toBe(80);
  });
});

// ── evaluateSoftwareChecks: provenance and trusted_publishing paths (lines 197,199,203) ──

describe('evaluateSoftwareChecks — provenance and trusted_publishing', () => {
  function makeEntity(overrides = {}) {
    return {
      id: 'db-uuid-001',
      entity_id: 'acme',
      display_name: 'Acme',
      entity_type: 'github_app',
      category: 'software',
      status: 'active',
      principal_id: null,
      software_meta: null,
      trust_snapshot: null,
      trust_materialized_at: null,
      ...overrides,
    };
  }

  it('fails provenance_verified when required but not set — line 197', () => {
    const entity = makeEntity({ software_meta: { provenance_verified: false } });
    const policy = { software_requirements: { provenance_verified: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('provenance_not_verified');
  });

  it('passes provenance_verified when present — line 199', () => {
    const entity = makeEntity({ software_meta: { provenance_verified: true } });
    const policy = { software_requirements: { provenance_verified: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.passed).toContain('provenance_verified');
    expect(result.failed).not.toContain('provenance_not_verified');
  });

  it('fails trusted_publishing when required but not set — line 203', () => {
    const entity = makeEntity({ software_meta: { trusted_publishing: false } });
    const policy = { software_requirements: { trusted_publishing: true } };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).toContain('trusted_publishing_not_verified');
  });

  it('does not flag trusted_publishing when not required', () => {
    const entity = makeEntity({ software_meta: { trusted_publishing: false } });
    const policy = { software_requirements: {} };
    const result = evaluateSoftwareChecks(entity, policy);
    expect(result.failed).not.toContain('trusted_publishing_not_verified');
  });
});

// ── canonicalEvaluate: EP-IX predecessor mode (line 437) ──────────────────────

describe('canonicalEvaluate — EP-IX predecessor mode (line 437)', () => {
  it('computes successors map when entity is a predecessor (asPredecessor has entries)', async () => {
    const entity = makeEntity({ principal_id: 'db-principal-pred' });

    const receiptsChain = makeChain({ data: [], error: null });
    receiptsChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const activeDisputesChain = makeChain({ data: [], error: null });
    activeDisputesChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    const principalChain = makeChain({
      data: { principal_id: 'p-pred', principal_type: 'organization', display_name: 'Old Corp', status: 'active' },
      error: null,
    });

    // asSuccessor: empty (entity is not a successor)
    const successorChain = makeChain({ data: [], error: null });
    successorChain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);

    // asPredecessor: has entries (entity is a predecessor — someone succeeded it)
    const predecessorData = [
      { new_entity_id: 'new-entity-001', reason: 'restructuring', status: 'approved_full', transfer_policy: 'partial' },
    ];
    const predecessorChain = makeChain({ data: predecessorData, error: null });
    predecessorChain.then = (r) => Promise.resolve({ data: predecessorData, error: null }).then(r);

    // rejectedClaims: 0
    const rejectedClaimsChain = makeChain({ count: 0, data: null, error: null });
    rejectedClaimsChain.then = (r) => Promise.resolve({ count: 0, data: null, error: null }).then(r);

    const defaultChain = makeChain({ data: [], error: null, count: 0 });
    defaultChain.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);

    let continuityClaimsCallIdx = 0;
    mockSupabase.from.mockImplementation((table) => {
      if (table === 'entities') return makeChain({ data: entity, error: null });
      if (table === 'receipts') {
        const rc = makeChain({ data: [], error: null });
        rc.then = (r) => Promise.resolve({ data: [], error: null }).then(r);
        return rc;
      }
      if (table === 'disputes') {
        const dc = makeChain({ data: [], error: null, count: 0 });
        dc.then = (r) => Promise.resolve({ data: [], error: null, count: 0 }).then(r);
        return dc;
      }
      if (table === 'principals') return principalChain;
      if (table === 'continuity_claims') {
        continuityClaimsCallIdx++;
        if (continuityClaimsCallIdx === 1) return successorChain;
        if (continuityClaimsCallIdx === 2) return predecessorChain;
        return rejectedClaimsChain;
      }
      return defaultChain;
    });

    mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });

    const result = await canonicalEvaluate('acme-corp', {
      includeEstablishment: false,
      includeDisputes: false,
    });

    expect(result.continuity).not.toBeNull();
    // mode should be 'predecessor' since asSuccessor is empty and asPredecessor has entries
    expect(result.continuity.mode).toBe('predecessor');
    expect(result.continuity.successors).toHaveLength(1);
    expect(result.continuity.successors[0].to).toBe('new-entity-001');
  });
});
