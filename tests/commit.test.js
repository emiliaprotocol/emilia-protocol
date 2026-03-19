/**
 * EMILIA Protocol — EP Commit Tests
 *
 * Tests for the EP Commit system: signed pre-action authorization tokens.
 * Covers issueCommit, verifyCommit, revokeCommit, fulfillCommit,
 * bindReceiptToCommit, and the state machine lifecycle.
 *
 * Uses vi.mock to mock Supabase, canonical-evaluator, and delegation
 * dependencies so no real DB or network calls are made.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Supabase mock helpers (same pattern as other EP tests)
// ============================================================================

function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ============================================================================
// Mock dependencies
// ============================================================================

const mockGetServiceClient = vi.fn();
const mockCanonicalEvaluate = vi.fn();
const mockVerifyDelegation = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/canonical-evaluator.js', () => ({
  canonicalEvaluate: (...args) => mockCanonicalEvaluate(...args),
}));

vi.mock('../lib/delegation.js', () => ({
  verifyDelegation: (...args) => mockVerifyDelegation(...args),
}));

// Import after mocks
import {
  issueCommit,
  verifyCommit,
  revokeCommit,
  fulfillCommit,
  bindReceiptToCommit,
  _internals,
  _resetForTesting,
} from '../lib/commit.js';

// ============================================================================
// Helper: build a mock Supabase client that returns specified data
// ============================================================================

function buildMockDb(commitRecord = null, { insertError = null, updateError = null } = {}) {
  const readChain = makeChain({ data: commitRecord, error: null });
  const writeInsertChain = makeChain({ data: null, error: insertError });

  const updateChain = {
    eq: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue({
      data: commitRecord ? { ...commitRecord, status: 'fulfilled', fulfilled_at: new Date().toISOString() } : null,
      error: updateError,
    }),
    maybeSingle: vi.fn().mockResolvedValue({ data: null, error: updateError }),
    then: (resolve) => Promise.resolve({ data: null, error: updateError }).then(resolve),
  };

  const fromFn = vi.fn(() => ({
    select: (...args) => {
      readChain.select(...args);
      return readChain;
    },
    insert: writeInsertChain.insert,
    update: (...args) => {
      return updateChain;
    },
  }));

  return { from: fromFn };
}

/** Default mock evaluation result — no policyResult => review (safe default) */
function mockEvaluation(overrides = {}) {
  return {
    score: 0.8,
    confidence: 0.9,
    profile: { history_length: 10 },
    anomaly: null,
    policyResult: null,
    error: null,
    ...overrides,
  };
}

// ============================================================================
// 1. issueCommit
// ============================================================================

describe('issueCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
    // Default: evaluation succeeds with policy pass => allow
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({
      policyResult: { pass: true, failures: [], warnings: [] },
    }));
    // Default: Supabase returns a mock client
    mockGetServiceClient.mockReturnValue(buildMockDb());
  });

  it('issues a commit with valid params and returns epc_ prefixed ID', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.commit_id).toMatch(/^epc_/);
    expect(commit.commit_id.length).toBeGreaterThan(4);
  });

  it('decision is review when no policyResult exists (regardless of high score)', async () => {
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({ score: 0.8, policyResult: null }));

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.decision).toBe('review');
  });

  it('decision is review when no policyResult exists (mid-range score)', async () => {
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({ score: 0.45, policyResult: null }));

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'connect',
    });

    expect(commit.decision).toBe('review');
  });

  it('decision is review when no policyResult exists (low score)', async () => {
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({ score: 0.1, policyResult: null }));

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'transact',
    });

    expect(commit.decision).toBe('review');
  });

  it('REGRESSION: score 50 (0-100 scale) without policyResult does NOT become allow', async () => {
    // computeTrustProfile returns score: 50 on 0-100 scale for no-receipt entities.
    // Previously, 50 >= 0.6 was true, so this would incorrectly allow.
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({ score: 50, policyResult: null }));

    const commit = await issueCommit({
      entity_id: 'entity-no-receipts',
      action_type: 'install',
    });

    expect(commit.decision).toBe('review');
    expect(commit.decision).not.toBe('allow');
  });

  it('INVARIANT: commit without policy always returns review', async () => {
    // No matter what score is returned, absence of policyResult must yield review
    for (const score of [0, 0.1, 0.3, 0.5, 0.6, 0.8, 1.0, 50, 100]) {
      mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({ score, policyResult: null }));

      const commit = await issueCommit({
        entity_id: 'entity-invariant',
        action_type: 'install',
      });

      expect(commit.decision).toBe('review');
    }
  });

  it('commit contains all required fields from the runtime schema', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    const requiredFields = [
      'commit_id', 'entity_id', 'principal_id', 'counterparty_entity_id',
      'delegation_id', 'action_type', 'decision', 'scope', 'max_value_usd',
      'context', 'policy_snapshot', 'nonce', 'signature', 'public_key',
      'expires_at', 'status', 'evaluation_result', 'created_at',
    ];

    for (const field of requiredFields) {
      expect(commit).toHaveProperty(field);
    }
  });

  it('commit does NOT contain a version field', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit).not.toHaveProperty('version');
  });

  it('uses created_at (not issued_at) as the timestamp field', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit).toHaveProperty('created_at');
    expect(commit).not.toHaveProperty('issued_at');
  });

  it('signature is present and non-empty (Ed25519 base64)', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.signature).toBeDefined();
    expect(typeof commit.signature).toBe('string');
    expect(commit.signature.length).toBeGreaterThan(0);
  });

  it('public_key is present (base64 32-byte Ed25519 key)', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.public_key).toBeDefined();
    const keyBytes = Buffer.from(commit.public_key, 'base64');
    expect(keyBytes.length).toBe(32);
  });

  it('nonce is 32 bytes hex (64 chars)', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.nonce).toMatch(/^[a-f0-9]{64}$/);
  });

  it('expiry is ~10 minutes after created_at by default', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    const createdAt = new Date(commit.created_at).getTime();
    const expiresAt = new Date(commit.expires_at).getTime();
    const diffMinutes = (expiresAt - createdAt) / (60 * 1000);

    expect(diffMinutes).toBeCloseTo(10, 0);
  });

  it('expiry is clamped to 5-15 minute range', async () => {
    // Try 1 minute — should clamp to 5
    const commit1 = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
      expiry_ms: 1 * 60_000,
    });
    const diff1 = (new Date(commit1.expires_at) - new Date(commit1.created_at)) / 60_000;
    expect(diff1).toBeCloseTo(5, 0);

    // Try 30 minutes — should clamp to 15
    const commit2 = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
      expiry_ms: 30 * 60_000,
    });
    const diff2 = (new Date(commit2.expires_at) - new Date(commit2.created_at)) / 60_000;
    expect(diff2).toBeCloseTo(15, 0);
  });

  it('status is "active" on issuance', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.status).toBe('active');
  });

  it('max_value_usd is advisory — included in commit but does not affect decision logic', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'transact',
      max_value_usd: 500,
    });

    expect(commit.max_value_usd).toBe(500);
  });

  it('evaluation_result contains score, confidence, profile, anomaly', async () => {
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.evaluation_result).toHaveProperty('score');
    expect(commit.evaluation_result).toHaveProperty('confidence');
    expect(commit.evaluation_result).toHaveProperty('profile');
    expect(commit.evaluation_result).toHaveProperty('anomaly');
  });

  it('throws on invalid action_type', async () => {
    await expect(
      issueCommit({
        entity_id: 'entity-123',
        action_type: 'purchase',
      })
    ).rejects.toThrow('action_type must be one of');
  });

  it('only accepts canonical action types: install, connect, delegate, transact', async () => {
    for (const action of ['install', 'connect', 'delegate', 'transact']) {
      const commit = await issueCommit({
        entity_id: 'entity-123',
        action_type: action,
      });
      expect(commit.action_type).toBe(action);
    }

    // Old types should be rejected
    for (const oldAction of ['purchase', 'delegation', 'tool_invocation', 'api_call', 'transfer']) {
      await expect(
        issueCommit({ entity_id: 'entity-123', action_type: oldAction })
      ).rejects.toThrow('action_type must be one of');
    }
  });

  it('throws on missing entity_id', async () => {
    await expect(
      issueCommit({
        entity_id: '',
        action_type: 'install',
      })
    ).rejects.toThrow('entity_id is required');

    await expect(
      issueCommit({
        action_type: 'install',
      })
    ).rejects.toThrow('entity_id is required');
  });

  it('verifies delegation when delegation_id is provided', async () => {
    mockVerifyDelegation.mockResolvedValue({ valid: true, action_permitted: true });

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'delegate',
      delegation_id: 'del_abc',
    });

    expect(mockVerifyDelegation).toHaveBeenCalledWith('del_abc', 'delegate');
    expect(commit.delegation_id).toBe('del_abc');
  });

  it('throws when delegation is invalid', async () => {
    mockVerifyDelegation.mockResolvedValue({ valid: false, reason: 'expired delegation' });

    await expect(
      issueCommit({
        entity_id: 'entity-123',
        action_type: 'install',
        delegation_id: 'del_invalid',
      })
    ).rejects.toThrow('Delegation invalid');
  });

  it('policy result pass=true yields allow decision', async () => {
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({
      policyResult: { pass: true, failures: [], warnings: [] },
    }));

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.decision).toBe('allow');
  });

  it('policy result pass=false with failures yields deny', async () => {
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({
      policyResult: { pass: false, failures: ['too_risky'], warnings: [] },
    }));

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.decision).toBe('deny');
  });

  it('policy result pass=false with only warnings yields review', async () => {
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({
      policyResult: { pass: false, failures: [], warnings: ['low_history'] },
    }));

    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    expect(commit.decision).toBe('review');
  });
});

// ============================================================================
// 2. verifyCommit
// ============================================================================

describe('verifyCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('valid active commit returns { valid: true }', async () => {
    // Issue a real commit first so signature is valid
    mockCanonicalEvaluate.mockResolvedValue(mockEvaluation({
      policyResult: { pass: true, failures: [], warnings: [] },
    }));
    // For issueCommit — no DB
    mockGetServiceClient.mockReturnValue(null);
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
    });

    // For verifyCommit — return the commit from DB
    const db = buildMockDb(commit);
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit(commit.commit_id);
    expect(result.valid).toBe(true);
    expect(result.status).toBe('active');
    expect(result.decision).toBe('allow');
  });

  it('expired commit returns { valid: false, status: "expired" }', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_expired',
      status: 'active',
      expires_at: pastExpiry,
      decision: 'allow',
      created_at: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_expired');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('expired');
  });

  it('revoked commit returns { valid: false, status: "revoked" }', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_revoked',
      status: 'revoked',
      expires_at: futureExpiry,
      decision: 'allow',
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_revoked');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('revoked');
  });

  it('unknown commit_id returns { valid: false, status: "not_found" }', async () => {
    const db = buildMockDb(null);
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_nonexistent');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('not_found');
  });

  it('verification response includes reasons array', async () => {
    const db = buildMockDb(null);
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_nonexistent');
    expect(result).toHaveProperty('reasons');
    expect(Array.isArray(result.reasons)).toBe(true);
  });

  it('fulfilled commit returns { valid: false, status: "fulfilled" }', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_fulfilled',
      status: 'fulfilled',
      expires_at: futureExpiry,
      decision: 'allow',
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_fulfilled');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('fulfilled');
  });

  it('invalid signature returns { valid: false } with signature failure reason', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_badsig',
      entity_id: 'entity-123',
      principal_id: null,
      counterparty_entity_id: null,
      delegation_id: null,
      action_type: 'install',
      decision: 'allow',
      scope: null,
      max_value_usd: null,
      context: null,
      nonce: 'a'.repeat(64),
      signature: 'invalidsignaturedata',
      public_key: Buffer.alloc(32).toString('base64'),
      expires_at: futureExpiry,
      created_at: new Date().toISOString(),
      status: 'active',
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_badsig');
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('invalid_signature');
  });
});

// ============================================================================
// 3. revokeCommit
// ============================================================================

describe('revokeCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('active commit can be revoked', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_active',
      status: 'active',
      expires_at: futureExpiry,
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await revokeCommit('epc_active', 'policy change');
    expect(result.success).toBe(true);
    expect(result.commit_id).toBe('epc_active');
  });

  it('requires a reason for revocation', async () => {
    await expect(revokeCommit('epc_active')).rejects.toThrow('reason is required');
  });

  it('fulfilled commit cannot be revoked (terminal state)', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_fulfilled',
      status: 'fulfilled',
      expires_at: futureExpiry,
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      revokeCommit('epc_fulfilled', 'some reason')
    ).rejects.toThrow('terminal states are immutable');
  });

  it('already revoked commit cannot be revoked again (terminal state)', async () => {
    const db = buildMockDb({
      commit_id: 'epc_revoked',
      status: 'revoked',
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      revokeCommit('epc_revoked', 'some reason')
    ).rejects.toThrow('terminal states are immutable');
  });
});

// ============================================================================
// 4. fulfillCommit
// ============================================================================

describe('fulfillCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('active commit can be fulfilled', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_active',
      status: 'active',
      expires_at: futureExpiry,
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await fulfillCommit('epc_active');
    expect(result).toBeDefined();
  });

  it('revoked commit cannot be fulfilled (terminal state)', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_revoked',
      status: 'revoked',
      expires_at: futureExpiry,
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(fulfillCommit('epc_revoked')).rejects.toThrow('terminal states are immutable');
  });

  it('expired commit cannot be fulfilled', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_expired',
      status: 'active',
      expires_at: pastExpiry,
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(fulfillCommit('epc_expired')).rejects.toThrow(/expired/i);
  });
});

// ============================================================================
// 5. State machine
// ============================================================================

describe('state machine', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('active -> expired via auto-expire on verify', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm1',
      status: 'active',
      expires_at: pastExpiry,
      decision: 'allow',
      created_at: new Date(Date.now() - 20 * 60_000).toISOString(),
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await verifyCommit('epc_sm1');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('expired');
  });

  it('fulfilled -> revoked fails (terminal)', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm2',
      status: 'fulfilled',
      expires_at: futureExpiry,
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(revokeCommit('epc_sm2', 'test')).rejects.toThrow('terminal states are immutable');
  });
});

// ============================================================================
// 6. bindReceiptToCommit
// ============================================================================

describe('bindReceiptToCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('links receipt_id to an active commit', async () => {
    const db = buildMockDb({
      commit_id: 'epc_bind1',
      status: 'active',
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await bindReceiptToCommit('epc_bind1', 'receipt_xyz');
    expect(result.success).toBe(true);
    expect(result.receipt_id).toBe('receipt_xyz');
    expect(result.commit_id).toBe('epc_bind1');
  });

  it('links receipt_id to a fulfilled commit', async () => {
    const db = buildMockDb({
      commit_id: 'epc_bind2',
      status: 'fulfilled',
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await bindReceiptToCommit('epc_bind2', 'receipt_abc');
    expect(result.success).toBe(true);
  });

  it('revoked commit cannot accept receipt binding', async () => {
    const db = buildMockDb({
      commit_id: 'epc_bind3',
      status: 'revoked',
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      bindReceiptToCommit('epc_bind3', 'receipt_def')
    ).rejects.toThrow("Cannot bind receipt to commit in 'revoked' state");
  });

  it('expired commit cannot accept receipt binding', async () => {
    const db = buildMockDb({
      commit_id: 'epc_bind4',
      status: 'expired',
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      bindReceiptToCommit('epc_bind4', 'receipt_ghi')
    ).rejects.toThrow("Cannot bind receipt to commit in 'expired' state");
  });
});

// ============================================================================
// 7. Internal helpers validation
// ============================================================================

describe('EP Commit internals', () => {
  beforeEach(() => {
    _resetForTesting();
  });

  it('newNonce produces 64 hex characters (32 bytes)', () => {
    const nonce = _internals.newNonce();
    expect(nonce).toMatch(/^[a-f0-9]{64}$/);
  });

  it('newCommitId produces epc_ prefixed IDs', () => {
    const id = _internals.newCommitId();
    expect(id).toMatch(/^epc_/);
  });

  it('buildCanonicalPayload sorts keys deterministically', () => {
    const payload1 = _internals.buildCanonicalPayload({ b: 2, a: 1, c: 3 });
    const payload2 = _internals.buildCanonicalPayload({ c: 3, a: 1, b: 2 });
    expect(payload1).toBe(payload2);
    expect(JSON.parse(payload1)).toEqual({ a: 1, b: 2, c: 3 });
  });

  it('buildCanonicalPayload omits undefined values', () => {
    const payload = _internals.buildCanonicalPayload({ a: 1, b: undefined, c: 3 });
    const parsed = JSON.parse(payload);
    expect(parsed).toEqual({ a: 1, c: 3 });
    expect(parsed).not.toHaveProperty('b');
  });

  it('signPayload + verifySignature round-trip succeeds (Ed25519)', () => {
    const payload = JSON.stringify({ test: 'data' });
    const { signature, publicKeyBase64 } = _internals.signPayload(payload);
    const valid = _internals.verifySignature(payload, signature, publicKeyBase64);
    expect(valid).toBe(true);
  });

  it('verifySignature rejects tampered payload', () => {
    const payload = JSON.stringify({ test: 'data' });
    const { signature, publicKeyBase64 } = _internals.signPayload(payload);
    const tampered = JSON.stringify({ test: 'tampered' });
    const valid = _internals.verifySignature(tampered, signature, publicKeyBase64);
    expect(valid).toBe(false);
  });

  it('VALID_DECISIONS contains exactly allow, review, deny', () => {
    expect(_internals.VALID_DECISIONS).toEqual(new Set(['allow', 'review', 'deny']));
  });

  it('VALID_ACTIONS contains install, connect, delegate, transact', () => {
    expect(_internals.VALID_ACTIONS).toEqual(new Set(['install', 'connect', 'delegate', 'transact']));
  });

  it('TERMINAL_STATUSES contains fulfilled, revoked, expired', () => {
    expect(_internals.TERMINAL_STATUSES.has('fulfilled')).toBe(true);
    expect(_internals.TERMINAL_STATUSES.has('revoked')).toBe(true);
    expect(_internals.TERMINAL_STATUSES.has('expired')).toBe(true);
  });

  it('DEFAULT_EXPIRY_MS is 10 minutes', () => {
    expect(_internals.DEFAULT_EXPIRY_MS).toBe(10 * 60 * 1000);
  });
});
