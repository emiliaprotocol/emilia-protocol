/**
 * Extended tests for lib/commit.js
 *
 * Targets uncovered lines:
 *   701  — ProtocolWriteError from fulfillCommit fetch failure
 *   814  — ProtocolWriteError from bindReceiptToCommit fetch failure
 *   820  — CommitError NOT_FOUND in bindReceiptToCommit
 *   837  — CommitError DB_ERROR in bindReceiptToCommit update failure
 *
 * Additional coverage for getCommitStatus, _trackNonce eviction,
 * requireServiceClient failure, and getAllTrustedKeys.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mock dependencies ─────────────────────────────────────────────────────────

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
  getCommitStatus,
  CommitError,
  _internals,
  _resetForTesting,
} from '../lib/commit.js';

import { ProtocolWriteError } from '../lib/errors.js';

// ── Chain builders ────────────────────────────────────────────────────────────

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

/**
 * Build a mock DB where:
 * - the first from('commits') select returns fetchResult
 * - updates return updateResult
 */
function buildSelectMockDb(fetchResult, updateResult = { data: null, error: null }) {
  const selectChain = makeChain(fetchResult);
  const updateChain = {
    eq: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(updateResult),
    maybeSingle: vi.fn().mockResolvedValue(updateResult),
    then: (resolve) => Promise.resolve(updateResult).then(resolve),
  };

  return {
    from: vi.fn(() => ({
      select: (...args) => {
        selectChain.select(...args);
        return selectChain;
      },
      update: () => updateChain,
      insert: vi.fn().mockResolvedValue({ data: null, error: null }),
    })),
  };
}

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

// ── fulfillCommit (line 701) ──────────────────────────────────────────────────

describe('fulfillCommit — ProtocolWriteError on DB fetch failure (line ~701)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('throws ProtocolWriteError when DB fetch fails during fulfillment', async () => {
    const db = buildSelectMockDb({ data: null, error: { message: 'read timeout' } });
    mockGetServiceClient.mockReturnValue(db);

    await expect(fulfillCommit('epc_test1')).rejects.toSatisfy((err) => {
      return err.constructor.name === 'ProtocolWriteError' ||
             err.message.includes('Failed to fetch commit for fulfillment') ||
             err.code === 'FULFILLMENT_FETCH_FAILED';
    });
  });

  it('throws CommitError NOT_FOUND when commit not found during fulfillment', async () => {
    const db = buildSelectMockDb({ data: null, error: null });
    mockGetServiceClient.mockReturnValue(db);

    await expect(fulfillCommit('epc_notfound')).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
  });

  it('throws CommitError on fulfillment update DB error', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const commit = {
      commit_id: 'epc_active',
      status: 'active',
      expires_at: futureExpiry,
    };
    const db = buildSelectMockDb(
      { data: commit, error: null },
      { data: null, error: { message: 'update failed' } }
    );
    mockGetServiceClient.mockReturnValue(db);

    await expect(fulfillCommit('epc_active')).rejects.toMatchObject({
      code: 'DB_ERROR',
    });
  });

  it('requires commit_id to be provided', async () => {
    await expect(fulfillCommit(null)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      status: 400,
    });
  });

  it('auto-expires and throws COMMIT_EXPIRED when commit is past expiry', async () => {
    const pastExpiry = new Date(Date.now() - 60_000).toISOString();
    const commit = {
      commit_id: 'epc_expired_fulfill',
      status: 'active',
      expires_at: pastExpiry,
    };
    const updateChain = {
      eq: vi.fn().mockReturnThis(),
      then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
    };
    const db = {
      from: vi.fn(() => ({
        select: () => makeChain({ data: commit, error: null }),
        update: () => updateChain,
      })),
    };
    mockGetServiceClient.mockReturnValue(db);

    await expect(fulfillCommit('epc_expired_fulfill')).rejects.toMatchObject({
      code: 'COMMIT_EXPIRED',
      status: 409,
    });
  });
});

// ── bindReceiptToCommit (lines 814, 820, 837) ────────────────────────────────

describe('bindReceiptToCommit — ProtocolWriteError on DB fetch failure (line ~814)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('throws ProtocolWriteError when DB fetch fails during bind', async () => {
    const db = buildSelectMockDb({ data: null, error: { message: 'connection reset' } });
    mockGetServiceClient.mockReturnValue(db);

    await expect(bindReceiptToCommit('epc_bind', 'receipt_1')).rejects.toSatisfy((err) => {
      return err.constructor.name === 'ProtocolWriteError' ||
             err.message.includes('Failed to fetch commit for receipt binding') ||
             err.code === 'BIND_RECEIPT_FETCH_FAILED';
    });
  });
});

describe('bindReceiptToCommit — NOT_FOUND (line ~820)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('throws CommitError NOT_FOUND when commit does not exist', async () => {
    const db = buildSelectMockDb({ data: null, error: null });
    mockGetServiceClient.mockReturnValue(db);

    await expect(bindReceiptToCommit('epc_notfound', 'receipt_1')).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
  });
});

describe('bindReceiptToCommit — update DB_ERROR (line ~837)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('throws CommitError DB_ERROR when update fails', async () => {
    const commit = { commit_id: 'epc_bind_err', status: 'active' };
    const db = buildSelectMockDb(
      { data: commit, error: null },
      { data: null, error: { message: 'constraint violation' } }
    );
    mockGetServiceClient.mockReturnValue(db);

    await expect(bindReceiptToCommit('epc_bind_err', 'receipt_1')).rejects.toMatchObject({
      code: 'DB_ERROR',
    });
  });

  it('requires both commit_id and receipt_id', async () => {
    await expect(bindReceiptToCommit(null, 'receipt_1')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
    await expect(bindReceiptToCommit('epc_1', null)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
    await expect(bindReceiptToCommit('', '')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
  });

  it('throws INVALID_STATE_FOR_RECEIPT when commit is expired', async () => {
    const commit = { commit_id: 'epc_expired', status: 'expired' };
    const db = buildSelectMockDb({ data: commit, error: null });
    mockGetServiceClient.mockReturnValue(db);

    await expect(bindReceiptToCommit('epc_expired', 'receipt_1')).rejects.toMatchObject({
      code: 'INVALID_STATE_FOR_RECEIPT',
      status: 409,
    });
  });

  it('throws INVALID_STATE_FOR_RECEIPT when commit is revoked', async () => {
    const commit = { commit_id: 'epc_revoked', status: 'revoked' };
    const db = buildSelectMockDb({ data: commit, error: null });
    mockGetServiceClient.mockReturnValue(db);

    await expect(bindReceiptToCommit('epc_revoked', 'receipt_1')).rejects.toMatchObject({
      code: 'INVALID_STATE_FOR_RECEIPT',
    });
  });
});

// ── getCommitStatus ───────────────────────────────────────────────────────────

describe('getCommitStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('returns null when commit not found', async () => {
    const db = buildSelectMockDb({ data: null, error: null });
    mockGetServiceClient.mockReturnValue(db);

    const result = await getCommitStatus('epc_notfound');
    expect(result).toBeNull();
  });

  it('returns commit when active and not expired', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const commit = {
      commit_id: 'epc_active',
      status: 'active',
      expires_at: futureExpiry,
      decision: 'allow',
    };
    const db = buildSelectMockDb({ data: commit, error: null });
    mockGetServiceClient.mockReturnValue(db);

    const result = await getCommitStatus('epc_active');
    expect(result).not.toBeNull();
    expect(result.status).toBe('active');
  });

  it('auto-expires commit past expiry and returns expired status', async () => {
    const pastExpiry = new Date(Date.now() - 60_000).toISOString();
    const commit = {
      commit_id: 'epc_exp_status',
      status: 'active',
      expires_at: pastExpiry,
      decision: 'allow',
    };
    const updateChain = {
      eq: vi.fn().mockReturnThis(),
      then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
    };
    const db = {
      from: vi.fn(() => ({
        select: () => makeChain({ data: commit, error: null }),
        update: () => updateChain,
      })),
    };
    mockGetServiceClient.mockReturnValue(db);

    const result = await getCommitStatus('epc_exp_status');
    expect(result.status).toBe('expired');
  });

  it('throws ProtocolWriteError when DB fetch fails', async () => {
    const db = buildSelectMockDb({ data: null, error: { message: 'query error' } });
    mockGetServiceClient.mockReturnValue(db);

    await expect(getCommitStatus('epc_err')).rejects.toSatisfy((err) => {
      return err.constructor.name === 'ProtocolWriteError' ||
             err.message.includes('Failed to fetch commit status');
    });
  });

  it('requires commit_id', async () => {
    await expect(getCommitStatus('')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
  });
});

// ── revokeCommit — additional paths ──────────────────────────────────────────

describe('revokeCommit — additional paths', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
  });

  it('throws CommitError NOT_FOUND when commit not found for revocation', async () => {
    const db = buildSelectMockDb({ data: null, error: null });
    mockGetServiceClient.mockReturnValue(db);

    await expect(revokeCommit('epc_notfound', 'reason')).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
  });

  it('throws ProtocolWriteError when DB fetch fails during revocation', async () => {
    const db = buildSelectMockDb({ data: null, error: { message: 'DB error' } });
    mockGetServiceClient.mockReturnValue(db);

    await expect(revokeCommit('epc_err', 'reason')).rejects.toSatisfy((err) => {
      return err.constructor.name === 'ProtocolWriteError' ||
             err.message.includes('Failed to fetch commit for revocation');
    });
  });

  it('throws CommitError DB_ERROR when revocation update fails', async () => {
    const commit = { commit_id: 'epc_active', status: 'active' };
    const db = buildSelectMockDb(
      { data: commit, error: null },
      { data: null, error: { message: 'write error' } }
    );
    mockGetServiceClient.mockReturnValue(db);

    await expect(revokeCommit('epc_active', 'reason')).rejects.toMatchObject({
      code: 'DB_ERROR',
    });
  });

  it('requires commit_id', async () => {
    await expect(revokeCommit('', 'reason')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
  });
});

// ── _trackNonce eviction ──────────────────────────────────────────────────────

describe('_internals._trackNonce — cache eviction', () => {
  beforeEach(() => {
    _resetForTesting();
  });

  it('evicts oldest entries when cache exceeds MAX_NONCE_CACHE_SIZE', () => {
    const { _trackNonce, _usedNonces, MAX_NONCE_CACHE_SIZE } = _internals;
    const firstNonce = 'first-nonce-to-be-evicted';
    _trackNonce(firstNonce);
    expect(_usedNonces.has(firstNonce)).toBe(true);

    // Fill the cache to the limit + 1 more
    for (let i = 0; i < MAX_NONCE_CACHE_SIZE; i++) {
      _trackNonce(`nonce-${i}`);
    }

    // firstNonce should have been evicted
    expect(_usedNonces.has(firstNonce)).toBe(false);
    expect(_usedNonces.size).toBeLessThanOrEqual(MAX_NONCE_CACHE_SIZE);
  });

  it('does not evict when cache is below MAX_NONCE_CACHE_SIZE', () => {
    const { _trackNonce, _usedNonces, MAX_NONCE_CACHE_SIZE } = _internals;
    _trackNonce('keep-this-nonce');
    _trackNonce('also-keep');
    expect(_usedNonces.has('keep-this-nonce')).toBe(true);
    expect(_usedNonces.has('also-keep')).toBe(true);
  });
});

// ── getAllTrustedKeys ─────────────────────────────────────────────────────────

describe('_internals.getAllTrustedKeys', () => {
  beforeEach(() => {
    _resetForTesting();
  });

  it('returns empty array when no keys registered', () => {
    const keys = _internals.getAllTrustedKeys();
    expect(Array.isArray(keys)).toBe(true);
    expect(keys).toHaveLength(0);
  });

  it('returns registered keys with kid and publicKeyBase64', () => {
    _internals.registerTrustedKey('test-kid-1', 'abc123');
    _internals.registerTrustedKey('test-kid-2', 'def456');
    const keys = _internals.getAllTrustedKeys();
    expect(keys).toHaveLength(2);
    expect(keys.find(k => k.kid === 'test-kid-1')).toBeDefined();
    expect(keys.find(k => k.kid === 'test-kid-1').publicKeyBase64).toBe('abc123');
  });
});

// ── getTrustedKey ─────────────────────────────────────────────────────────────

describe('_internals.getTrustedKey', () => {
  beforeEach(() => {
    _resetForTesting();
  });

  it('returns undefined for unknown kid', () => {
    const result = _internals.getTrustedKey('nonexistent-kid');
    expect(result).toBeUndefined();
  });

  it('returns public key for registered kid', () => {
    _internals.registerTrustedKey('known-kid', 'mypubkey');
    expect(_internals.getTrustedKey('known-kid')).toBe('mypubkey');
  });
});

// ── verifySignature edge cases ────────────────────────────────────────────────

describe('_internals.verifySignature — edge cases', () => {
  beforeEach(() => {
    _resetForTesting();
  });

  it('returns false for wrong-length public key', () => {
    const result = _internals.verifySignature(
      'payload',
      Buffer.alloc(64).toString('base64'),
      Buffer.alloc(16).toString('base64'), // wrong length, not 32
    );
    expect(result).toBe(false);
  });

  it('returns false for invalid base64 signature', () => {
    // Generate a real keypair to get valid public key
    const { publicKeyBase64 } = _internals.signPayload('test');
    const result = _internals.verifySignature(
      'test-payload',
      'not-valid-base64!!!',
      publicKeyBase64,
    );
    expect(result).toBe(false);
  });
});

// ── issueCommit with delegation scope denied ──────────────────────────────────

describe('issueCommit — delegation scope denied', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
    mockGetServiceClient.mockReturnValue(buildSelectMockDb({ data: null, error: null }));
  });

  it('throws DELEGATION_SCOPE_DENIED when action not permitted by delegation', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      action_permitted: false,
      reason: 'action not in allowed set',
    });

    await expect(issueCommit({
      entity_id: 'entity-123',
      action_type: 'install',
      delegation_id: 'del_scoped',
    })).rejects.toMatchObject({
      code: 'DELEGATION_SCOPE_DENIED',
      status: 403,
    });
  });
});

// ── issueCommit evaluation error ──────────────────────────────────────────────

describe('issueCommit — evaluation error', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetForTesting();
    mockGetServiceClient.mockReturnValue(buildSelectMockDb({ data: null, error: null }));
  });

  it('throws EVALUATION_FAILED when canonical evaluator returns error', async () => {
    mockCanonicalEvaluate.mockResolvedValue({
      error: 'entity not found',
      status: 404,
      score: null,
      policyResult: null,
    });

    await expect(issueCommit({
      entity_id: 'entity-missing',
      action_type: 'connect',
    })).rejects.toMatchObject({
      code: 'EVALUATION_FAILED',
    });
  });
});
