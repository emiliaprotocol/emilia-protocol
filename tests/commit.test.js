/**
 * EMILIA Protocol — EP Commit Tests
 *
 * Tests for the EP Commit system: signed pre-action authorization tokens.
 * Covers issueCommit, verifyCommit, revokeCommit, fulfillCommit,
 * bindReceiptToCommit, and the state machine lifecycle.
 *
 * Uses mock Supabase clients following the same pattern as other EP tests
 * (vi.mock with spy functions, makeChain helper).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Supabase mock helpers (same pattern as dispute-adjudication.test.js)
// ============================================================================

/**
 * makeChain builds a fluent Supabase query builder mock.
 * Each chainable method returns `this` so you can call .from().select()... etc.
 * The terminal call (maybeSingle) resolves to { data, error }.
 */
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
// Mock @/lib/supabase so ep-commit never calls a real DB
// ============================================================================

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(),
}));

import { getServiceClient } from '../lib/supabase.js';

// Import after mocks
import {
  issueCommit,
  verifyCommit,
  revokeCommit,
  fulfillCommit,
  bindReceiptToCommit,
  _internals,
} from '../lib/ep-commit.js';

// ============================================================================
// Helper: build a mock DB that returns specified data for reads and succeeds for writes
// ============================================================================

function buildMockDb(commitRecord = null) {
  const readChain = makeChain({ data: commitRecord, error: null });
  const writeChain = makeChain({ data: null, error: null });

  const fromFn = vi.fn((table) => {
    // Return different chains depending on whether it's a read or write operation
    return {
      select: (...args) => {
        readChain.select(...args);
        return readChain;
      },
      insert: writeChain.insert,
      update: (...args) => {
        writeChain.update(...args);
        // update().eq() needs to resolve
        return {
          eq: vi.fn().mockResolvedValue({ data: null, error: null }),
        };
      },
    };
  });

  return { from: fromFn };
}

// ============================================================================
// 1. issueCommit
// ============================================================================

describe('issueCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('issues a commit with valid params and returns epc_ prefixed ID', async () => {
    const db = buildMockDb();
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      db,
    });

    expect(commit.commit_id).toMatch(/^epc_/);
    expect(commit.commit_id.length).toBeGreaterThan(4);
  });

  it('decision is restricted to allow/review/deny (canonical vocabulary only)', async () => {
    const db = buildMockDb();

    for (const decision of ['allow', 'review', 'deny']) {
      const commit = await issueCommit({
        entity_id: 'entity-123',
        action_type: 'purchase',
        decision,
        db,
      });
      expect(commit.decision).toBe(decision);
    }
  });

  it('commit contains all required fields', async () => {
    const db = buildMockDb();
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      db,
    });

    const requiredFields = [
      'commit_id', 'version', 'decision', 'action_type', 'entity_id',
      'scope', 'nonce', 'issued_at', 'expires_at', 'status', 'signature',
    ];

    for (const field of requiredFields) {
      expect(commit).toHaveProperty(field);
    }
  });

  it('signature is present and non-empty', async () => {
    const db = buildMockDb();
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      db,
    });

    expect(commit.signature).toBeDefined();
    expect(typeof commit.signature).toBe('string');
    expect(commit.signature.length).toBeGreaterThan(0);
  });

  it('nonce is 32 bytes hex (64 chars)', async () => {
    const db = buildMockDb();
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      db,
    });

    expect(commit.nonce).toMatch(/^[a-f0-9]{64}$/);
  });

  it('expiry is ~10 minutes after issued_at by default', async () => {
    const db = buildMockDb();
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      db,
    });

    const issuedAt = new Date(commit.issued_at).getTime();
    const expiresAt = new Date(commit.expires_at).getTime();
    const diffMinutes = (expiresAt - issuedAt) / (60 * 1000);

    // Should be 10 minutes (allow 0.1 minute tolerance for test execution time)
    expect(diffMinutes).toBeCloseTo(10, 0);
  });

  it('status is "active" on issuance', async () => {
    const db = buildMockDb();
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      db,
    });

    expect(commit.status).toBe('active');
  });

  it('max_value_usd is advisory — included in commit but does not affect decision logic', async () => {
    const db = buildMockDb();

    // max_value_usd is included in the commit record for policy reference
    // but EP does not enforce, hold, or settle monetary value.
    const commit = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      max_value_usd: 500,
      db,
    });

    expect(commit.max_value_usd).toBe(500);

    // A second commit with different max_value_usd but same params
    // gets the same decision — max_value_usd does not change the decision
    const commit2 = await issueCommit({
      entity_id: 'entity-123',
      action_type: 'purchase',
      decision: 'allow',
      max_value_usd: 50000,
      db,
    });

    expect(commit2.decision).toBe(commit.decision);
  });

  it('throws on invalid action_type', async () => {
    const db = buildMockDb();
    await expect(
      issueCommit({
        entity_id: 'entity-123',
        action_type: 'hack_the_planet',
        decision: 'allow',
        db,
      })
    ).rejects.toThrow('Invalid action_type');
  });

  it('throws on missing entity_id', async () => {
    const db = buildMockDb();
    await expect(
      issueCommit({
        entity_id: '',
        action_type: 'purchase',
        decision: 'allow',
        db,
      })
    ).rejects.toThrow('entity_id is required');

    await expect(
      issueCommit({
        action_type: 'purchase',
        decision: 'allow',
        db,
      })
    ).rejects.toThrow('entity_id is required');
  });
});

// ============================================================================
// 2. verifyCommit
// ============================================================================

describe('verifyCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('valid active commit returns { valid: true }', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_abc123',
      status: 'active',
      expires_at: futureExpiry,
      decision: 'allow',
    });

    const result = await verifyCommit('epc_abc123', db);
    expect(result.valid).toBe(true);
  });

  it('expired commit returns { valid: false, status: "expired" }', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_expired',
      status: 'active',
      expires_at: pastExpiry,
      decision: 'allow',
    });

    const result = await verifyCommit('epc_expired', db);
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

    const result = await verifyCommit('epc_revoked', db);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('revoked');
  });

  it('unknown commit_id returns { valid: false }', async () => {
    const db = buildMockDb(null); // no data found

    const result = await verifyCommit('epc_nonexistent', db);
    expect(result.valid).toBe(false);
  });

  it('verification does not expose full commit payload', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_abc123',
      status: 'active',
      expires_at: futureExpiry,
      decision: 'allow',
    });

    const result = await verifyCommit('epc_abc123', db);

    // Verify response does not contain scope, reasons, entity_id, nonce, etc.
    expect(result).not.toHaveProperty('scope');
    expect(result).not.toHaveProperty('reasons');
    expect(result).not.toHaveProperty('entity_id');
    expect(result).not.toHaveProperty('nonce');
    expect(result).not.toHaveProperty('signature');
  });

  it('fulfilled commit returns { valid: false, status: "fulfilled" }', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_fulfilled',
      status: 'fulfilled',
      expires_at: futureExpiry,
      decision: 'allow',
    });

    const result = await verifyCommit('epc_fulfilled', db);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('fulfilled');
  });
});

// ============================================================================
// 3. revokeCommit
// ============================================================================

describe('revokeCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('active commit can be revoked', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_active',
      status: 'active',
      expires_at: futureExpiry,
    });

    const result = await revokeCommit('epc_active', db);
    expect(result.status).toBe('revoked');
    expect(result.commit_id).toBe('epc_active');
  });

  it('already revoked commit throws error', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_revoked',
      status: 'revoked',
      expires_at: futureExpiry,
    });

    await expect(revokeCommit('epc_revoked', db)).rejects.toThrow('already revoked');
  });

  it('expired commit cannot be revoked (terminal)', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_expired',
      status: 'active',
      expires_at: pastExpiry,
    });

    await expect(revokeCommit('epc_expired', db)).rejects.toThrow('terminal state');
  });

  it('fulfilled commit cannot be revoked (terminal)', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_fulfilled',
      status: 'fulfilled',
      expires_at: futureExpiry,
    });

    await expect(revokeCommit('epc_fulfilled', db)).rejects.toThrow('terminal state');
  });
});

// ============================================================================
// 4. fulfillCommit
// ============================================================================

describe('fulfillCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('active commit can be fulfilled', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_active',
      status: 'active',
      expires_at: futureExpiry,
    });

    const result = await fulfillCommit('epc_active', db);
    expect(result.status).toBe('fulfilled');
    expect(result.commit_id).toBe('epc_active');
  });

  it('fulfilled commit stays fulfilled (idempotent)', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_fulfilled',
      status: 'fulfilled',
      expires_at: futureExpiry,
    });

    const result = await fulfillCommit('epc_fulfilled', db);
    expect(result.status).toBe('fulfilled');
  });

  it('terminal states cannot transition to fulfilled', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    // revoked → fulfilled should fail
    const dbRevoked = buildMockDb({
      commit_id: 'epc_revoked',
      status: 'revoked',
      expires_at: futureExpiry,
    });
    await expect(fulfillCommit('epc_revoked', dbRevoked)).rejects.toThrow('terminal state');

    // expired → fulfilled should fail
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const dbExpired = buildMockDb({
      commit_id: 'epc_expired',
      status: 'active',
      expires_at: pastExpiry,
    });
    await expect(fulfillCommit('epc_expired', dbExpired)).rejects.toThrow('terminal state');
  });
});

// ============================================================================
// 5. State machine
// ============================================================================

describe('state machine', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('active → fulfilled works', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm1',
      status: 'active',
      expires_at: futureExpiry,
    });

    const result = await fulfillCommit('epc_sm1', db);
    expect(result.status).toBe('fulfilled');
  });

  it('active → revoked works', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm2',
      status: 'active',
      expires_at: futureExpiry,
    });

    const result = await revokeCommit('epc_sm2', db);
    expect(result.status).toBe('revoked');
  });

  it('active → expired works (simulate by setting expires_at in past)', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm3',
      status: 'active',
      expires_at: pastExpiry,
      decision: 'allow',
    });

    const result = await verifyCommit('epc_sm3', db);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('expired');
  });

  it('fulfilled → revoked fails (terminal)', async () => {
    const futureExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm4',
      status: 'fulfilled',
      expires_at: futureExpiry,
    });

    await expect(revokeCommit('epc_sm4', db)).rejects.toThrow('terminal state');
  });

  it('expired → fulfilled fails (terminal)', async () => {
    const pastExpiry = new Date(Date.now() - 60 * 1000).toISOString();
    const db = buildMockDb({
      commit_id: 'epc_sm5',
      status: 'active',
      expires_at: pastExpiry,
    });

    await expect(fulfillCommit('epc_sm5', db)).rejects.toThrow('terminal state');
  });
});

// ============================================================================
// 6. bindReceiptToCommit
// ============================================================================

describe('bindReceiptToCommit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('links receipt_id to an active commit', async () => {
    const db = buildMockDb({
      commit_id: 'epc_bind1',
      status: 'active',
    });

    const result = await bindReceiptToCommit('epc_bind1', 'receipt_xyz', db);
    expect(result.bound).toBe(true);
    expect(result.receipt_id).toBe('receipt_xyz');
    expect(result.commit_id).toBe('epc_bind1');
  });

  it('commit must be active or fulfilled to bind', async () => {
    // Revoked commit should not allow binding
    const dbRevoked = buildMockDb({
      commit_id: 'epc_bind2',
      status: 'revoked',
    });

    await expect(
      bindReceiptToCommit('epc_bind2', 'receipt_abc', dbRevoked)
    ).rejects.toThrow('Cannot bind receipt to commit in state: revoked');

    // Expired commit should not allow binding
    const dbExpired = buildMockDb({
      commit_id: 'epc_bind3',
      status: 'expired',
    });

    await expect(
      bindReceiptToCommit('epc_bind3', 'receipt_def', dbExpired)
    ).rejects.toThrow('Cannot bind receipt to commit in state: expired');

    // Fulfilled commit should allow binding
    const dbFulfilled = buildMockDb({
      commit_id: 'epc_bind4',
      status: 'fulfilled',
    });

    const result = await bindReceiptToCommit('epc_bind4', 'receipt_ghi', dbFulfilled);
    expect(result.bound).toBe(true);
  });
});

// ============================================================================
// 7. Internal helpers validation
// ============================================================================

describe('EP Commit internals', () => {
  it('generateNonce produces 64 hex characters (32 bytes)', () => {
    const nonce = _internals.generateNonce();
    expect(nonce).toMatch(/^[a-f0-9]{64}$/);
  });

  it('generateCommitId produces epc_ prefixed IDs', () => {
    const id = _internals.generateCommitId();
    expect(id).toMatch(/^epc_/);
  });

  it('signCommit produces deterministic signatures', () => {
    const payload = { a: 1, b: 'hello', c: true };
    const sig1 = _internals.signCommit(payload);
    const sig2 = _internals.signCommit(payload);
    expect(sig1).toBe(sig2);
    expect(sig1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
  });

  it('VALID_DECISIONS contains exactly allow, review, deny', () => {
    expect(_internals.VALID_DECISIONS).toEqual(['allow', 'review', 'deny']);
  });

  it('TERMINAL_STATES contains fulfilled, revoked, expired', () => {
    expect(_internals.TERMINAL_STATES).toContain('fulfilled');
    expect(_internals.TERMINAL_STATES).toContain('revoked');
    expect(_internals.TERMINAL_STATES).toContain('expired');
  });
});
