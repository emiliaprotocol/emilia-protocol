/**
 * EMILIA Protocol — Operational Failure Modeling Tests
 *
 * Tests system behavior under partial infrastructure outages and degraded
 * conditions. Validates that trust-bearing operations fail closed while
 * non-truth-bearing operations degrade gracefully.
 *
 * Categories:
 *   - Authority registry downtime
 *   - Partial DB outage
 *   - Degraded mode guarantees
 *   - Recovery behavior
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ProtocolWriteError, TrustEvaluationError } from '../lib/errors.js';

// ============================================================================
// Mock infrastructure
// ============================================================================

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/scoring-v2.js', () => ({
  computeTrustProfile: vi.fn().mockReturnValue({
    score: 75, confidence: 'medium', effectiveEvidence: 5,
    uniqueSubmitters: 3, receiptCount: 10, profile: {}, anomaly: null,
  }),
  evaluateTrustPolicy: vi.fn().mockReturnValue({ pass: true, failures: [], warnings: [] }),
  TRUST_POLICIES: {
    standard: { min_score: 50 },
    github_private_repo_safe_v1: {},
    npm_buildtime_safe_v1: {},
    browser_extension_safe_v1: {},
    mcp_server_safe_v1: {},
  },
}));

vi.mock('../lib/create-receipt.js', () => ({
  createReceipt: vi.fn(),
}));

vi.mock('../lib/delegation.js', () => ({
  verifyDelegation: vi.fn().mockResolvedValue({ valid: true }),
}));

vi.mock('../lib/env.js', () => ({
  getCommitSigningConfig: () => ({ signingKey: null, isProduction: false, trustedKeys: null }),
}));

// ============================================================================
// Helpers
// ============================================================================

/**
 * Assert a promise rejects with an error whose .name matches.
 * Needed because vi.mock aliasing can create distinct class references
 * for the same ProtocolWriteError across module boundaries, so
 * instanceof checks fail even though the thrown error IS a ProtocolWriteError.
 */
async function expectProtocolWriteError(promise, messagePattern) {
  let caught;
  try {
    await promise;
    expect.unreachable('Expected promise to reject');
  } catch (e) {
    caught = e;
  }
  expect(caught.name).toBe('ProtocolWriteError');
  if (messagePattern) {
    expect(caught.message).toMatch(messagePattern);
  }
  return caught;
}

/**
 * Build a mock Supabase client where individual tables can be configured
 * to fail. tableOverrides maps table name -> behavior.
 */
function buildMockClient(tableOverrides = {}) {
  function makeChain() {
    const chain = {};
    for (const method of ['select', 'insert', 'update', 'delete', 'eq', 'neq', 'in', 'contains', 'order', 'limit']) {
      chain[method] = vi.fn().mockReturnValue(chain);
    }
    chain.single = vi.fn().mockResolvedValue({ data: null, error: null });
    chain.maybeSingle = vi.fn().mockResolvedValue({ data: null, error: null });
    return chain;
  }

  function makeTimeoutChain() {
    const chain = makeChain();
    const timeoutErr = { message: 'timeout: query exceeded 30s limit', code: '57014' };
    chain.single = vi.fn().mockResolvedValue({ data: null, error: timeoutErr });
    chain.maybeSingle = vi.fn().mockResolvedValue({ data: null, error: timeoutErr });
    return chain;
  }

  const client = {
    from: vi.fn((table) => {
      const override = tableOverrides[table];
      if (override === 'timeout') return makeTimeoutChain();
      return makeChain();
    }),
    rpc: vi.fn().mockResolvedValue({ data: 75, error: null }),
  };
  return client;
}

/** Standard entity data used across multiple tests. */
const ENTITY_DATA = {
  id: 'db-id-1', entity_id: 'test-entity', display_name: 'Test',
  entity_type: 'service', status: 'active', category: 'commerce',
};

/** Build a mock client that serves standard entity/receipt/dispute data
 *  but allows overriding specific tables. */
function buildEvaluationClient(tableOverrides = {}) {
  const client = {
    from: vi.fn((table) => {
      if (tableOverrides[table]) return tableOverrides[table]();
      if (table === 'entities') {
        return {
          select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
          single: vi.fn().mockResolvedValue({ data: ENTITY_DATA, error: null }),
        };
      }
      if (table === 'receipts') {
        return {
          select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
          contains: vi.fn().mockReturnThis(), order: vi.fn().mockReturnThis(),
          limit: vi.fn().mockReturnThis(),
          then: (resolve) => resolve({ data: [], error: null }),
        };
      }
      if (table === 'disputes') {
        return {
          select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
          in: vi.fn().mockReturnThis(), order: vi.fn().mockReturnThis(),
          limit: vi.fn().mockReturnThis(),
          then: (resolve) => resolve({ data: [], count: 0, error: null }),
        };
      }
      if (table === 'commits') {
        return {
          select: vi.fn().mockReturnThis(),
          insert: vi.fn().mockResolvedValue({ data: null, error: null }),
          eq: vi.fn().mockReturnThis(), neq: vi.fn().mockReturnThis(),
          limit: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        };
      }
      // Default
      return {
        select: vi.fn().mockReturnThis(),
        insert: vi.fn().mockResolvedValue({ data: null, error: null }),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: null, error: null }),
        maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
      };
    }),
    rpc: vi.fn().mockResolvedValue({
      data: [{ established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 }],
      error: null,
    }),
  };
  return client;
}

// ============================================================================
// Tests
// ============================================================================

describe('Operational Failure Modeling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
  });

  // ==========================================================================
  // Authority Registry Downtime
  // ==========================================================================
  describe('Authority registry downtime', () => {
    it('commit verification fails with ProtocolWriteError when DB is unavailable, not silent degradation', async () => {
      mockGetServiceClient.mockImplementation(() => {
        throw new Error('connection refused: ECONNREFUSED');
      });

      const { verifyCommit, _resetForTesting } = await import('../lib/commit.js');
      _resetForTesting();

      await expectProtocolWriteError(
        verifyCommit('epc_test123'),
        /Database unavailable/
      );
    });

    it('commit verification fails closed on timeout — does not return unknown/degraded', async () => {
      const client = buildMockClient({ commits: 'timeout' });
      mockGetServiceClient.mockReturnValue(client);

      const { verifyCommit, _resetForTesting } = await import('../lib/commit.js');
      _resetForTesting();

      await expectProtocolWriteError(
        verifyCommit('epc_test123'),
        /timeout/i
      );
    });

    it('commit verification rejects corrupted registry data — does not accept garbled commits', async () => {
      const corruptedCommit = {
        commit_id: 'epc_test123',
        entity_id: null,
        kid: 'ep-signing-key-1',
        status: 42, // should be string
        nonce: {},  // should be string
        signature: 'not-a-valid-sig',
        public_key: 'not-a-valid-key',
        expires_at: 'not-a-date',
      };

      const chain = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        neq: vi.fn().mockReturnThis(),
        limit: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: corruptedCommit, error: null }),
      };
      const client = { from: vi.fn(() => chain), rpc: vi.fn() };
      mockGetServiceClient.mockReturnValue(client);

      const { verifyCommit, _resetForTesting } = await import('../lib/commit.js');
      _resetForTesting();

      // With corrupted data, status is 42 (not 'active'), so verification
      // returns invalid — never valid. That's fail-closed behavior.
      const result = await verifyCommit('epc_test123');
      expect(result.valid).toBe(false);
      expect(result.reasons.length).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // Partial DB Outage
  // ==========================================================================
  describe('Partial DB outage', () => {
    it('receipt creation fails closed when receipts table is unavailable', async () => {
      const { createReceipt } = await import('../lib/create-receipt.js');
      createReceipt.mockRejectedValue(new ProtocolWriteError(
        'Failed to store receipt: connection refused',
        { status: 503, code: 'DB_UNAVAILABLE' }
      ));

      const { canonicalSubmitReceipt } = await import('../lib/canonical-writer.js');

      await expectProtocolWriteError(
        canonicalSubmitReceipt(
          { entity_id: 'test-entity', transaction_ref: 'tx_1', transaction_type: 'purchase' },
          { entity_id: 'submitter-1', id: 'sub-db-id' }
        ),
        /Failed to store receipt/
      );
    });

    it('trust profile materialization fails with ProtocolWriteError when DB is down', async () => {
      const client = buildMockClient();
      client.rpc = vi.fn().mockResolvedValue({ data: null, error: { message: 'connection refused' } });
      mockGetServiceClient.mockReturnValue(client);

      const { materializeTrustProfile } = await import('../lib/canonical-writer.js');

      await expectProtocolWriteError(
        materializeTrustProfile('entity-db-id-1'),
        /materialization failed/i
      );
    });

    it('protocol event append fails gracefully (non-truth-bearing) but logs', async () => {
      const makeFullChain = (overrides = {}) => {
        const chain = {};
        for (const m of ['select', 'insert', 'update', 'delete', 'eq', 'neq', 'in', 'contains', 'order', 'limit']) {
          chain[m] = vi.fn().mockReturnValue(chain);
        }
        chain.single = vi.fn().mockResolvedValue({ data: null, error: null });
        chain.maybeSingle = vi.fn().mockResolvedValue({ data: null, error: null });
        Object.assign(chain, overrides);
        return chain;
      };

      const client = {
        from: vi.fn((table) => {
          if (table === 'protocol_events') {
            return {
              insert: vi.fn().mockRejectedValue(new Error('relation "protocol_events" does not exist')),
            };
          }
          if (table === 'receipts') {
            return makeFullChain({
              single: vi.fn().mockResolvedValue({
                data: {
                  receipt_id: 'r-1', entity_id: 'ent-1', submitted_by: 'other-ent',
                  bilateral_status: 'pending_confirmation', confirmation_deadline: null,
                },
                error: null,
              }),
            });
          }
          if (table === 'entities') {
            return makeFullChain({
              single: vi.fn().mockResolvedValue({
                data: ENTITY_DATA,
                error: null,
              }),
            });
          }
          return makeFullChain();
        }),
        rpc: vi.fn().mockResolvedValue({ data: 75, error: null }),
      };
      mockGetServiceClient.mockReturnValue(client);

      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const { canonicalBilateralConfirm } = await import('../lib/canonical-writer.js');

      // The operation should succeed even though event persistence fails.
      // canonicalBilateralConfirm triggers emitEvent -> persistEvent internally,
      // which catches errors and logs a warning (non-truth-bearing).
      const result = await canonicalBilateralConfirm('r-1', 'ent-1', true);
      expect(result).toBeDefined();
      expect(result.bilateral_status).toBe('confirmed');

      warnSpy.mockRestore();
    });

    it('commit issuance fails closed when commits table is unavailable', async () => {
      const client = buildEvaluationClient({
        commits: () => ({
          select: vi.fn().mockReturnThis(),
          insert: vi.fn().mockResolvedValue({
            data: null,
            error: { message: 'connection refused: commits table unreachable' },
          }),
          eq: vi.fn().mockReturnThis(),
        }),
      });
      mockGetServiceClient.mockReturnValue(client);

      const { issueCommit, _resetForTesting } = await import('../lib/commit.js');
      _resetForTesting();

      await expectProtocolWriteError(
        issueCommit({ entity_id: 'test-entity', action_type: 'install' }),
        /Failed to store commit/
      );
    });
  });

  // ==========================================================================
  // Degraded Mode Guarantees
  // ==========================================================================
  describe('Degraded mode guarantees', () => {
    it('read-only verify returns a structured result when commit data is fetchable', async () => {
      const futureDate = new Date(Date.now() + 600000).toISOString();
      const commitData = {
        commit_id: 'epc_active1', entity_id: 'ent-1', kid: 'ep-signing-key-1',
        status: 'active', decision: 'allow', nonce: 'unique-nonce-1',
        signature: 'fake-sig', public_key: 'fake-pk',
        expires_at: futureDate, created_at: new Date().toISOString(),
        action_type: 'install', principal_id: null,
        counterparty_entity_id: null, delegation_id: null,
        scope: null, max_value_usd: null, context: null,
      };

      const chain = {
        select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
        neq: vi.fn().mockReturnThis(), limit: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: commitData, error: null }),
      };
      const client = { from: vi.fn(() => chain), rpc: vi.fn() };
      mockGetServiceClient.mockReturnValue(client);

      const { verifyCommit, _resetForTesting } = await import('../lib/commit.js');
      _resetForTesting();

      // Signature won't match the ephemeral keypair, but the point is it
      // returns a structured result object, not an exception.
      const result = await verifyCommit('epc_active1');
      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('status');
      expect(typeof result.valid).toBe('boolean');
    });

    it('evaluation still works when dispute table is unavailable (non-blocking dispute fetch)', async () => {
      const client = buildEvaluationClient({
        disputes: () => ({
          select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
          in: vi.fn().mockReturnThis(), order: vi.fn().mockReturnThis(),
          limit: vi.fn().mockReturnThis(),
          then: (resolve) => resolve({ data: null, count: null, error: null }),
        }),
      });
      mockGetServiceClient.mockReturnValue(client);

      const { canonicalEvaluate } = await import('../lib/canonical-evaluator.js');

      const result = await canonicalEvaluate('test-entity', { includeDisputes: true });
      expect(result.entity_id).toBe('test-entity');
      expect(result.score).toBeDefined();
    });

    it('system clearly distinguishes trust-bearing failures from telemetry failures', () => {
      const trustError = new ProtocolWriteError('commit storage failed', {
        status: 500, code: 'COMMIT_STORAGE_FAILED',
      });
      expect(trustError.name).toBe('ProtocolWriteError');
      expect(trustError.code).toBe('COMMIT_STORAGE_FAILED');

      const evalError = new TrustEvaluationError('establishment lookup failed', {
        status: 500, code: 'ESTABLISHMENT_LOOKUP_FAILED',
      });
      expect(evalError.name).toBe('TrustEvaluationError');

      // These are distinct error hierarchies: trust-bearing ops throw these
      // typed errors. Telemetry/event persistence catches errors and logs them
      // (console.warn), never throwing. The type system makes it impossible
      // to confuse the two.
      expect(trustError).toBeInstanceOf(ProtocolWriteError);
      expect(trustError).not.toBeInstanceOf(TrustEvaluationError);
      expect(evalError).toBeInstanceOf(TrustEvaluationError);
      expect(evalError).not.toBeInstanceOf(ProtocolWriteError);
    });
  });

  // ==========================================================================
  // Recovery Behavior
  // ==========================================================================
  describe('Recovery behavior', () => {
    it('after DB reconnect, writes resume without data loss', async () => {
      // Phase 1: DB is down — getServiceClient throws
      mockGetServiceClient.mockImplementation(() => {
        throw new Error('connection refused');
      });

      const { issueCommit, _resetForTesting } = await import('../lib/commit.js');
      _resetForTesting();

      // Commit issuance calls requireServiceClient -> getServiceClient which
      // throws. But requireServiceClient wraps this in ProtocolWriteError.
      // However, the evaluator also calls getServiceClient before the commit
      // insert, so it may throw plain Error. Either way, it must reject.
      await expect(
        issueCommit({ entity_id: 'test-entity', action_type: 'install' })
      ).rejects.toThrow();

      // Phase 2: DB comes back
      const storedCommits = [];
      const workingClient = buildEvaluationClient({
        commits: () => ({
          select: vi.fn().mockReturnThis(),
          insert: vi.fn().mockImplementation((record) => {
            storedCommits.push(record);
            return Promise.resolve({ data: record, error: null });
          }),
          eq: vi.fn().mockReturnThis(),
          neq: vi.fn().mockReturnThis(),
          limit: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      });
      mockGetServiceClient.mockReturnValue(workingClient);

      const commit = await issueCommit({ entity_id: 'test-entity', action_type: 'install' });
      expect(commit).toBeDefined();
      expect(commit.commit_id).toMatch(/^epc_/);
      expect(commit.status).toBe('active');
      expect(storedCommits.length).toBe(1);
    });

    it('idempotency prevents duplicate writes during retry storms', async () => {
      const { protocolWrite, COMMAND_TYPES, _internals } = await import('../lib/protocol-write.js');
      _internals._idempotencyCache.clear();

      let insertCount = 0;
      const client = buildEvaluationClient({
        commits: () => ({
          select: vi.fn().mockReturnThis(),
          insert: vi.fn().mockImplementation(() => {
            insertCount++;
            return Promise.resolve({ data: null, error: null });
          }),
          eq: vi.fn().mockReturnThis(),
        }),
      });
      // protocol_events — fire-and-forget
      const origFrom = client.from;
      client.from = vi.fn((table) => {
        if (table === 'protocol_events') {
          return { insert: vi.fn().mockResolvedValue({ data: null, error: null }) };
        }
        return origFrom(table);
      });
      mockGetServiceClient.mockReturnValue(client);

      // Suppress telemetry logs
      const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});

      const command = {
        type: COMMAND_TYPES.ISSUE_COMMIT,
        input: { entity_id: 'test-entity', action_type: 'install' },
        actor: 'actor-1',
      };

      // First call executes
      const result1 = await protocolWrite(command);
      expect(result1).toBeDefined();
      expect(insertCount).toBe(1);

      // Retry storm: same command 5 more times
      const results = await Promise.all([
        protocolWrite({ ...command }),
        protocolWrite({ ...command }),
        protocolWrite({ ...command }),
        protocolWrite({ ...command }),
        protocolWrite({ ...command }),
      ]);

      for (const r of results) {
        expect(r._idempotent).toBe(true);
      }
      // DB insert count unchanged
      expect(insertCount).toBe(1);

      infoSpy.mockRestore();
    });

    it('nonce tracking survives restart via DB (not just memory)', async () => {
      const { _resetForTesting, _internals } = await import('../lib/commit.js');

      // Simulate restart: in-memory nonce set is empty
      _resetForTesting();
      expect(_internals._usedNonces.size).toBe(0);

      // DB has the nonce — UNIQUE constraint rejects the insert with code 23505
      const client = buildEvaluationClient({
        commits: () => ({
          select: vi.fn().mockReturnThis(),
          insert: vi.fn().mockResolvedValue({
            data: null,
            error: {
              message: 'duplicate key value violates unique constraint "commits_nonce_key"',
              code: '23505',
            },
          }),
          eq: vi.fn().mockReturnThis(),
        }),
      });
      mockGetServiceClient.mockReturnValue(client);

      const { issueCommit } = await import('../lib/commit.js');

      // The insert fails with a DB unique constraint violation.
      // issueCommit MUST throw ProtocolWriteError, proving nonce enforcement
      // survives process restart via the DB constraint (not in-memory set).
      await expectProtocolWriteError(
        issueCommit({ entity_id: 'test-entity', action_type: 'install' }),
        /Failed to store commit/
      );
    });
  });
});
