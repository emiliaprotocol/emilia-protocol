import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Route-contract tests for EP Commit routes
//
// These verify that each commit route returns the exact JSON shape that
// the MCP server and SDKs expect. We mock the underlying lib functions
// and auth layer so these are pure contract tests.
// ============================================================================

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: vi.fn(),
}));

vi.mock('@/lib/commit', () => ({
  issueCommit: vi.fn(),
  verifyCommit: vi.fn(),
  getCommitStatus: vi.fn(),
  revokeCommit: vi.fn(),
  bindReceiptToCommit: vi.fn(),
  fulfillCommit: vi.fn(),
  CommitError: class CommitError extends Error {
    constructor(message, status, code) {
      super(message);
      this.status = status;
      this.code = code;
    }
  },
}));

vi.mock('@/lib/commit-auth', () => ({
  authorizeCommitIssuance: vi.fn(),
  authorizeCommitAccess: vi.fn(),
}));

import { authenticateRequest } from '@/lib/supabase';
import {
  issueCommit,
  verifyCommit,
  getCommitStatus,
  revokeCommit,
  bindReceiptToCommit,
  fulfillCommit,
} from '@/lib/commit';
import { authorizeCommitIssuance, authorizeCommitAccess } from '@/lib/commit-auth';

// Route handlers
import { POST as issueRoute } from '@/app/api/commit/issue/route';
import { POST as verifyRoute } from '@/app/api/commit/verify/route';
import { GET as statusRoute } from '@/app/api/commit/[commitId]/route';
import { POST as revokeRoute } from '@/app/api/commit/[commitId]/revoke/route';
import { POST as receiptRoute } from '@/app/api/commit/[commitId]/receipt/route';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(body) {
  return {
    json: () => Promise.resolve(body),
    headers: new Headers({ 'Content-Type': 'application/json' }),
  };
}

function makeParams(commitId) {
  return { params: Promise.resolve({ commitId }) };
}

const MOCK_COMMIT = {
  commit_id: 'epc_test_123',
  entity_id: 'test-entity',
  principal_id: null,
  counterparty_entity_id: null,
  delegation_id: null,
  action_type: 'transact',
  decision: 'allow',
  scope: null,
  max_value_usd: 500,
  context: null,
  nonce: 'nonce_abc',
  signature: 'sig_xyz',
  public_key: 'pk_123',
  expires_at: '2026-03-19T00:00:00.000Z',
  status: 'active',
  created_at: '2026-03-18T00:00:00.000Z',
  appeal_path: '/api/disputes/report',
};

const MOCK_AUTH = { entity: { entity_id: 'test-entity' } };

beforeEach(() => {
  vi.clearAllMocks();
  authenticateRequest.mockResolvedValue(MOCK_AUTH);
  authorizeCommitIssuance.mockResolvedValue({ authorized: true });
  authorizeCommitAccess.mockReturnValue({ authorized: true });
});

// ============================================================================
// POST /api/commit/issue
// ============================================================================

describe('POST /api/commit/issue — response shape', () => {
  it('returns { decision: string, commit: { commit_id, ... } }', async () => {
    issueCommit.mockResolvedValue(MOCK_COMMIT);

    const req = makeRequest({
      action_type: 'transact',
      entity_id: 'test-entity',
    });

    const res = await issueRoute(req);
    const data = await res.json();

    // Top-level keys
    expect(data).toHaveProperty('decision');
    expect(data).toHaveProperty('commit');
    expect(typeof data.decision).toBe('string');
    expect(data.decision).toBe('allow');

    // Nested commit object
    expect(data.commit).toHaveProperty('commit_id');
    expect(data.commit).toHaveProperty('entity_id');
    expect(data.commit).toHaveProperty('action_type');
    expect(data.commit).toHaveProperty('decision');
    expect(data.commit).toHaveProperty('status');
    expect(data.commit).toHaveProperty('expires_at');
    expect(data.commit).toHaveProperty('created_at');
    expect(data.commit.commit_id).toBe('epc_test_123');
    expect(res.status).toBe(201);
  });

  it('decision matches commit.decision', async () => {
    issueCommit.mockResolvedValue({ ...MOCK_COMMIT, decision: 'deny' });

    const req = makeRequest({
      action_type: 'transact',
      entity_id: 'test-entity',
    });

    const res = await issueRoute(req);
    const data = await res.json();

    expect(data.decision).toBe('deny');
    expect(data.commit.decision).toBe('deny');
  });
});

// ============================================================================
// POST /api/commit/verify
// ============================================================================

describe('POST /api/commit/verify — response shape', () => {
  it('returns { valid: boolean, status: string, commit_id is NOT present, ... }', async () => {
    verifyCommit.mockResolvedValue({
      valid: true,
      status: 'active',
      decision: 'allow',
      expires_at: '2026-03-19T00:00:00.000Z',
      entity_id: 'test-entity',
      action_type: 'transact',
      scope: null,
    });

    const req = makeRequest({ commit_id: 'epc_test_123' });
    const res = await verifyRoute(req);
    const data = await res.json();

    expect(data).toHaveProperty('valid', true);
    expect(data).toHaveProperty('status', 'active');
    expect(data).toHaveProperty('decision', 'allow');
    expect(data).toHaveProperty('expires_at');
    expect(data).toHaveProperty('reasons');
    // Minimum disclosure: verify MUST NOT expose entity_id, action_type, or scope
    expect(data).not.toHaveProperty('entity_id');
    expect(data).not.toHaveProperty('action_type');
    expect(data).not.toHaveProperty('scope');

    // The verify route does NOT return commit_id in the response body
    // MCP handler should use args.commit_id instead
    expect(data).not.toHaveProperty('commit_id');

    expect(res.status).toBe(200);
  });
});

// ============================================================================
// GET /api/commit/[commitId]
// ============================================================================

describe('GET /api/commit/[commitId] — response shape', () => {
  it('returns { commit: { commit_id, status, ... } }', async () => {
    getCommitStatus.mockResolvedValue(MOCK_COMMIT);

    const req = makeRequest({});
    const res = await statusRoute(req, makeParams('epc_test_123'));
    const data = await res.json();

    // Top-level: only { commit }
    expect(data).toHaveProperty('commit');
    expect(data).not.toHaveProperty('commit_id');
    expect(data).not.toHaveProperty('status');

    // Nested commit
    expect(data.commit).toHaveProperty('commit_id', 'epc_test_123');
    expect(data.commit).toHaveProperty('status', 'active');
    expect(data.commit).toHaveProperty('action_type', 'transact');
    expect(data.commit).toHaveProperty('entity_id', 'test-entity');
    expect(data.commit).toHaveProperty('decision', 'allow');
    expect(data.commit).toHaveProperty('expires_at');

    expect(res.status).toBe(200);
  });

  it('returns 404 when commit not found', async () => {
    getCommitStatus.mockResolvedValue(null);

    const req = makeRequest({});
    const res = await statusRoute(req, makeParams('epc_nonexistent'));

    expect(res.status).toBe(404);
  });
});

// ============================================================================
// POST /api/commit/[commitId]/revoke
// ============================================================================

describe('POST /api/commit/[commitId]/revoke — response shape', () => {
  it('returns { commit_id, status: "revoked", revoked_at }', async () => {
    getCommitStatus.mockResolvedValue(MOCK_COMMIT);
    revokeCommit.mockResolvedValue({ commit_id: 'epc_test_123' });

    const req = makeRequest({ reason: 'No longer needed' });
    const res = await revokeRoute(req, makeParams('epc_test_123'));
    const data = await res.json();

    expect(data).toHaveProperty('commit_id', 'epc_test_123');
    expect(data).toHaveProperty('status', 'revoked');
    expect(data).toHaveProperty('revoked_at');

    // Verify revoked_at is a valid ISO timestamp
    expect(new Date(data.revoked_at).toISOString()).toBe(data.revoked_at);

    expect(res.status).toBe(200);
  });
});

// ============================================================================
// POST /api/commit/[commitId]/receipt
// ============================================================================

describe('POST /api/commit/[commitId]/receipt — response shape', () => {
  it('returns { commit_id, status: "fulfilled", receipt_id }', async () => {
    getCommitStatus.mockResolvedValue(MOCK_COMMIT);
    bindReceiptToCommit.mockResolvedValue({
      commit_id: 'epc_test_123',
      receipt_id: 'ep_rcpt_abc',
    });
    fulfillCommit.mockResolvedValue({});

    const req = makeRequest({ receipt_id: 'ep_rcpt_abc' });
    const res = await receiptRoute(req, makeParams('epc_test_123'));
    const data = await res.json();

    expect(data).toHaveProperty('commit_id', 'epc_test_123');
    expect(data).toHaveProperty('status', 'fulfilled');
    expect(data).toHaveProperty('receipt_id', 'ep_rcpt_abc');

    expect(res.status).toBe(200);
  });

  it('returns 400 when receipt_id is missing', async () => {
    getCommitStatus.mockResolvedValue(MOCK_COMMIT);

    const req = makeRequest({});
    const res = await receiptRoute(req, makeParams('epc_test_123'));

    expect(res.status).toBe(400);
  });
});
