// SPDX-License-Identifier: Apache-2.0
//
// Regression for the commit-dispute IDOR. POST /api/commit/[commitId]/dispute
// authenticated the caller and loaded the commit but never called
// authorizeCommitAccess — so any authenticated entity could file a dispute
// against a commit they don't own, starting a 7-day response clock against the
// real receipt submitter. Its revoke sibling always gated on authorizeCommitAccess.
// (Isolated file: the dispute route uses getGuardedClient, which the shared
// commit-routes suite must not mock — the issue route relies on the real one.)

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/supabase', () => ({ authenticateRequest: vi.fn() }));

const guard = vi.hoisted(() => ({ single: vi.fn() }));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from: () => ({ select: () => ({ eq: () => ({ single: guard.single }) }) }),
  }),
}));

vi.mock('@/lib/commit-auth', () => ({ authorizeCommitAccess: vi.fn() }));

const protocolWrite = vi.fn();
vi.mock('@/lib/protocol-write', () => ({
  protocolWrite: (...a) => protocolWrite(...a),
  COMMAND_TYPES: { FILE_DISPUTE: 'FILE_DISPUTE' },
}));

vi.mock('@/lib/commit', () => ({ CommitError: class CommitError extends Error {} }));

import { authenticateRequest } from '@/lib/supabase';
import { authorizeCommitAccess } from '@/lib/commit-auth';
import { POST as disputeRoute } from '@/app/api/commit/[commitId]/dispute/route';

const AUTH = { entity: { entity_id: 'owner-entity' } };
const COMMIT = {
  commit_id: 'epc_1', entity_id: 'owner-entity', principal_id: null,
  receipt_id: 'rcpt_1', action_type: 'transact', scope: null,
};

function req(body = {}) {
  return { json: () => Promise.resolve(body), headers: new Headers({ 'content-type': 'application/json' }) };
}
const params = { params: Promise.resolve({ commitId: 'epc_1' }) };

beforeEach(() => {
  vi.clearAllMocks();
  authenticateRequest.mockResolvedValue(AUTH);
  guard.single.mockResolvedValue({ data: COMMIT, error: null });
  authorizeCommitAccess.mockReturnValue({ authorized: true });
  protocolWrite.mockResolvedValue({ dispute_id: 'dsp_1' });
});

describe('POST /api/commit/[commitId]/dispute — authorization (IDOR regression)', () => {
  it('rejects with 403 and files nothing when caller is not issuer or principal', async () => {
    authorizeCommitAccess.mockReturnValue({ authorized: false, reason: 'Only the issuing entity or principal can dispute this commit' });
    const res = await disputeRoute(req({ reason: 'context_mismatch' }), params);
    expect(res.status).toBe(403);
    expect(authorizeCommitAccess).toHaveBeenCalledWith(AUTH, COMMIT, 'dispute');
    expect(protocolWrite).not.toHaveBeenCalled();
  });

  it('files the dispute (201) when the caller is authorized', async () => {
    const res = await disputeRoute(req({ reason: 'context_mismatch' }), params);
    expect(res.status).toBe(201);
    expect(protocolWrite).toHaveBeenCalledTimes(1);
    expect(protocolWrite.mock.calls[0][0].type).toBe('FILE_DISPUTE');
  });

  it('gates authz BEFORE the receipt-binding probe (no state leak): unauthorized caller on a receiptless commit still gets 403, not 409', async () => {
    guard.single.mockResolvedValue({ data: { ...COMMIT, receipt_id: null }, error: null });
    authorizeCommitAccess.mockReturnValue({ authorized: false, reason: 'nope' });
    const res = await disputeRoute(req({ reason: 'x' }), params);
    expect(res.status).toBe(403);
  });
});
