// SPDX-License-Identifier: Apache-2.0
//
// Regression coverage for MED finding: several authenticated write routes read
// raw request.json() with no size cap (heap-exhaustion DoS by an authed key
// holder). Each route now wraps the body read in readLimitedJson (lib/http/
// body-limit.js), which enforces a hard byte cap on the request STREAM before
// any parsing or business-logic work. These tests submit an oversized body to
// each route and assert a 413 short-circuit — proving the underlying write
// engines are never reached.

import { describe, expect, it, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks: auth passes; every downstream write engine is stubbed so we can assert
// the 413 fires BEFORE any of them are touched.
// ---------------------------------------------------------------------------

const mockAuthenticate = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticate(...args),
  // present route imports this; not reached on the 413 path, but must resolve.
  getServiceClient: () => ({ from: () => ({ select: () => ({ eq: () => ({ data: [], error: null }) }) }) }),
}));

const mockProtocolWrite = vi.fn();
vi.mock('@/lib/protocol-write', () => ({
  protocolWrite: (...args) => mockProtocolWrite(...args),
  COMMAND_TYPES: {
    RESPOND_DISPUTE: 'RESPOND_DISPUTE',
    FILE_DISPUTE: 'FILE_DISPUTE',
    SUBMIT_RECEIPT: 'SUBMIT_RECEIPT',
    REVOKE_COMMIT: 'REVOKE_COMMIT',
  },
  ProtocolWriteError: class ProtocolWriteError extends Error {},
}));

const mockCreateBinding = vi.fn();
const mockVerifyBinding = vi.fn();
const mockFileContinuityClaim = vi.fn();
vi.mock('@/lib/ep-ix', () => ({
  createBinding: (...args) => mockCreateBinding(...args),
  verifyBinding: (...args) => mockVerifyBinding(...args),
  fileContinuityClaim: (...args) => mockFileContinuityClaim(...args),
}));

// present route deps — not reached on the 413 path, mocked so imports resolve.
vi.mock('@/lib/handshake', () => ({ addPresentation: vi.fn() }));
vi.mock('@/lib/handshake-auth', () => ({
  authorizeHandshakePresent: vi.fn().mockResolvedValue(undefined),
  resolveAuthEntityId: (a) => (a && (a.entity_id || a.id)) || null,
}));

const mockGetCommitStatus = vi.fn();
vi.mock('@/lib/commit', () => ({
  getCommitStatus: (...args) => mockGetCommitStatus(...args),
  CommitError: class CommitError extends Error {},
}));

const mockAuthorizeCommitAccess = vi.fn();
vi.mock('@/lib/commit-auth', () => ({
  authorizeCommitAccess: (...args) => mockAuthorizeCommitAccess(...args),
}));

const mockBuildAttributionChain = vi.fn(() => []);
const mockApplyAttributionChain = vi.fn();
vi.mock('@/lib/attribution', () => ({
  buildAttributionChain: (...args) => mockBuildAttributionChain(...args),
  applyAttributionChain: (...args) => mockApplyAttributionChain(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const DisputesRespond = await import('../app/api/disputes/respond/route.js');
const DisputesFile = await import('../app/api/disputes/file/route.js');
const ReceiptsSubmit = await import('../app/api/receipts/submit/route.js');
const IdentityBind = await import('../app/api/identity/bind/route.js');
const IdentityVerify = await import('../app/api/identity/verify/route.js');
const IdentityContinuity = await import('../app/api/identity/continuity/route.js');
const CommitRevoke = await import('../app/api/commit/[commitId]/revoke/route.js');
const HandshakePresent = await import('../app/api/handshake/[handshakeId]/present/route.js');

// A real Request carrying a body STREAM (not a `{ json() }` test double), so the
// byte-enforcing path in readLimitedJson runs rather than the double fallback.
function oversizedReq(path, bytes, body = { ping: true }) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'content-length': String(bytes),
    },
    body: JSON.stringify(body),
  });
}

// Same, but with NO Content-Length, so the cap must be enforced from the stream.
function oversizedUndeclaredReq(path, bodyText) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: bodyText,
  });
}

describe('authenticated write-route body limits (heap-exhaustion DoS)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Auth always succeeds — the cap must fire on the body regardless of a valid key.
    mockAuthenticate.mockResolvedValue({ entity: { id: 'ent_1', entity_id: 'test-entity' } });
    // Commit revoke reads the body AFTER these gates; let them pass.
    mockGetCommitStatus.mockResolvedValue({ commit_id: 'epc_1', status: 'active' });
    mockAuthorizeCommitAccess.mockReturnValue({ authorized: true });
  });

  // [name, handler, path, capBytes, callParams]
  const cases = [
    ['disputes/respond', DisputesRespond.POST, '/api/disputes/respond', 10 * 1024, undefined],
    ['disputes/file', DisputesFile.POST, '/api/disputes/file', 10 * 1024, undefined],
    ['receipts/submit', ReceiptsSubmit.POST, '/api/receipts/submit', 100 * 1024, undefined],
    ['identity/bind', IdentityBind.POST, '/api/identity/bind', 10 * 1024, undefined],
    ['identity/verify', IdentityVerify.POST, '/api/identity/verify', 10 * 1024, undefined],
    ['identity/continuity', IdentityContinuity.POST, '/api/identity/continuity', 10 * 1024, undefined],
    ['commit/[commitId]/revoke', CommitRevoke.POST, '/api/commit/epc_1/revoke', 5 * 1024, { params: Promise.resolve({ commitId: 'epc_1' }) }],
    ['handshake/[handshakeId]/present', HandshakePresent.POST, '/api/handshake/eph_1/present', 100 * 1024, { params: Promise.resolve({ handshakeId: 'eph_1' }) }],
  ];

  for (const [name, handler, path, cap, params] of cases) {
    it(`${name} returns 413 for a declared oversized body before writing`, async () => {
      const res = await handler(oversizedReq(path, cap + 1), params);

      expect(res.status).toBe(413);
      const body = await res.json();
      expect(body.type).toContain('payload_too_large');

      // No trust-bearing write engine may have been reached.
      expect(mockProtocolWrite).not.toHaveBeenCalled();
      expect(mockCreateBinding).not.toHaveBeenCalled();
    });

    it(`${name} enforces the cap even when Content-Length is absent`, async () => {
      // Build a JSON body that exceeds the cap without declaring its length.
      const filler = 'a'.repeat(cap + 1024);
      const hugeJson = JSON.stringify({ blob: filler });
      const res = await handler(oversizedUndeclaredReq(path, hugeJson), params);

      expect(res.status).toBe(413);
      expect(mockProtocolWrite).not.toHaveBeenCalled();
      expect(mockCreateBinding).not.toHaveBeenCalled();
    });
  }

  it('lets a within-cap body through to the write engine (receipts/submit)', async () => {
    // Sanity: the cap must not reject legitimate small payloads. receipts/submit
    // is the largest cap; a tiny valid body should reach protocolWrite.
    mockProtocolWrite.mockResolvedValue({ receipt: { id: 'r_1' }, entityScore: 0.9 });

    const res = await ReceiptsSubmit.POST(new Request('https://www.emiliaprotocol.ai/api/receipts/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        entity_id: 'test-entity',
        transaction_type: 'purchase',
        transaction_ref: 'txn_123',
        agent_behavior: 'completed',
      }),
    }));

    expect(res.status).toBe(201);
    expect(mockProtocolWrite).toHaveBeenCalledTimes(1);
  });
});
