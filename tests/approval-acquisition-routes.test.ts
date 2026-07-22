// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import {
  APPROVAL_REQUIRED_FIELDS,
  bindApprovalCreateRequestScope,
  buildPaymentReleaseActionIdentity,
  parseApprovalCreateRequest,
} from '../lib/approval-acquisition/contract.ts';
import {
  encryptPollToken,
  hashPollToken,
} from '../lib/approval-acquisition/token.ts';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  requirePermission: vi.fn(),
  reserve: vi.fn(),
  enterBoundary: vi.fn(),
  complete: vi.fn(),
  reconcile: vi.fn(),
  refuse: vi.fn(),
  recoverPollToken: vi.fn(),
  find: vi.fn(),
  loadStatus: vi.fn(),
  cloudPost: vi.fn(),
  rateLimit: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock('@/lib/cloud/auth', () => ({ authenticateCloudRequest: mocks.authenticate }));
vi.mock('@/lib/cloud/authorize', () => ({
  requirePermission: mocks.requirePermission,
  CloudAuthorizationError: class CloudAuthorizationError extends Error {},
}));
vi.mock('@/lib/approval-acquisition/store.js', () => ({
  reserveApprovalRequest: mocks.reserve,
  enterApprovalRequestBoundary: mocks.enterBoundary,
  completeApprovalRequest: mocks.complete,
  reconcileApprovalRequest: mocks.reconcile,
  refuseApprovalRequest: mocks.refuse,
  recoverApprovalPollToken: mocks.recoverPollToken,
  findApprovalRequest: mocks.find,
  ApprovalStorageError: class ApprovalStorageError extends Error {},
}));
vi.mock('@/lib/approval-acquisition/evidence.js', () => ({
  loadApprovalStatus: mocks.loadStatus,
  ApprovalEvidenceError: class ApprovalEvidenceError extends Error {},
}));
vi.mock('@/app/api/cloud/approvals/route.js', () => ({ POST: mocks.cloudPost }));
vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: mocks.rateLimit,
  getClientIP: () => '203.0.113.1',
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: mocks.loggerError, warn: vi.fn(), info: vi.fn() },
}));

const ORIGINAL_KEY = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
const ORIGINAL_KEYRING = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
const ORIGINAL_ACTIVE_KEY_ID = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
const ORIGINAL_ORIGIN = process.env.EP_APPROVAL_PUBLIC_ORIGIN;
let POST: (request: any) => Promise<Response>;
let GET: (request: any, context: any) => Promise<Response>;

const futureExpiry = () => new Date(Date.now() + 10 * 60 * 1000).toISOString();

function validBody() {
  const material = {
    action_type: 'payment.release',
    amount_usd: 200,
    currency: 'USD',
    payment_instruction_id: 'payment:bike:0001',
    beneficiary_account_hash: `sha256:${'a'.repeat(64)}`,
    counterparty_name: 'Bicycle Shop',
  };
  const identity = buildPaymentReleaseActionIdentity(material);
  if (!identity.ok) throw new Error(identity.detail);
  const action = { ...material, action_caid: identity.actionCaid };
  return {
    flow: 'EP-APPROVAL-v1',
    challenge: {
      action: 'payment.release',
      action_hash: approvalActionHash(action),
      required_fields: [...APPROVAL_REQUIRED_FIELDS],
      caid_selector: { field: 'action_caid' },
    },
    action,
    approver_id: 'approver@example.test',
    idempotency_key: 'idem_0123456789abcdef',
  };
}

function request(body = validBody()) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/approvals', {
    method: 'POST',
    headers: { authorization: 'Bearer ept_test_secret', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function pendingRow(token = `apt_${'b'.repeat(48)}`) {
  const requestId = `apr_${'a'.repeat(32)}`;
  const tokenHash = hashPollToken(token);
  const scope = {
    requestId,
    tenantId: 'tenant-a',
    environment: 'production',
    requesterKeyId: 'key-a',
    pollTokenHash: tokenHash,
  };
  const sealed = encryptPollToken(token, scope);
  const parsed = parseApprovalCreateRequest(validBody());
  if (!parsed.ok) throw new Error(parsed.code);
  const scoped = bindApprovalCreateRequestScope(parsed.value, {
    tenantId: 'tenant-a',
    environment: 'production',
  });
  return {
    request_id: requestId,
    tenant_id: 'tenant-a',
    environment: 'production',
    requester_key_id: 'key-a',
    producer_key_id: 'key-a',
    idempotency_digest: scoped.idempotencyDigest,
    request_digest: scoped.requestDigest,
    challenge_hash: scoped.challengeHash,
    action_hash: validBody().challenge.action_hash,
    action_caid: validBody().action.action_caid,
    action: validBody().action,
    approver_id: 'approver@example.test',
    poll_token_hash: tokenHash,
    poll_token_key_id: sealed.keyId,
    poll_token_ciphertext: sealed.ciphertext,
    poll_token_iv: sealed.iv,
    poll_token_tag: sealed.tag,
    status: 'pending',
    refusal_code: null,
    receipt_id: `tr_${'c'.repeat(32)}`,
    signoff_id: `sig_${'d'.repeat(32)}`,
    receipt_action_hash: '4'.repeat(64),
    reconciliation_state: 'not_required',
    indeterminate_at: null,
    reconciled_at: null,
    refused_at: null,
    expires_at: futureExpiry(),
    created_at: '2026-07-21T19:00:00.000Z',
    updated_at: '2026-07-21T19:00:01.000Z',
  };
}

beforeAll(async () => {
  delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = '2026-07-v1';
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = JSON.stringify({
    '2026-07-v1': Buffer.alloc(32, 9).toString('base64'),
  });
  process.env.EP_APPROVAL_PUBLIC_ORIGIN = 'https://www.emiliaprotocol.ai';
  ({ POST } = await import('../app/api/v1/approvals/route.ts'));
  ({ GET } = await import('../app/api/v1/approvals/[requestId]/route.ts'));
});

afterAll(() => {
  if (ORIGINAL_KEY === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
  else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = ORIGINAL_KEY;
  if (ORIGINAL_KEYRING === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
  else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = ORIGINAL_KEYRING;
  if (ORIGINAL_ACTIVE_KEY_ID === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
  else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = ORIGINAL_ACTIVE_KEY_ID;
  if (ORIGINAL_ORIGIN === undefined) delete process.env.EP_APPROVAL_PUBLIC_ORIGIN;
  else process.env.EP_APPROVAL_PUBLIC_ORIGIN = ORIGINAL_ORIGIN;
});

beforeEach(() => {
  vi.clearAllMocks();
  mocks.authenticate.mockResolvedValue({
    tenantId: 'tenant-a', environment: 'production', keyId: 'key-a', permissions: ['approval_request'],
  });
  mocks.rateLimit.mockResolvedValue({ allowed: true, remaining: 10, reset: 60 });
  mocks.complete.mockResolvedValue(true);
  mocks.enterBoundary.mockResolvedValue(true);
  mocks.refuse.mockResolvedValue(true);
  mocks.recoverPollToken.mockImplementation(async (input) => ({
    ...pendingRow(),
    request_id: input.requestId,
    requester_key_id: input.requesterKeyId,
    poll_token_hash: input.pollTokenHash,
    poll_token_key_id: input.sealedToken.keyId,
    poll_token_ciphertext: input.sealedToken.ciphertext,
    poll_token_iv: input.sealedToken.iv,
    poll_token_tag: input.sealedToken.tag,
  }));
});

describe('POST /api/v1/approvals', () => {
  it('durably reserves before invoking the fixed cloud approval and returns separate capabilities', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: '4'.repeat(64),
      action_caid: validBody().action.action_caid,
      expires_at: futureExpiry(),
      signoff_id: `sig_${'d'.repeat(32)}`,
      required_assurance: 'A',
      status: 'pending',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));

    const response = await POST(request());
    const body = await response.json();
    expect(response.status).toBe(201);
    expect(body.request_id).toMatch(/^apr_[a-f0-9]{32}$/);
    expect(body.poll_token).toMatch(/^apt_[a-f0-9]{48}$/);
    expect(body.approval_url).toBe(`https://www.emiliaprotocol.ai/signoff/sig_${'d'.repeat(32)}`);
    expect(body.receipt).toBeUndefined();
    expect(mocks.reserve).toHaveBeenCalledTimes(1);
    expect(mocks.enterBoundary).toHaveBeenCalledTimes(1);
    expect(mocks.enterBoundary.mock.invocationCallOrder[0])
      .toBeLessThan(mocks.cloudPost.mock.invocationCallOrder[0]);
    expect(mocks.cloudPost).toHaveBeenCalledTimes(1);
    expect(mocks.complete).toHaveBeenCalledTimes(1);
    const delegated = await mocks.cloudPost.mock.calls[0][0].json();
    expect(delegated).toMatchObject({
      acquisition_tenant_id: 'tenant-a',
      acquisition_environment: 'production',
    });
  });

  it('returns the same recovered token and URL on an exact durable retry', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = pendingRow(token);
    mocks.reserve.mockResolvedValue({ outcome: 'existing', request: row });
    const response = await POST(request());
    const body = await response.json();
    expect(response.status).toBe(201);
    expect(body).toMatchObject({ request_id: row.request_id, poll_token: token, status: 'pending' });
    expect(mocks.cloudPost).not.toHaveBeenCalled();
  });

  it('keeps idempotency across requester-key rotation while retaining original actor provenance', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = pendingRow(token);
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'production', keyId: 'key-b', permissions: ['approval_request'],
    });
    mocks.reserve.mockImplementation(async (input) => {
      expect(input.requesterKeyId).toBe('key-b');
      return { outcome: 'existing', request: row };
    });

    const response = await POST(request());
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ request_id: row.request_id, poll_token: token });
    expect(row.requester_key_id).toBe('key-a');
    expect(mocks.cloudPost).not.toHaveBeenCalled();
  });

  it('rekeys a permanent indeterminate poll capability after envelope-key retirement', async () => {
    const oldToken = `apt_${'b'.repeat(48)}`;
    const row = {
      ...pendingRow(oldToken),
      status: 'indeterminate',
      reconciliation_state: 'required',
      receipt_id: null,
      signoff_id: null,
      receipt_action_hash: null,
      indeterminate_at: '2026-07-21T19:01:00.000Z',
    };
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = '2026-08-v2';
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = JSON.stringify({
      '2026-08-v2': Buffer.alloc(32, 10).toString('base64'),
    });
    mocks.reserve.mockResolvedValue({ outcome: 'existing', request: row });
    mocks.recoverPollToken.mockImplementation(async (input) => ({
      ...row,
      poll_token_hash: input.pollTokenHash,
      poll_token_key_id: input.sealedToken.keyId,
      poll_token_ciphertext: input.sealedToken.ciphertext,
      poll_token_iv: input.sealedToken.iv,
      poll_token_tag: input.sealedToken.tag,
    }));
    mocks.reconcile.mockImplementation(async (_requestId, _requestDigest) => ({
      outcome: 'indeterminate',
      request: row,
    }));

    const response = await POST(request());
    const body = await response.json();
    expect(response.status).toBe(202);
    expect(body.status).toBe('indeterminate');
    expect(body.poll_token).toMatch(/^apt_[a-f0-9]{48}$/);
    expect(body.poll_token).not.toBe(oldToken);
    expect(mocks.recoverPollToken).toHaveBeenCalledWith(expect.objectContaining({
      requestId: row.request_id,
      tenantId: row.tenant_id,
      environment: row.environment,
      requesterKeyId: row.requester_key_id,
      previousPollTokenKeyId: '2026-07-v1',
    }));
    expect(mocks.cloudPost).not.toHaveBeenCalled();
  });

  it('safely enters the producer on retry when the durable row proves the boundary was never entered', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = {
      ...pendingRow(token),
      status: 'initializing',
      receipt_id: null,
      signoff_id: null,
      receipt_action_hash: null,
    };
    mocks.reserve.mockResolvedValue({ outcome: 'existing', request: row });
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: '4'.repeat(64),
      action_caid: validBody().action.action_caid,
      expires_at: row.expires_at,
      signoff_id: `sig_${'d'.repeat(32)}`,
      required_assurance: 'A',
      status: 'pending',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));

    const response = await POST(request());
    expect(response.status).toBe(201);
    expect(mocks.enterBoundary).toHaveBeenCalledWith(row.request_id, row.request_digest, 'key-a');
    expect(mocks.cloudPost).toHaveBeenCalledTimes(1);
    expect(mocks.complete).toHaveBeenCalledTimes(1);
    expect(mocks.reconcile).not.toHaveBeenCalled();
  });

  it('resumes an initializing request under the rotated key without losing original requester provenance', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = {
      ...pendingRow(token),
      status: 'initializing',
      receipt_id: null,
      signoff_id: null,
      receipt_action_hash: null,
    };
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'production', keyId: 'key-b', permissions: ['approval_request'],
    });
    mocks.reserve.mockResolvedValue({ outcome: 'existing', request: row });
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: '4'.repeat(64),
      action_caid: validBody().action.action_caid,
      expires_at: row.expires_at,
      signoff_id: `sig_${'d'.repeat(32)}`,
      required_assurance: 'A',
      status: 'pending',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));

    const response = await POST(request());
    expect(response.status).toBe(201);
    expect(mocks.enterBoundary).toHaveBeenCalledWith(row.request_id, row.request_digest, 'key-b');
    expect(mocks.complete).toHaveBeenCalledTimes(1);
    expect(row.requester_key_id).toBe('key-a');
  });

  it('returns an explicit pollable indeterminate contract instead of reusing a consumed reservation', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = {
      ...pendingRow(token),
      status: 'invoking',
      receipt_id: null,
      signoff_id: null,
      receipt_action_hash: null,
      reconciliation_state: 'not_required',
    };
    mocks.reserve.mockResolvedValue({ outcome: 'existing', request: row });
    mocks.reconcile.mockResolvedValue({
      outcome: 'indeterminate',
      request: {
        ...row,
        status: 'indeterminate',
        reconciliation_state: 'required',
      },
    });

    const response = await POST(request());
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      request_id: row.request_id,
      poll_token: token,
      status: 'indeterminate',
      expires_at: row.expires_at,
      reconciliation: { state: 'required', retry_safe: false },
    });
    expect(mocks.cloudPost).not.toHaveBeenCalled();
    expect(mocks.enterBoundary).not.toHaveBeenCalled();
    expect(mocks.complete).not.toHaveBeenCalled();
  });

  it('rejects same-key body drift before creating another receipt', async () => {
    mocks.reserve.mockResolvedValue({ outcome: 'conflict' });
    const response = await POST(request());
    expect(response.status).toBe(409);
    expect(mocks.cloudPost).not.toHaveBeenCalled();
  });

  it('records a verified pre-boundary refusal and permits a corrected logical retry', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      code: 'invalid_payment_reference',
      detail: 'producer rejected before entry',
    }), {
      status: 400,
      headers: {
        'content-type': 'application/json',
        'x-emilia-approval-boundary': 'not-entered',
      },
    }));

    const response = await POST(request());
    expect(response.status).toBe(400);
    expect((await response.json()).code).toBe('invalid_payment_reference');
    expect(mocks.refuse).toHaveBeenCalledWith(expect.objectContaining({
      refusalCode: 'invalid_payment_reference',
    }));
    expect(mocks.reconcile).not.toHaveBeenCalled();
  });

  it('never trusts an unmarked refusal after boundary entry', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({ code: 'unknown_failure' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));
    mocks.reconcile.mockImplementation(async (requestId, requestDigest) => ({
      outcome: 'indeterminate',
      request: {
        ...pendingRow(), request_id: requestId, request_digest: requestDigest,
        status: 'indeterminate', receipt_id: null, signoff_id: null,
        receipt_action_hash: null, reconciliation_state: 'required',
      },
    }));

    const response = await POST(request());
    expect(response.status).toBe(202);
    expect(mocks.refuse).not.toHaveBeenCalled();
    expect(mocks.reconcile).toHaveBeenCalledTimes(1);
  });

  it('freezes an invalid post-invocation response as indeterminate instead of reporting ordinary failure', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: '4'.repeat(64),
      action_caid: validBody().action.action_caid,
      expires_at: new Date(Date.now() - 1).toISOString(),
      signoff_id: `sig_${'d'.repeat(32)}`,
      required_assurance: 'A',
      status: 'pending',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));
    mocks.reconcile.mockImplementation(async (requestId, requestDigest) => ({
      outcome: 'indeterminate',
      request: {
        ...pendingRow(),
        request_id: requestId,
        request_digest: requestDigest,
        status: 'indeterminate',
        receipt_id: null,
        signoff_id: null,
        receipt_action_hash: null,
        reconciliation_state: 'required',
      },
    }));

    const response = await POST(request());
    expect(response.status).toBe(202);
    expect((await response.json()).status).toBe('indeterminate');
    expect(mocks.complete).not.toHaveBeenCalled();
  });

  it('treats an upstream response loss as indeterminate and never retries the entered boundary', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockRejectedValue(new Error('provider_response_lost'));
    mocks.reconcile.mockImplementation(async (requestId, requestDigest) => ({
      outcome: 'indeterminate',
      request: {
        ...pendingRow(),
        request_id: requestId,
        request_digest: requestDigest,
        status: 'indeterminate',
        receipt_id: null,
        signoff_id: null,
        receipt_action_hash: null,
        reconciliation_state: 'required',
      },
    }));

    const first = await POST(request());
    expect(first.status).toBe(202);
    expect(await first.json()).toMatchObject({
      status: 'indeterminate',
      reconciliation: { state: 'required', retry_safe: false },
    });
    expect(mocks.cloudPost).toHaveBeenCalledTimes(1);
    expect(mocks.complete).not.toHaveBeenCalled();
  });
});

describe('GET /api/v1/approvals/{requestId}', () => {
  it('uses only the separate poll capability and never returns a receipt while pending', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = pendingRow(token);
    mocks.find.mockResolvedValue(row);
    mocks.loadStatus.mockResolvedValue({ status: 'pending' });
    const response = await GET(new Request(`https://www.emiliaprotocol.ai/api/v1/approvals/${row.request_id}`, {
      headers: { authorization: `EP-Approval ${token}` },
    }), { params: Promise.resolve({ requestId: row.request_id }) });
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body).toEqual({ request_id: row.request_id, status: 'pending' });
    expect(response.headers.get('cache-control')).toContain('no-store');
  });

  it('makes malformed, wrong-token, and cross-tenant probes indistinguishable', async () => {
    mocks.find.mockResolvedValue(null);
    const malformed = await GET(new Request('https://www.emiliaprotocol.ai/api/v1/approvals/not-an-id'), {
      params: Promise.resolve({ requestId: 'not-an-id' }),
    });
    const wrong = await GET(new Request(`https://www.emiliaprotocol.ai/api/v1/approvals/apr_${'a'.repeat(32)}`, {
      headers: { authorization: `EP-Approval apt_${'f'.repeat(48)}` },
    }), { params: Promise.resolve({ requestId: `apr_${'a'.repeat(32)}` }) });
    expect(malformed.status).toBe(404);
    expect(wrong.status).toBe(404);
    expect(await malformed.json()).toEqual(await wrong.json());
  });

  it('returns terminal expiry without a receipt and refuses unsigned/operator-only approval', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = pendingRow(token);
    mocks.find.mockResolvedValue(row);
    mocks.loadStatus.mockResolvedValueOnce({ status: 'expired' });
    const expired = await GET(new Request(`https://www.emiliaprotocol.ai/api/v1/approvals/${row.request_id}`, {
      headers: { authorization: `EP-Approval ${token}` },
    }), { params: Promise.resolve({ requestId: row.request_id }) });
    expect(await expired.json()).toEqual({ request_id: row.request_id, status: 'expired' });

    mocks.loadStatus.mockResolvedValueOnce({ status: 'not_ready', reason: 'signed_receipt_unavailable' });
    const unsigned = await GET(new Request(`https://www.emiliaprotocol.ai/api/v1/approvals/${row.request_id}`, {
      headers: { authorization: `EP-Approval ${token}` },
    }), { params: Promise.resolve({ requestId: row.request_id }) });
    expect(unsigned.status).toBe(503);
    expect((await unsigned.json()).code).toBe('approval_receipt_not_ready');
  });

  it('reconciles only after a valid poll capability and exposes unresolved indeterminacy without a receipt', async () => {
    const token = `apt_${'b'.repeat(48)}`;
    const row = {
      ...pendingRow(token),
      status: 'indeterminate',
      receipt_id: null,
      signoff_id: null,
      receipt_action_hash: null,
      reconciliation_state: 'required',
    };
    mocks.find.mockResolvedValue(row);
    mocks.reconcile.mockResolvedValue({ outcome: 'indeterminate', request: row });
    const response = await GET(new Request(`https://www.emiliaprotocol.ai/api/v1/approvals/${row.request_id}`, {
      headers: { authorization: `EP-Approval ${token}` },
    }), { params: Promise.resolve({ requestId: row.request_id }) });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      request_id: row.request_id,
      status: 'indeterminate',
      reconciliation: { state: 'required', retry_safe: false },
    });
    expect(mocks.reconcile).toHaveBeenCalledWith(row.request_id, row.request_digest);
    expect(mocks.loadStatus).not.toHaveBeenCalled();
  });
});
