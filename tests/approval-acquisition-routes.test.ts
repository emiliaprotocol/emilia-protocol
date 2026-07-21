// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import {
  APPROVAL_REQUIRED_FIELDS,
  buildPaymentReleaseActionIdentity,
} from '../lib/approval-acquisition/contract.ts';
import {
  encryptPollToken,
  hashPollToken,
} from '../lib/approval-acquisition/token.ts';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  requirePermission: vi.fn(),
  reserve: vi.fn(),
  complete: vi.fn(),
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
  completeApprovalRequest: mocks.complete,
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
  return {
    request_id: requestId,
    tenant_id: 'tenant-a',
    environment: 'production',
    requester_key_id: 'key-a',
    idempotency_digest: `sha256:${'1'.repeat(64)}`,
    request_digest: `sha256:${'2'.repeat(64)}`,
    challenge_hash: `sha256:${'3'.repeat(64)}`,
    action_hash: validBody().challenge.action_hash,
    action_caid: validBody().action.action_caid,
    action: validBody().action,
    approver_id: 'approver@example.test',
    poll_token_hash: tokenHash,
    poll_token_ciphertext: sealed.ciphertext,
    poll_token_iv: sealed.iv,
    poll_token_tag: sealed.tag,
    status: 'pending',
    receipt_id: `tr_${'c'.repeat(32)}`,
    signoff_id: `sig_${'d'.repeat(32)}`,
    receipt_action_hash: `sha256:${'4'.repeat(64)}`,
    expires_at: futureExpiry(),
    created_at: '2026-07-21T19:00:00.000Z',
    updated_at: '2026-07-21T19:00:01.000Z',
  };
}

beforeAll(async () => {
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 9).toString('base64');
  process.env.EP_APPROVAL_PUBLIC_ORIGIN = 'https://www.emiliaprotocol.ai';
  ({ POST } = await import('../app/api/v1/approvals/route.ts'));
  ({ GET } = await import('../app/api/v1/approvals/[requestId]/route.ts'));
});

afterAll(() => {
  if (ORIGINAL_KEY === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
  else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = ORIGINAL_KEY;
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
});

describe('POST /api/v1/approvals', () => {
  it('durably reserves before invoking the fixed cloud approval and returns separate capabilities', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: `sha256:${'4'.repeat(64)}`,
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
    expect(mocks.cloudPost).toHaveBeenCalledTimes(1);
    expect(mocks.complete).toHaveBeenCalledTimes(1);
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

  it('recovers an interrupted initialization through the idempotent receipt and signoff binding', async () => {
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
      action_hash: `sha256:${'4'.repeat(64)}`,
      action_caid: validBody().action.action_caid,
      expires_at: row.expires_at,
      signoff_id: `sig_${'d'.repeat(32)}`,
      required_assurance: 'A',
      status: 'pending',
    }), { status: 200, headers: { 'content-type': 'application/json' } }));

    const response = await POST(request());
    expect(response.status).toBe(201);
    expect(mocks.cloudPost).toHaveBeenCalledTimes(1);
    const delegated = await mocks.cloudPost.mock.calls[0][0].json();
    expect(delegated).toMatchObject({
      acquisition_request_id: row.request_id,
      acquisition_action_hash: row.action_hash,
      acquisition_action_caid: row.action_caid,
    });
    expect(delegated.acquisition_challenge_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(mocks.complete).toHaveBeenCalledTimes(1);
  });

  it('rejects same-key body drift before creating another receipt', async () => {
    mocks.reserve.mockResolvedValue({ outcome: 'conflict' });
    const response = await POST(request());
    expect(response.status).toBe(409);
    expect(mocks.cloudPost).not.toHaveBeenCalled();
  });

  it('refuses an already-expired downstream ceremony instead of returning a dead poll capability', async () => {
    mocks.reserve.mockImplementation(async (input) => ({
      outcome: 'created',
      request: { request_id: input.requestId, status: 'initializing' },
    }));
    mocks.cloudPost.mockResolvedValue(new Response(JSON.stringify({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: `sha256:${'4'.repeat(64)}`,
      action_caid: validBody().action.action_caid,
      expires_at: new Date(Date.now() - 1).toISOString(),
      signoff_id: `sig_${'d'.repeat(32)}`,
      required_assurance: 'A',
      status: 'pending',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));

    const response = await POST(request());
    expect(response.status).toBe(503);
    expect((await response.json()).code).toBe('approval_ceremony_unavailable');
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
});
