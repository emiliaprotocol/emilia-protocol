// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockAuthenticateCloudRequest,
  mockLoadTenantApprovalQueue,
  mockCreateReceipt,
  mockRequestSignoff,
  mockConsumeReceipt,
  mockReadEvidence,
} = vi.hoisted(() => ({
  mockAuthenticateCloudRequest: vi.fn(),
  mockLoadTenantApprovalQueue: vi.fn(),
  mockCreateReceipt: vi.fn(),
  mockRequestSignoff: vi.fn(),
  mockConsumeReceipt: vi.fn(),
  mockReadEvidence: vi.fn(),
}));

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...args) => mockAuthenticateCloudRequest(...args),
}));
vi.mock('@/lib/cloud/approval-queue.js', () => ({
  loadTenantApprovalQueue: (...args) => mockLoadTenantApprovalQueue(...args),
}));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({ from: vi.fn() }),
}));
vi.mock('@/app/api/v1/trust-receipts/route.js', () => ({
  POST: (...args) => mockCreateReceipt(...args),
}));
vi.mock('@/app/api/v1/signoffs/request/route.js', () => ({
  POST: (...args) => mockRequestSignoff(...args),
}));
vi.mock('@/app/api/v1/trust-receipts/[receiptId]/consume/route.js', () => ({
  POST: (...args) => mockConsumeReceipt(...args),
}));
vi.mock('@/app/api/v1/trust-receipts/[receiptId]/evidence/route.js', () => ({
  GET: (...args) => mockReadEvidence(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { GET, POST } from '../app/api/cloud/approvals/route.js';
import { POST as consume } from '../app/api/cloud/approvals/[receiptId]/consume/route.js';
import { GET as evidence } from '../app/api/cloud/approvals/[receiptId]/evidence/route.js';

const TENANT_ID = '33333333-3333-4333-8333-333333333333';
const RECEIPT_ID = `tr_${'a'.repeat(32)}`;
const ACTION_HASH = 'b'.repeat(64);
const DESTINATION_HASH = `sha256:${'d'.repeat(64)}`;
const ACTION_CAID = 'caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function request(method = 'GET', body, token = 'ept_live_approval') {
  return new Request('https://www.emiliaprotocol.ai/api/cloud/approvals', {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function approvalBody(overrides = {}) {
  return {
    payment_reference: 'payment:invoice-1842',
    amount: 82000,
    currency: 'USD',
    counterparty_name: 'Acme Medical Supply',
    approver_id: 'approver:cfo@example.com',
    payment_destination_hash: DESTINATION_HASH,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticateCloudRequest.mockResolvedValue({
    tenantId: TENANT_ID,
    environment: 'production',
    permissions: ['approval_request'],
    keyId: 'key-approval',
  });
  mockLoadTenantApprovalQueue.mockResolvedValue({ approvals: [], error: null });
  mockCreateReceipt.mockResolvedValue(Response.json({
    receipt_id: RECEIPT_ID,
    action_hash: ACTION_HASH,
    expires_at: '2026-07-20T00:00:00.000Z',
    signoff_required: true,
    required_assurance: 'A',
    canonical_action: { action_caid: ACTION_CAID },
  }, { status: 201 }));
  mockRequestSignoff.mockResolvedValue(Response.json({
    signoff_id: `sig_${'c'.repeat(32)}`,
    receipt_id: RECEIPT_ID,
    action_hash: ACTION_HASH,
    status: 'pending',
  }, { status: 201 }));
  mockConsumeReceipt.mockResolvedValue(Response.json({ status: 'consumed' }));
  mockReadEvidence.mockResolvedValue(Response.json({ receipt_id: RECEIPT_ID, signed: true }));
});

describe('Cloud approval endpoint', () => {
  it('fails closed when the Cloud key is absent', async () => {
    mockAuthenticateCloudRequest.mockResolvedValue(null);
    expect((await GET(request('GET', undefined, null))).status).toBe(401);
    expect((await POST(request('POST', approvalBody(), null))).status).toBe(401);
  });

  it('lists only the authenticated tenant queue', async () => {
    mockLoadTenantApprovalQueue.mockResolvedValue({
      approvals: [{ receipt_id: RECEIPT_ID, status: 'pending' }],
      error: null,
    });

    const response = await GET(request());

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store, private');
    expect(mockLoadTenantApprovalQueue).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: TENANT_ID,
    }));
    expect(await response.json()).toMatchObject({
      tenant_id: TENANT_ID,
      summary: { pending: 1, approved: 0, rejected: 0, expired: 0, consumed: 0 },
    });
  });

  it('turns one bounded payment request into a Class-A review URL', async () => {
    const response = await POST(request('POST', approvalBody()));

    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toBe('no-store, private');
    const createRequest = mockCreateReceipt.mock.calls[0][0];
    const createBody = await createRequest.json();
    expect(createBody).toMatchObject({
      organization_id: TENANT_ID,
      action_type: 'large_payment_release',
      target_resource_id: 'payment:invoice-1842',
      amount: 82000,
      currency: 'USD',
      counterparty_name: 'Acme Medical Supply',
      payment_destination_hash: DESTINATION_HASH,
      enforcement_mode: 'enforce',
    });
    expect(createBody).not.toHaveProperty('actor_id');

    const signoffRequest = mockRequestSignoff.mock.calls[0][0];
    expect(await signoffRequest.json()).toMatchObject({
      receipt_id: RECEIPT_ID,
      approver_id: 'approver:cfo@example.com',
    });
    expect(await response.json()).toMatchObject({
      receipt_id: RECEIPT_ID,
      action_hash: ACTION_HASH,
      action_caid: ACTION_CAID,
      required_assurance: 'A',
      status: 'pending',
      review_path: `/signoff/sig_${'c'.repeat(32)}`,
    });
  });

  it.each([
    ['non-positive amount', { amount: 0 }],
    ['non-finite amount', { amount: '82000' }],
    ['lowercase currency', { currency: 'usd' }],
    ['empty counterparty', { counterparty_name: '' }],
    ['invalid approver', { approver_id: 'x' }],
    ['unsafe reference', { payment_reference: '../other-tenant' }],
    ['invalid destination digest', { payment_destination_hash: 'sha256:bad' }],
  ])('rejects %s before minting a receipt', async (_label, overrides) => {
    const response = await POST(request('POST', approvalBody(overrides)));
    expect(response.status).toBe(400);
    expect(response.headers.get('x-emilia-approval-boundary')).toBe('not-entered');
    expect(mockCreateReceipt).not.toHaveBeenCalled();
  });

  it('does not continue to signoff when receipt minting fails', async () => {
    mockCreateReceipt.mockResolvedValue(Response.json(
      { type: 'authority_not_authorized', detail: 'No active authority.' },
      { status: 403 },
    ));

    const response = await POST(request('POST', approvalBody()));

    expect(response.status).toBe(403);
    expect(mockRequestSignoff).not.toHaveBeenCalled();
  });

  it('delegates one-time consume with a fixed executing-system identity', async () => {
    const response = await consume(
      request('POST', { action_hash: ACTION_HASH }),
      { params: Promise.resolve({ receiptId: RECEIPT_ID }) },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store, private');
    const delegatedRequest = mockConsumeReceipt.mock.calls[0][0];
    expect(await delegatedRequest.json()).toEqual({
      action_hash: ACTION_HASH,
      executing_system: 'emilia_cloud_approval_endpoint',
    });
  });

  it('delegates evidence export without accepting a tenant override', async () => {
    const response = await evidence(
      request(),
      { params: Promise.resolve({ receiptId: RECEIPT_ID }) },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store, private');
    expect(mockReadEvidence).toHaveBeenCalledOnce();
  });
});
