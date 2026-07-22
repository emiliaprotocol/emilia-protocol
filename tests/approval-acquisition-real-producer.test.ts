// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import {
  APPROVAL_REQUIRED_FIELDS,
  buildPaymentReleaseActionIdentity,
} from '../lib/approval-acquisition/contract.ts';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  reserve: vi.fn(),
  enter: vi.fn(),
  complete: vi.fn(),
  reconcile: vi.fn(),
  refuse: vi.fn(),
  recoverPollToken: vi.fn(),
  createReceipt: vi.fn(),
  requestSignoff: vi.fn(),
  rateLimit: vi.fn(),
}));

vi.mock('@/lib/cloud/auth', () => ({ authenticateCloudRequest: mocks.authenticate }));
vi.mock('@/lib/approval-acquisition/store.js', () => ({
  reserveApprovalRequest: mocks.reserve,
  enterApprovalRequestBoundary: mocks.enter,
  completeApprovalRequest: mocks.complete,
  reconcileApprovalRequest: mocks.reconcile,
  refuseApprovalRequest: mocks.refuse,
  recoverApprovalPollToken: mocks.recoverPollToken,
  ApprovalStorageError: class ApprovalStorageError extends Error {},
}));
vi.mock('@/app/api/v1/trust-receipts/route.js', () => ({ POST: mocks.createReceipt }));
vi.mock('@/app/api/v1/signoffs/request/route.js', () => ({ POST: mocks.requestSignoff }));
vi.mock('@/lib/cloud/approval-queue.js', () => ({ loadTenantApprovalQueue: vi.fn() }));
vi.mock('@/lib/write-guard', () => ({ getGuardedClient: () => ({ from: vi.fn() }) }));
vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: mocks.rateLimit,
  getClientIP: () => '203.0.113.2',
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const ORIGINAL_KEYRING = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
const ORIGINAL_ACTIVE_KEY_ID = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
const ORIGINAL_ORIGIN = process.env.EP_APPROVAL_PUBLIC_ORIGIN;
const TENANT_ID = '33333333-3333-4333-8333-333333333333';
const GUARD_ACTION_HASH = 'b'.repeat(64);
let POST: (request: any) => Promise<Response>;
let trustReceiptInput: any;

function body() {
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

beforeAll(async () => {
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = '2026-07-v1';
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = JSON.stringify({
    '2026-07-v1': Buffer.alloc(32, 11).toString('base64'),
  });
  process.env.EP_APPROVAL_PUBLIC_ORIGIN = 'https://www.emiliaprotocol.ai';
  ({ POST } = await import('../app/api/v1/approvals/route.ts'));
});

afterAll(() => {
  if (ORIGINAL_KEYRING === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
  else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = ORIGINAL_KEYRING;
  if (ORIGINAL_ACTIVE_KEY_ID === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
  else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = ORIGINAL_ACTIVE_KEY_ID;
  if (ORIGINAL_ORIGIN === undefined) delete process.env.EP_APPROVAL_PUBLIC_ORIGIN;
  else process.env.EP_APPROVAL_PUBLIC_ORIGIN = ORIGINAL_ORIGIN;
});

beforeEach(() => {
  vi.clearAllMocks();
  trustReceiptInput = null;
  mocks.authenticate.mockResolvedValue({
    tenantId: TENANT_ID,
    environment: 'production',
    keyId: 'key-a',
    permissions: ['approval_request'],
  });
  mocks.rateLimit.mockResolvedValue({ allowed: true, remaining: 10, reset: 60 });
  mocks.reserve.mockImplementation(async (input) => ({
    outcome: 'created',
    request: { request_id: input.requestId, status: 'initializing' },
  }));
  mocks.enter.mockResolvedValue(true);
  mocks.complete.mockResolvedValue(true);
  mocks.createReceipt.mockImplementation(async (request) => {
    const delegated = await request.json();
    trustReceiptInput = delegated;
    return Response.json({
      receipt_id: `tr_${'c'.repeat(32)}`,
      action_hash: GUARD_ACTION_HASH,
      canonical_action: { action_caid: delegated.acquisition_action_caid },
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      signoff_required: true,
      required_assurance: 'A',
    }, { status: 201 });
  });
  mocks.requestSignoff.mockResolvedValue(Response.json({
    signoff_id: `sig_${'d'.repeat(32)}`,
    approver_id: 'approver@example.test',
    status: 'pending',
  }, { status: 201 }));
});

describe('EP-APPROVAL-v1 real Guard approval producer integration', () => {
  it('accepts the producer bare action hash and persists that exact signed-action binding', async () => {
    const response = await POST(new Request('https://www.emiliaprotocol.ai/api/v1/approvals', {
      method: 'POST',
      headers: { authorization: 'Bearer ept_test_secret', 'content-type': 'application/json' },
      body: JSON.stringify(body()),
    }));

    expect(response.status).toBe(201);
    expect(mocks.complete).toHaveBeenCalledWith(expect.objectContaining({
      receiptActionHash: GUARD_ACTION_HASH,
    }));
    expect(trustReceiptInput).toMatchObject({
      acquisition_tenant_id: TENANT_ID,
      acquisition_environment: 'production',
    });
  });
});
