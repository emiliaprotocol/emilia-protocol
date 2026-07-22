// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const serviceClient = vi.hoisted(() => ({
  get: vi.fn(),
}));

vi.mock('@/lib/supabase.js', () => ({
  getServiceClient: serviceClient.get,
}));

import {
  ApprovalStorageError,
  completeApprovalRequest,
  enterApprovalRequestBoundary,
  findApprovalRequest,
  reconcileApprovalRequest,
  recoverApprovalPollToken,
  refuseApprovalRequest,
  reserveApprovalRequest,
  type ApprovalAcquisitionRow,
  type ReserveApprovalInput,
} from '../lib/approval-acquisition/store.ts';

const request = {
  request_id: 'apr_11111111111111111111111111111111',
  request_digest: `sha256:${'1'.repeat(64)}`,
  poll_token_hash: `sha256:${'2'.repeat(64)}`,
  status: 'pending',
} as ApprovalAcquisitionRow;

const reserveInput: ReserveApprovalInput = {
  requestId: request.request_id,
  tenantId: 'tenant-a',
  environment: 'production',
  requesterKeyId: 'requester-key',
  idempotencyDigest: `sha256:${'3'.repeat(64)}`,
  requestDigest: request.request_digest,
  challengeHash: `sha256:${'4'.repeat(64)}`,
  actionHash: `sha256:${'5'.repeat(64)}`,
  actionCaid: 'caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  action: { action_type: 'payment.release' },
  approverId: 'approver-a',
  pollTokenHash: request.poll_token_hash,
  sealedToken: { keyId: 'key-v1', ciphertext: 'ciphertext', iv: 'iv', tag: 'tag' },
  expiresAt: '2026-07-22T04:00:00.000Z',
};

function rpcClient(result: unknown) {
  return {
    rpc: vi.fn().mockResolvedValue(result),
    from: vi.fn(),
  };
}

function queryClient(result: unknown) {
  const maybeSingle = vi.fn().mockResolvedValue(result);
  const secondEq = vi.fn(() => ({ maybeSingle }));
  const firstEq = vi.fn(() => ({ eq: secondEq }));
  const select = vi.fn(() => ({ eq: firstEq }));
  const from = vi.fn(() => ({ select }));
  return { client: { rpc: vi.fn(), from }, from, select, firstEq, secondEq, maybeSingle };
}

beforeEach(() => {
  serviceClient.get.mockReset();
});

describe('approval acquisition durable store adapter', () => {
  it('maps every mutating operation to its exact RPC contract', async () => {
    const client = rpcClient({ data: true, error: null });
    serviceClient.get.mockReturnValue(client);

    await expect(enterApprovalRequestBoundary('apr', 'digest', 'producer')).resolves.toBe(true);
    expect(client.rpc).toHaveBeenLastCalledWith('enter_approval_acquisition_boundary', {
      p_request_id: 'apr', p_request_digest: 'digest', p_producer_key_id: 'producer',
    });

    await expect(completeApprovalRequest({
      requestId: 'apr', requestDigest: 'digest', receiptId: 'receipt', signoffId: 'signoff',
      receiptActionHash: 'action', expiresAt: 'expiry',
    })).resolves.toBe(true);
    expect(client.rpc).toHaveBeenLastCalledWith('complete_approval_acquisition_request', {
      p_request_id: 'apr', p_request_digest: 'digest', p_receipt_id: 'receipt',
      p_signoff_id: 'signoff', p_receipt_action_hash: 'action', p_expires_at: 'expiry',
    });

    await expect(refuseApprovalRequest({
      requestId: 'apr', requestDigest: 'digest', refusalCode: 'refused',
    })).resolves.toBe(true);
    expect(client.rpc).toHaveBeenLastCalledWith('refuse_approval_acquisition_request', {
      p_request_id: 'apr', p_request_digest: 'digest', p_refusal_code: 'refused',
    });

    await expect(recoverApprovalPollToken({
      requestId: 'apr', requestDigest: 'digest', tenantId: 'tenant-a', environment: 'production',
      requesterKeyId: 'requester', idempotencyDigest: 'idempotency',
      previousPollTokenHash: 'old-hash', previousPollTokenKeyId: 'old-key',
      pollTokenHash: 'new-hash',
      sealedToken: { keyId: 'new-key', ciphertext: 'ciphertext', iv: 'iv', tag: 'tag' },
    })).resolves.toBe(true);
    expect(client.rpc).toHaveBeenLastCalledWith('recover_approval_acquisition_poll_token', {
      p_request_id: 'apr', p_request_digest: 'digest', p_tenant_id: 'tenant-a',
      p_environment: 'production', p_requester_key_id: 'requester',
      p_idempotency_digest: 'idempotency', p_previous_poll_token_hash: 'old-hash',
      p_previous_poll_token_key_id: 'old-key', p_poll_token_hash: 'new-hash',
      p_poll_token_key_id: 'new-key', p_poll_token_ciphertext: 'ciphertext',
      p_poll_token_iv: 'iv', p_poll_token_tag: 'tag',
    });
  });

  it('returns false for closed RPC refusals and throws on storage errors', async () => {
    const client = rpcClient({ data: false, error: null });
    serviceClient.get.mockReturnValue(client);
    await expect(enterApprovalRequestBoundary('apr', 'digest', 'producer')).resolves.toBe(false);
    await expect(completeApprovalRequest({
      requestId: 'apr', requestDigest: 'digest', receiptId: 'receipt', signoffId: 'signoff',
      receiptActionHash: 'action', expiresAt: 'expiry',
    })).resolves.toBe(false);
    await expect(refuseApprovalRequest({
      requestId: 'apr', requestDigest: 'digest', refusalCode: 'refused',
    })).resolves.toBe(false);
    await expect(recoverApprovalPollToken({
      requestId: 'apr', requestDigest: 'digest', tenantId: 'tenant', environment: 'prod',
      requesterKeyId: 'key', idempotencyDigest: 'idem', previousPollTokenHash: 'old',
      previousPollTokenKeyId: 'old-key', pollTokenHash: 'new',
      sealedToken: { keyId: 'new-key', ciphertext: 'cipher', iv: 'iv', tag: 'tag' },
    })).resolves.toBe(false);

    client.rpc.mockResolvedValue({ data: null, error: { message: 'db down' } });
    await expect(enterApprovalRequestBoundary('apr', 'digest', 'producer'))
      .rejects.toMatchObject({ name: 'ApprovalStorageError', code: 'approval_storage_unavailable' });
    await expect(completeApprovalRequest({
      requestId: 'apr', requestDigest: 'digest', receiptId: 'receipt', signoffId: 'signoff',
      receiptActionHash: 'action', expiresAt: 'expiry',
    })).rejects.toBeInstanceOf(ApprovalStorageError);
    await expect(refuseApprovalRequest({
      requestId: 'apr', requestDigest: 'digest', refusalCode: 'refused',
    })).rejects.toBeInstanceOf(ApprovalStorageError);
    await expect(recoverApprovalPollToken({
      requestId: 'apr', requestDigest: 'digest', tenantId: 'tenant', environment: 'prod',
      requesterKeyId: 'key', idempotencyDigest: 'idem', previousPollTokenHash: 'old',
      previousPollTokenKeyId: 'old-key', pollTokenHash: 'new',
      sealedToken: { keyId: 'new-key', ciphertext: 'cipher', iv: 'iv', tag: 'tag' },
    })).rejects.toBeInstanceOf(ApprovalStorageError);
  });

  it('reserves created and existing requests, while preserving conflicts', async () => {
    const client = rpcClient({ data: { outcome: 'created', request }, error: null });
    serviceClient.get.mockReturnValue(client);
    await expect(reserveApprovalRequest(reserveInput)).resolves.toEqual({ outcome: 'created', request });
    expect(client.rpc).toHaveBeenCalledWith('reserve_approval_acquisition_request', {
      p_request_id: reserveInput.requestId,
      p_tenant_id: reserveInput.tenantId,
      p_environment: reserveInput.environment,
      p_requester_key_id: reserveInput.requesterKeyId,
      p_idempotency_digest: reserveInput.idempotencyDigest,
      p_request_digest: reserveInput.requestDigest,
      p_challenge_hash: reserveInput.challengeHash,
      p_action_hash: reserveInput.actionHash,
      p_action_caid: reserveInput.actionCaid,
      p_action: reserveInput.action,
      p_approver_id: reserveInput.approverId,
      p_poll_token_hash: reserveInput.pollTokenHash,
      p_poll_token_key_id: reserveInput.sealedToken.keyId,
      p_poll_token_ciphertext: reserveInput.sealedToken.ciphertext,
      p_poll_token_iv: reserveInput.sealedToken.iv,
      p_poll_token_tag: reserveInput.sealedToken.tag,
      p_expires_at: reserveInput.expiresAt,
    });

    client.rpc.mockResolvedValue({ data: { outcome: 'existing', request }, error: null });
    await expect(reserveApprovalRequest(reserveInput)).resolves.toEqual({ outcome: 'existing', request });
    client.rpc.mockResolvedValue({ data: { outcome: 'conflict' }, error: null });
    await expect(reserveApprovalRequest(reserveInput)).resolves.toEqual({ outcome: 'conflict' });
  });

  it.each([
    { data: null, error: null },
    { data: { outcome: 'unknown', request }, error: null },
    { data: { outcome: 'created', request: null }, error: null },
    { data: { outcome: 'created', request: [] }, error: null },
    { data: { outcome: 'created', request: { ...request, request_id: 1 } }, error: null },
    { data: { outcome: 'created', request: { ...request, request_digest: 1 } }, error: null },
    { data: { outcome: 'created', request: { ...request, poll_token_hash: 1 } }, error: null },
    { data: { outcome: 'created', request: { ...request, status: 1 } }, error: null },
    { data: { outcome: 'created', request }, error: { message: 'db' } },
  ])('fails closed on malformed reserve output %#', async (result) => {
    serviceClient.get.mockReturnValue(rpcClient(result));
    await expect(reserveApprovalRequest(reserveInput)).rejects.toBeInstanceOf(ApprovalStorageError);
  });

  it.each(['indeterminate', 'pending', 'reconciled'] as const)(
    'accepts the closed %s reconciliation outcome',
    async (outcome) => {
      serviceClient.get.mockReturnValue(rpcClient({ data: { outcome, request }, error: null }));
      await expect(reconcileApprovalRequest('apr', 'digest')).resolves.toEqual({ outcome, request });
    },
  );

  it.each([
    { data: null, error: null },
    { data: { outcome: 'unknown', request }, error: null },
    { data: { outcome: 'pending', request: null }, error: null },
    { data: { outcome: 'pending', request }, error: { message: 'db' } },
  ])('fails closed on malformed reconciliation output %#', async (result) => {
    serviceClient.get.mockReturnValue(rpcClient(result));
    await expect(reconcileApprovalRequest('apr', 'digest')).rejects.toBeInstanceOf(ApprovalStorageError);
  });

  it('finds only usable rows through the closed polling projection', async () => {
    const query = queryClient({ data: request, error: null });
    serviceClient.get.mockReturnValue(query.client);
    await expect(findApprovalRequest('apr', 'poll-hash')).resolves.toBe(request);
    expect(query.from).toHaveBeenCalledWith('approval_acquisition_requests');
    expect(query.firstEq).toHaveBeenCalledWith('request_id', 'apr');
    expect(query.secondEq).toHaveBeenCalledWith('poll_token_hash', 'poll-hash');

    query.maybeSingle.mockResolvedValue({ data: null, error: null });
    await expect(findApprovalRequest('apr', 'poll-hash')).resolves.toBeNull();
    query.maybeSingle.mockResolvedValue({ data: {}, error: null });
    await expect(findApprovalRequest('apr', 'poll-hash')).rejects.toBeInstanceOf(ApprovalStorageError);
    query.maybeSingle.mockResolvedValue({ data: request, error: { message: 'db' } });
    await expect(findApprovalRequest('apr', 'poll-hash')).rejects.toBeInstanceOf(ApprovalStorageError);
  });

  it.each([
    null,
    {},
    { rpc: vi.fn() },
    { from: vi.fn() },
  ])('rejects an unusable service client %#', async (invalidClient) => {
    serviceClient.get.mockReturnValue(invalidClient);
    await expect(enterApprovalRequestBoundary('apr', 'digest', 'producer'))
      .rejects.toBeInstanceOf(ApprovalStorageError);
  });

  it('normalizes thrown client construction failures and supports explicit error codes', async () => {
    serviceClient.get.mockImplementation(() => { throw new Error('secret detail'); });
    await expect(enterApprovalRequestBoundary('apr', 'digest', 'producer'))
      .rejects.toMatchObject({ message: 'approval_storage_unavailable' });
    expect(new ApprovalStorageError('custom_storage_code')).toMatchObject({
      name: 'ApprovalStorageError', code: 'custom_storage_code', message: 'custom_storage_code',
    });
  });
});
