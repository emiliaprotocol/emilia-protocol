// SPDX-License-Identifier: Apache-2.0

import { getServiceClient } from '@/lib/supabase.js';
import type { SealedPollToken } from './token.js';

export type ApprovalAcquisitionRow = {
  request_id: string;
  tenant_id: string;
  environment: string;
  requester_key_id: string;
  producer_key_id: string | null;
  idempotency_digest: string;
  request_digest: string;
  challenge_hash: string;
  action_hash: string;
  action_caid: string;
  action: Record<string, any>;
  approver_id: string;
  poll_token_hash: string;
  poll_token_key_id: string;
  poll_token_ciphertext: string;
  poll_token_iv: string;
  poll_token_tag: string;
  status: 'initializing' | 'invoking' | 'indeterminate' | 'pending' | 'refused';
  reconciliation_state: 'not_required' | 'required' | 'reconciled';
  refusal_code: string | null;
  receipt_id: string | null;
  signoff_id: string | null;
  receipt_action_hash: string | null;
  indeterminate_at: string | null;
  reconciled_at: string | null;
  refused_at: string | null;
  expires_at: string;
  created_at: string;
  updated_at: string;
};

export type ReserveApprovalInput = {
  requestId: string;
  tenantId: string;
  environment: string;
  requesterKeyId: string;
  idempotencyDigest: string;
  requestDigest: string;
  challengeHash: string;
  actionHash: string;
  actionCaid: string;
  action: Record<string, any>;
  approverId: string;
  pollTokenHash: string;
  sealedToken: SealedPollToken;
  expiresAt: string;
};

export class ApprovalStorageError extends Error {
  code: string;

  constructor(code = 'approval_storage_unavailable') {
    super(code);
    this.name = 'ApprovalStorageError';
    this.code = code;
  }
}

export async function enterApprovalRequestBoundary(
  requestId: string,
  requestDigest: string,
  producerKeyId: string,
): Promise<boolean> {
  const { data, error } = await client().rpc('enter_approval_acquisition_boundary', {
    p_request_id: requestId,
    p_request_digest: requestDigest,
    p_producer_key_id: producerKeyId,
  });
  if (error) throw new ApprovalStorageError();
  return data === true;
}

function usableRow(value: any): value is ApprovalAcquisitionRow {
  return value && typeof value === 'object' && !Array.isArray(value)
    && typeof value.request_id === 'string'
    && typeof value.request_digest === 'string'
    && typeof value.poll_token_hash === 'string'
    && typeof value.status === 'string';
}

function client() {
  try {
    const value = getServiceClient();
    if (!value || typeof value.rpc !== 'function' || typeof value.from !== 'function') {
      throw new Error('invalid_client');
    }
    return value;
  } catch {
    throw new ApprovalStorageError();
  }
}

export async function reserveApprovalRequest(input: ReserveApprovalInput): Promise<
  | { outcome: 'created' | 'existing'; request: ApprovalAcquisitionRow }
  | { outcome: 'conflict' }
> {
  const { data, error } = await client().rpc('reserve_approval_acquisition_request', {
    p_request_id: input.requestId,
    p_tenant_id: input.tenantId,
    p_environment: input.environment,
    p_requester_key_id: input.requesterKeyId,
    p_idempotency_digest: input.idempotencyDigest,
    p_request_digest: input.requestDigest,
    p_challenge_hash: input.challengeHash,
    p_action_hash: input.actionHash,
    p_action_caid: input.actionCaid,
    p_action: input.action,
    p_approver_id: input.approverId,
    p_poll_token_hash: input.pollTokenHash,
    p_poll_token_key_id: input.sealedToken.keyId,
    p_poll_token_ciphertext: input.sealedToken.ciphertext,
    p_poll_token_iv: input.sealedToken.iv,
    p_poll_token_tag: input.sealedToken.tag,
    p_expires_at: input.expiresAt,
  });
  if (error || !data || !['created', 'existing', 'conflict'].includes(data.outcome)) {
    throw new ApprovalStorageError();
  }
  if (data.outcome === 'conflict') return { outcome: 'conflict' };
  if (!usableRow(data.request)) throw new ApprovalStorageError();
  return { outcome: data.outcome, request: data.request };
}

export async function completeApprovalRequest({
  requestId,
  requestDigest,
  receiptId,
  signoffId,
  receiptActionHash,
  expiresAt,
}: {
  requestId: string;
  requestDigest: string;
  receiptId: string;
  signoffId: string;
  receiptActionHash: string;
  expiresAt: string;
}): Promise<boolean> {
  const { data, error } = await client().rpc('complete_approval_acquisition_request', {
    p_request_id: requestId,
    p_request_digest: requestDigest,
    p_receipt_id: receiptId,
    p_signoff_id: signoffId,
    p_receipt_action_hash: receiptActionHash,
    p_expires_at: expiresAt,
  });
  if (error) throw new ApprovalStorageError();
  return data === true;
}

export async function reconcileApprovalRequest(
  requestId: string,
  requestDigest: string,
): Promise<{
  outcome: 'indeterminate' | 'pending' | 'reconciled';
  request: ApprovalAcquisitionRow;
}> {
  const { data, error } = await client().rpc('reconcile_approval_acquisition_request', {
    p_request_id: requestId,
    p_request_digest: requestDigest,
  });
  if (error || !data || !['indeterminate', 'pending', 'reconciled'].includes(data.outcome)
      || !usableRow(data.request)) {
    throw new ApprovalStorageError();
  }
  return { outcome: data.outcome, request: data.request };
}

export async function refuseApprovalRequest({
  requestId,
  requestDigest,
  refusalCode,
}: {
  requestId: string;
  requestDigest: string;
  refusalCode: string;
}): Promise<boolean> {
  const { data, error } = await client().rpc('refuse_approval_acquisition_request', {
    p_request_id: requestId,
    p_request_digest: requestDigest,
    p_refusal_code: refusalCode,
  });
  if (error) throw new ApprovalStorageError();
  return data === true;
}

export async function recoverApprovalPollToken(input: {
  requestId: string;
  requestDigest: string;
  tenantId: string;
  environment: string;
  requesterKeyId: string;
  idempotencyDigest: string;
  previousPollTokenHash: string;
  previousPollTokenKeyId: string;
  pollTokenHash: string;
  sealedToken: SealedPollToken;
}): Promise<boolean> {
  const { data, error } = await client().rpc('recover_approval_acquisition_poll_token', {
    p_request_id: input.requestId,
    p_request_digest: input.requestDigest,
    p_tenant_id: input.tenantId,
    p_environment: input.environment,
    p_requester_key_id: input.requesterKeyId,
    p_idempotency_digest: input.idempotencyDigest,
    p_previous_poll_token_hash: input.previousPollTokenHash,
    p_previous_poll_token_key_id: input.previousPollTokenKeyId,
    p_poll_token_hash: input.pollTokenHash,
    p_poll_token_key_id: input.sealedToken.keyId,
    p_poll_token_ciphertext: input.sealedToken.ciphertext,
    p_poll_token_iv: input.sealedToken.iv,
    p_poll_token_tag: input.sealedToken.tag,
  });
  if (error) throw new ApprovalStorageError();
  return data === true;
}

const POLL_SELECT = [
  'request_id', 'tenant_id', 'environment', 'requester_key_id', 'producer_key_id',
  'idempotency_digest', 'request_digest', 'challenge_hash', 'action_hash',
  'action_caid', 'action', 'approver_id', 'poll_token_hash',
  'poll_token_key_id', 'poll_token_ciphertext', 'poll_token_iv', 'poll_token_tag', 'status',
  'reconciliation_state', 'refusal_code',
  'receipt_id', 'signoff_id', 'receipt_action_hash',
  'indeterminate_at', 'reconciled_at', 'refused_at',
  'expires_at', 'created_at', 'updated_at',
].join(', ');

export async function findApprovalRequest(
  requestId: string,
  pollTokenHash: string,
): Promise<ApprovalAcquisitionRow | null> {
  const { data, error } = await client()
    .from('approval_acquisition_requests')
    .select(POLL_SELECT)
    .eq('request_id', requestId)
    .eq('poll_token_hash', pollTokenHash)
    .maybeSingle();
  if (error) throw new ApprovalStorageError();
  if (!data) return null;
  if (!usableRow(data)) throw new ApprovalStorageError();
  return data as ApprovalAcquisitionRow;
}
