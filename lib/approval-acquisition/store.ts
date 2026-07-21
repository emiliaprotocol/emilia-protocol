// SPDX-License-Identifier: Apache-2.0

import { getServiceClient } from '@/lib/supabase.js';
import type { SealedPollToken } from './token.js';

export type ApprovalAcquisitionRow = {
  request_id: string;
  tenant_id: string;
  environment: string;
  requester_key_id: string;
  idempotency_digest: string;
  request_digest: string;
  challenge_hash: string;
  action_hash: string;
  action_caid: string;
  action: Record<string, any>;
  approver_id: string;
  poll_token_hash: string;
  poll_token_ciphertext: string;
  poll_token_iv: string;
  poll_token_tag: string;
  status: 'initializing' | 'pending';
  receipt_id: string | null;
  signoff_id: string | null;
  receipt_action_hash: string | null;
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

const POLL_SELECT = [
  'request_id', 'tenant_id', 'environment', 'requester_key_id',
  'idempotency_digest', 'request_digest', 'challenge_hash', 'action_hash',
  'action_caid', 'action', 'approver_id', 'poll_token_hash',
  'poll_token_ciphertext', 'poll_token_iv', 'poll_token_tag', 'status',
  'receipt_id', 'signoff_id', 'receipt_action_hash',
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
