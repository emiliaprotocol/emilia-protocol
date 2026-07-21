// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import { POST as createCloudApproval } from '@/app/api/cloud/approvals/route.js';
import type { ApprovalCreateValue } from './contract.js';
import { approvalJson, approvalProblem } from './response.js';
import { completeApprovalRequest, reserveApprovalRequest } from './store.js';
import {
  decryptPollToken,
  encryptPollToken,
  generateApprovalPollToken,
  generateApprovalRequestId,
  hashPollToken,
} from './token.js';
import type { CloudAuthContext } from '@/lib/cloud/auth';
import { getApprovalAcquisitionConfig } from '@/lib/env.js';

const ACQUISITION_TTL_MS = 15 * 60 * 1000;
const RECEIPT_ID = /^tr_[a-f0-9]{32}$/;
const SIGNOFF_ID = /^sig_[a-f0-9]{32}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;

type UpstreamApproval = {
  receipt_id: string;
  action_hash: string;
  action_caid: string;
  expires_at: string;
  signoff_id: string;
  required_assurance: string;
  status: string;
};

function publicOrigin(): string {
  const configured = getApprovalAcquisitionConfig().publicOrigin;
  if (!configured) throw new Error('approval_public_origin_unavailable');
  const url = new URL(configured);
  if (url.protocol !== 'https:' || url.origin !== configured || url.username || url.password) {
    throw new Error('approval_public_origin_invalid');
  }
  return url.origin;
}

function createResponse(
  requestId: string,
  pollToken: string,
  signoffId: string,
  expiresAt: string,
  origin: string,
): NextResponse {
  return approvalJson({
    request_id: requestId,
    poll_token: pollToken,
    approval_url: new URL(`/signoff/${encodeURIComponent(signoffId)}`, origin).toString(),
    status: 'pending',
    expires_at: expiresAt,
  }, { status: 201 });
}

function validUpstream(value: any, expectedCaid: string, nowMs = Date.now()): value is UpstreamApproval {
  const expiresAt = Date.parse(value?.expires_at || '');
  return value && typeof value === 'object' && !Array.isArray(value)
    && RECEIPT_ID.test(value.receipt_id || '')
    && SIGNOFF_ID.test(value.signoff_id || '')
    && SHA256.test(value.action_hash || '')
    && value.action_caid === expectedCaid
    && value.required_assurance === 'A'
    && value.status === 'pending'
    && Number.isFinite(nowMs)
    && Number.isFinite(expiresAt)
    && expiresAt > nowMs;
}

export async function initializeApprovalRequest(
  request: NextRequest,
  auth: CloudAuthContext,
  value: ApprovalCreateValue,
): Promise<NextResponse> {
  const origin = publicOrigin();
  let requestId = generateApprovalRequestId();
  let pollToken = generateApprovalPollToken();
  const pollTokenHash = hashPollToken(pollToken);
  const sealedToken = encryptPollToken(pollToken, {
    requestId,
    tenantId: auth.tenantId,
    environment: auth.environment,
    requesterKeyId: auth.keyId,
    pollTokenHash,
  });
  let expiresAt = new Date(Date.now() + ACQUISITION_TTL_MS).toISOString();
  const reservation = await reserveApprovalRequest({
    requestId,
    tenantId: auth.tenantId,
    environment: auth.environment,
    requesterKeyId: auth.keyId,
    idempotencyDigest: value.idempotencyDigest,
    requestDigest: value.requestDigest,
    challengeHash: value.challengeHash,
    actionHash: value.actionHash,
    actionCaid: value.actionCaid,
    action: value.action,
    approverId: value.approverId,
    pollTokenHash,
    sealedToken,
    expiresAt,
  });

  if (reservation.outcome === 'conflict') {
    return approvalProblem(409, 'idempotency_conflict', 'The idempotency key is already bound to a different request');
  }
  if (reservation.outcome === 'existing') {
    const row = reservation.request;
    const recovered = decryptPollToken({
      ciphertext: row.poll_token_ciphertext,
      iv: row.poll_token_iv,
      tag: row.poll_token_tag,
    }, {
      requestId: row.request_id,
      tenantId: row.tenant_id,
      environment: row.environment,
      requesterKeyId: row.requester_key_id,
      pollTokenHash: row.poll_token_hash,
    });
    if (Date.now() >= Date.parse(row.expires_at)) {
      return approvalProblem(410, 'approval_request_expired', 'The approval request has expired');
    }
    if (row.status === 'pending' && row.signoff_id) {
      return createResponse(row.request_id, recovered, row.signoff_id, row.expires_at, origin);
    }
    if (row.status !== 'initializing') {
      return approvalProblem(503, 'approval_initialization_unavailable', 'The approval request is not recoverable');
    }
    // The downstream receipt and signoff routes are idempotent on this exact
    // request id, so retrying an initializing row cannot duplicate a ceremony.
    requestId = row.request_id;
    pollToken = recovered;
    expiresAt = row.expires_at;
  }

  const upstreamResponse = await createCloudApproval(new Request(request.url, {
    method: 'POST',
    headers: {
      authorization: request.headers.get('authorization') || '',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      ...value.cloudApprovalBody,
      acquisition_request_id: requestId,
      acquisition_request_digest: value.requestDigest,
      acquisition_action_hash: value.actionHash,
      acquisition_action_caid: value.actionCaid,
      acquisition_challenge_hash: value.challengeHash,
    }),
  }) as NextRequest);
  let upstream: any = null;
  try {
    upstream = await upstreamResponse.json();
  } catch {
    // Closed below with the status and upstream response contract.
  }
  if (![200, 201].includes(upstreamResponse.status) || !validUpstream(upstream, value.actionCaid)) {
    return approvalProblem(503, 'approval_ceremony_unavailable', 'The approval ceremony could not be initialized');
  }
  const upstreamExpiry = new Date(Math.min(Date.parse(upstream.expires_at), Date.parse(expiresAt))).toISOString();
  const completed = await completeApprovalRequest({
    requestId,
    requestDigest: value.requestDigest,
    receiptId: upstream.receipt_id,
    signoffId: upstream.signoff_id,
    receiptActionHash: upstream.action_hash,
    expiresAt: upstreamExpiry,
  });
  if (!completed) {
    return approvalProblem(503, 'approval_storage_unavailable', 'The approval request could not be persisted');
  }
  return createResponse(requestId, pollToken, upstream.signoff_id, upstreamExpiry, origin);
}
