// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import { POST as createCloudApproval } from '@/app/api/cloud/approvals/route.js';
import {
  bindApprovalCreateRequestScope,
  type ApprovalCreateValue,
  type ScopedApprovalCreateValue,
} from './contract.js';
import { approvalJson, approvalProblem } from './response.js';
import {
  completeApprovalRequest,
  enterApprovalRequestBoundary,
  recoverApprovalPollToken,
  reconcileApprovalRequest,
  refuseApprovalRequest,
  reserveApprovalRequest,
  type ApprovalAcquisitionRow,
} from './store.js';
import {
  ApprovalTokenKeyUnavailableError,
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
const GUARD_ACTION_HASH = /^[a-f0-9]{64}$/;
const REFUSAL_CODE = /^[a-z][a-z0-9_]{2,127}$/;
const PRE_BOUNDARY_HEADER = 'x-emilia-approval-boundary';

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

function indeterminateResponse(
  requestId: string,
  pollToken: string,
  expiresAt: string,
): NextResponse {
  return approvalJson({
    request_id: requestId,
    poll_token: pollToken,
    status: 'indeterminate',
    expires_at: expiresAt,
    reconciliation: { state: 'required', retry_safe: false },
  }, { status: 202 });
}

async function reconcileOrIndeterminate({
  requestId,
  requestDigest,
  pollToken,
  expiresAt,
  origin,
}: {
  requestId: string;
  requestDigest: string;
  pollToken: string;
  expiresAt: string;
  origin: string;
}): Promise<NextResponse> {
  const recovery = await reconcileApprovalRequest(requestId, requestDigest);
  if (recovery.outcome === 'pending' || recovery.outcome === 'reconciled') {
    const row = recovery.request;
    if (row.status !== 'pending' || !row.signoff_id || Date.now() >= Date.parse(row.expires_at)) {
      return approvalProblem(410, 'approval_request_expired', 'The approval request has expired');
    }
    return createResponse(row.request_id, pollToken, row.signoff_id, row.expires_at, origin);
  }
  return indeterminateResponse(requestId, pollToken, recovery.request.expires_at || expiresAt);
}

function validUpstream(value: any, expectedCaid: string, nowMs = Date.now()): value is UpstreamApproval {
  const expiresAt = Date.parse(value?.expires_at || '');
  return value && typeof value === 'object' && !Array.isArray(value)
    && RECEIPT_ID.test(value.receipt_id || '')
    && SIGNOFF_ID.test(value.signoff_id || '')
    && GUARD_ACTION_HASH.test(value.action_hash || '')
    && value.action_caid === expectedCaid
    && value.required_assurance === 'A'
    && value.status === 'pending'
    && Number.isFinite(nowMs)
    && Number.isFinite(expiresAt)
    && expiresAt > nowMs;
}

function isVerifiedPreBoundaryRefusal(response: Response, body: any): body is Record<string, any> {
  return response.status >= 400
    && response.status < 500
    && response.headers.get(PRE_BOUNDARY_HEADER) === 'not-entered'
    && body
    && typeof body === 'object'
    && !Array.isArray(body)
    && REFUSAL_CODE.test(body.code || '');
}

async function recoverExistingPollToken(row: ApprovalAcquisitionRow): Promise<string> {
  try {
    return decryptPollToken({
      keyId: row.poll_token_key_id,
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
  } catch (error) {
    if (!(error instanceof ApprovalTokenKeyUnavailableError)) throw error;
  }

  // Retiring an envelope key must not erase an already-durable safety state.
  // A new poll capability may be issued only through the authenticated POST
  // replay and an exact tenant/environment/logical-request compare-and-swap.
  // The original requester_key_id remains immutable actor provenance.
  const replacement = generateApprovalPollToken();
  const replacementHash = hashPollToken(replacement);
  const sealedToken = encryptPollToken(replacement, {
    requestId: row.request_id,
    tenantId: row.tenant_id,
    environment: row.environment,
    requesterKeyId: row.requester_key_id,
    pollTokenHash: replacementHash,
  });
  const recovered = await recoverApprovalPollToken({
    requestId: row.request_id,
    requestDigest: row.request_digest,
    tenantId: row.tenant_id,
    environment: row.environment,
    requesterKeyId: row.requester_key_id,
    idempotencyDigest: row.idempotency_digest,
    previousPollTokenHash: row.poll_token_hash,
    previousPollTokenKeyId: row.poll_token_key_id,
    pollTokenHash: replacementHash,
    sealedToken,
  });
  if (!recovered) throw new Error('approval_poll_token_recovery_failed');
  return replacement;
}

async function invokeApprovalProducer({
  request,
  value,
  requestId,
  requestDigest,
  pollToken,
  expiresAt,
  origin,
  producerKeyId,
}: {
  request: NextRequest;
  value: ScopedApprovalCreateValue;
  requestId: string;
  requestDigest: string;
  pollToken: string;
  expiresAt: string;
  origin: string;
  producerKeyId: string;
}): Promise<NextResponse> {
  const entered = await enterApprovalRequestBoundary(requestId, requestDigest, producerKeyId);
  if (!entered) {
    return approvalProblem(503, 'approval_initialization_unavailable', 'The approval boundary could not be entered safely');
  }

  let upstreamResponse: NextResponse;
  try {
    upstreamResponse = await createCloudApproval(new Request(request.url, {
      method: 'POST',
      headers: {
        authorization: request.headers.get('authorization') || '',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        ...value.cloudApprovalBody,
        acquisition_request_id: requestId,
        acquisition_request_digest: requestDigest,
        acquisition_action_hash: value.actionHash,
        acquisition_action_caid: value.actionCaid,
        acquisition_challenge_hash: value.challengeHash,
        acquisition_tenant_id: value.requestScope.tenant_id,
        acquisition_environment: value.requestScope.environment,
      }),
    }) as NextRequest);
  } catch {
    return reconcileOrIndeterminate({ requestId, requestDigest, pollToken, expiresAt, origin });
  }

  let upstream: any = null;
  try {
    upstream = await upstreamResponse.json();
  } catch {
    // Closed below with the status and upstream response contract.
  }
  if (isVerifiedPreBoundaryRefusal(upstreamResponse, upstream)) {
    const refused = await refuseApprovalRequest({
      requestId,
      requestDigest,
      refusalCode: upstream.code,
    });
    if (refused) return approvalJson(upstream, { status: upstreamResponse.status });
  }
  if (![200, 201].includes(upstreamResponse.status) || !validUpstream(upstream, value.actionCaid)) {
    return reconcileOrIndeterminate({ requestId, requestDigest, pollToken, expiresAt, origin });
  }

  const upstreamExpiry = new Date(Math.min(Date.parse(upstream.expires_at), Date.parse(expiresAt))).toISOString();
  let completed = false;
  try {
    completed = await completeApprovalRequest({
      requestId,
      requestDigest,
      receiptId: upstream.receipt_id,
      signoffId: upstream.signoff_id,
      receiptActionHash: upstream.action_hash,
      expiresAt: upstreamExpiry,
    });
  } catch {
    return reconcileOrIndeterminate({ requestId, requestDigest, pollToken, expiresAt, origin });
  }
  if (!completed) {
    return reconcileOrIndeterminate({ requestId, requestDigest, pollToken, expiresAt, origin });
  }
  return createResponse(requestId, pollToken, upstream.signoff_id, upstreamExpiry, origin);
}

export async function initializeApprovalRequest(
  request: NextRequest,
  auth: CloudAuthContext,
  value: ApprovalCreateValue,
): Promise<NextResponse> {
  const origin = publicOrigin();
  const scopedValue = bindApprovalCreateRequestScope(value, {
    tenantId: auth.tenantId,
    environment: auth.environment,
  });
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
    requestDigest: scopedValue.requestDigest,
    challengeHash: scopedValue.challengeHash,
    actionHash: scopedValue.actionHash,
    actionCaid: scopedValue.actionCaid,
    action: scopedValue.action,
    approverId: scopedValue.approverId,
    pollTokenHash,
    sealedToken,
    expiresAt,
  });

  if (reservation.outcome === 'conflict') {
    return approvalProblem(409, 'idempotency_conflict', 'The idempotency key is already bound to a different request');
  }
  if (reservation.outcome === 'existing') {
    const row = reservation.request;
    if (row.tenant_id !== auth.tenantId
        || row.environment !== auth.environment
        || row.idempotency_digest !== scopedValue.idempotencyDigest
        || row.request_digest !== scopedValue.requestDigest) {
      return approvalProblem(409, 'idempotency_conflict', 'The idempotency key is already bound to a different request');
    }
    const recovered = await recoverExistingPollToken(row);
    if (row.status === 'pending' && row.signoff_id) {
      if (Date.now() >= Date.parse(row.expires_at)) {
        return approvalProblem(410, 'approval_request_expired', 'The approval request has expired');
      }
      return createResponse(row.request_id, recovered, row.signoff_id, row.expires_at, origin);
    }
    if (row.status === 'invoking' || row.status === 'indeterminate') {
      return reconcileOrIndeterminate({
        requestId: row.request_id,
        requestDigest: row.request_digest,
        pollToken: recovered,
        expiresAt: row.expires_at,
        origin,
      });
    }
    if (row.status !== 'initializing') {
      return approvalProblem(503, 'approval_initialization_unavailable', 'The approval request is not recoverable');
    }
    requestId = row.request_id;
    pollToken = recovered;
    expiresAt = row.expires_at;
  }

  return invokeApprovalProducer({
    request,
    value: scopedValue,
    requestId,
    requestDigest: scopedValue.requestDigest,
    pollToken,
    expiresAt,
    origin,
    producerKeyId: auth.keyId,
  });
}
