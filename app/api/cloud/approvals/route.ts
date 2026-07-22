// SPDX-License-Identifier: Apache-2.0
//
// Connected reference approval endpoint. This surface deliberately exposes
// one bounded, high-risk action rather than turning a tenant key into a
// generic Guard receipt minting capability.

import { NextRequest, NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission, CloudAuthorizationError } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn';
import { loadTenantApprovalQueue } from '@/lib/cloud/approval-queue.js';
import { POST as createTrustReceipt } from '../../v1/trust-receipts/route.js';
import { POST as requestSignoff } from '../../v1/signoffs/request/route.js';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { buildPaymentReleaseActionIdentity } from '@/lib/approval-acquisition/contract.js';

const MAX_APPROVAL_REQUEST_BYTES = 32 * 1024;
const PAYMENT_REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._/-]{2,199}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ACQUISITION_REQUEST_PATTERN = /^apr_[a-f0-9]{32}$/;
const APPROVAL_BOUNDARY_HEADER = 'x-emilia-approval-boundary';

function preBoundary<T extends NextResponse>(response: T): T {
  response.headers.set(APPROVAL_BOUNDARY_HEADER, 'not-entered');
  return response;
}

function authHeader(request: NextRequest): string {
  return request.headers.get('authorization') || '';
}

function delegatedRequest(url: URL, authorization: string, body: any): Request {
  return new Request(url, {
    method: 'POST',
    headers: {
      authorization,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

async function relayJson(response: Response) {
  let body: any;
  try {
    body = await response.json();
  } catch {
    body = {
      type: 'https://www.emiliaprotocol.ai/problems/upstream_invalid_response',
      title: 'Upstream Invalid Response',
      detail: 'The approval primitive returned a non-JSON response.',
    };
  }
  return NextResponse.json(body, {
    status: response.status,
    headers: { 'cache-control': 'no-store, private' },
  });
}

function validateApprovalInput(
  body: any,
  scope: { tenantId: string; environment: string },
): [string, string] | null {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return ['invalid_body', 'request body must be a JSON object'];
  }
  if (!PAYMENT_REFERENCE_PATTERN.test(body.payment_reference || '')
      || String(body.payment_reference).includes('..')) {
    return [
      'invalid_payment_reference',
      'payment_reference must be 3-200 safe identifier characters and may not contain ".."',
    ];
  }
  if (typeof body.amount !== 'number'
      || !Number.isFinite(body.amount)
      || body.amount <= 0
      || body.amount > 1_000_000_000_000) {
    return ['invalid_amount', 'amount must be a positive finite JSON number no greater than 1 trillion'];
  }
  if (typeof body.currency !== 'string' || !/^[A-Z]{3}$/.test(body.currency)) {
    return ['invalid_currency', 'currency must be a three-letter uppercase ISO-style code'];
  }
  if (typeof body.counterparty_name !== 'string'
      || !body.counterparty_name.trim()
      || body.counterparty_name.length > 160
      || CONTROL_CHARACTERS.test(body.counterparty_name)) {
    return ['invalid_counterparty_name', 'counterparty_name must be 1-160 printable characters'];
  }
  if (!APPROVER_ID_PATTERN.test(body.approver_id || '')) {
    return ['invalid_approver_id', 'approver_id must be 3-128 characters of [A-Za-z0-9:_.@-]'];
  }
  if (!SHA256_DIGEST_PATTERN.test(body.payment_destination_hash || '')) {
    return [
      'invalid_payment_destination_hash',
      'payment_destination_hash must be sha256:<64 lowercase hex>',
    ];
  }
  const acquisitionKeys = [
    'acquisition_request_id',
    'acquisition_request_digest',
    'acquisition_action_hash',
    'acquisition_action_caid',
    'acquisition_challenge_hash',
    'acquisition_tenant_id',
    'acquisition_environment',
  ];
  const acquisitionCount = acquisitionKeys.filter((key) => body[key] !== undefined).length;
  if (acquisitionCount !== 0 && acquisitionCount !== acquisitionKeys.length) {
    return ['invalid_acquisition_binding', 'the acquisition binding must be supplied as one complete set'];
  }
  if (acquisitionCount === acquisitionKeys.length) {
    if (!ACQUISITION_REQUEST_PATTERN.test(body.acquisition_request_id || '')
        || !SHA256_DIGEST_PATTERN.test(body.acquisition_request_digest || '')
        || !SHA256_DIGEST_PATTERN.test(body.acquisition_action_hash || '')
        || !SHA256_DIGEST_PATTERN.test(body.acquisition_challenge_hash || '')
        || body.acquisition_tenant_id !== scope.tenantId
        || body.acquisition_environment !== scope.environment) {
      return ['invalid_acquisition_binding', 'the acquisition binding identifiers are malformed'];
    }
    const material = {
      action_type: 'payment.release',
      amount_usd: body.amount,
      currency: body.currency,
      payment_instruction_id: body.payment_reference,
      beneficiary_account_hash: body.payment_destination_hash,
      counterparty_name: body.counterparty_name.trim(),
    };
    const identity = buildPaymentReleaseActionIdentity(material);
    if (!identity.ok
        || identity.actionCaid !== body.acquisition_action_caid
        || approvalActionHash({ ...material, action_caid: identity.actionCaid }) !== body.acquisition_action_hash) {
      return ['invalid_acquisition_binding', 'the acquisition binding does not identify the exact payment action'];
    }
  }
  return null;
}

function summarize(approvals: any[]): Record<string, number> {
  const summary: Record<string, number> = {
    pending: 0,
    approved: 0,
    rejected: 0,
    expired: 0,
    consumed: 0,
  };
  for (const approval of approvals) {
    if (Object.hasOwn(summary, approval?.status)) summary[approval.status] += 1;
  }
  return summary;
}

export async function GET(request: NextRequest) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return epProblem(401, 'unauthorized', 'A valid Cloud API key is required');
    requirePermission(auth, 'approval_request');

    const result = await loadTenantApprovalQueue({
      supabase: getGuardedClient(),
      tenantId: auth.tenantId,
      log: logger,
    });
    if (result.error) {
      return epProblem(503, 'approval_queue_unavailable', result.error);
    }
    const approvals = result.approvals || [];
    return NextResponse.json({
      tenant_id: auth.tenantId,
      approvals,
      summary: summarize(approvals),
      implementation_status: 'prototype',
    }, {
      headers: { 'cache-control': 'no-store, private' },
    });
  } catch (error) {
    if (error instanceof CloudAuthorizationError) {
      return epProblem(403, 'approval_request_permission_required', error.message);
    }
    logger.error('[cloud/approvals] GET failed:', error);
    return epProblem(500, 'internal_error', 'Approval queue failed');
  }
}

export async function POST(request: NextRequest) {
  let boundaryEntered = false;
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return preBoundary(epProblem(401, 'unauthorized', 'A valid Cloud API key is required'));
    requirePermission(auth, 'approval_request');

    const parsed = await readLimitedJson(request, MAX_APPROVAL_REQUEST_BYTES, { invalidValue: {} });
    if (!parsed.ok) return preBoundary(epProblem(parsed.status, parsed.code, parsed.detail));
    const body = parsed.value;
    const inputError = validateApprovalInput(body, auth);
    if (inputError) return preBoundary(epProblem(400, inputError[0], inputError[1]));

    const authorization = authHeader(request);
    boundaryEntered = true;
    const receiptResponse = await createTrustReceipt(delegatedRequest(
      new URL('/api/v1/trust-receipts', request.url),
      authorization,
      {
        organization_id: auth.tenantId,
        action_type: 'large_payment_release',
        target_resource_id: body.payment_reference,
        amount: body.amount,
        currency: body.currency,
        counterparty_name: body.counterparty_name.trim(),
        payment_destination_hash: body.payment_destination_hash,
        ...(body.acquisition_request_id ? {
          acquisition_request_id: body.acquisition_request_id,
          acquisition_request_digest: body.acquisition_request_digest,
          acquisition_action_hash: body.acquisition_action_hash,
          acquisition_action_caid: body.acquisition_action_caid,
          acquisition_challenge_hash: body.acquisition_challenge_hash,
          acquisition_tenant_id: body.acquisition_tenant_id,
          acquisition_environment: body.acquisition_environment,
        } : {}),
        display_summary: `Release ${body.currency} ${body.amount} to ${body.counterparty_name.trim()}`,
        expires_in_sec: 60 * 60,
        enforcement_mode: 'enforce',
      },
    ) as any);
    if (![200, 201].includes(receiptResponse.status)) return relayJson(receiptResponse);
    const receipt = await receiptResponse.json();
    if (!receipt.signoff_required || receipt.required_assurance !== 'A') {
      logger.error('[cloud/approvals] critical action minted without Class-A signoff', {
        receipt_id: receipt.receipt_id,
      });
      return epProblem(
        500,
        'approval_invariant_failed',
        'The critical action did not require Class-A signoff; refusing to continue.',
      );
    }

    const signoffResponse = await requestSignoff(delegatedRequest(
      new URL('/api/v1/signoffs/request', request.url),
      authorization,
      {
        receipt_id: receipt.receipt_id,
        approver_id: body.approver_id,
        expires_in_minutes: 60,
        comment: typeof body.comment === 'string' ? body.comment.slice(0, 500) : null,
        ...(body.acquisition_request_id ? {
          acquisition_request_id: body.acquisition_request_id,
          acquisition_request_digest: body.acquisition_request_digest,
          acquisition_tenant_id: body.acquisition_tenant_id,
          acquisition_environment: body.acquisition_environment,
          return_existing: true,
        } : {}),
      },
    ) as any);
    if (![200, 201].includes(signoffResponse.status)) {
      const failed = await relayJson(signoffResponse);
      failed.headers.set('x-emilia-orphaned-receipt-id', receipt.receipt_id);
      return failed;
    }
    const signoff = await signoffResponse.json();

    return NextResponse.json({
      receipt_id: receipt.receipt_id,
      action_hash: receipt.action_hash,
      action_caid: receipt.canonical_action?.action_caid || receipt.action_caid || null,
      expires_at: receipt.expires_at,
      signoff_id: signoff.signoff_id,
      approver_id: signoff.approver_id,
      required_assurance: receipt.required_assurance,
      status: 'pending',
      review_path: `/signoff/${signoff.signoff_id}`,
      implementation_status: 'prototype',
    }, {
      status: 201,
      headers: { 'cache-control': 'no-store, private' },
    });
  } catch (error) {
    if (error instanceof CloudAuthorizationError) {
      const response = epProblem(403, 'approval_request_permission_required', error.message);
      return boundaryEntered ? response : preBoundary(response);
    }
    logger.error('[cloud/approvals] POST failed:', error);
    const response = epProblem(500, 'internal_error', 'Approval request failed');
    return boundaryEntered ? response : preBoundary(response);
  }
}
