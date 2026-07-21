// SPDX-License-Identifier: Apache-2.0

import { NextRequest } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission, CloudAuthorizationError } from '@/lib/cloud/authorize';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { POST as consumeTrustReceipt } from '../../../../v1/trust-receipts/[receiptId]/consume/route.js';

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;
const ACTION_HASH_PATTERN = /^[a-f0-9]{64}$/;

export async function POST(request: NextRequest, { params }: { params: Promise<{ receiptId: string }> }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return epProblem(401, 'unauthorized', 'A valid Cloud API key is required');
    requirePermission(auth, 'approval_request');

    const { receiptId } = await params;
    if (!RECEIPT_ID_PATTERN.test(receiptId || '')) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }
    const parsed = await readLimitedJson(request, 8 * 1024, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const actionHash = parsed.value?.action_hash;
    if (!ACTION_HASH_PATTERN.test(actionHash || '')) {
      return epProblem(400, 'invalid_action_hash', 'action_hash must be 64 lowercase hexadecimal characters');
    }

    const delegated = new Request(
      new URL(`/api/v1/trust-receipts/${receiptId}/consume`, request.url),
      {
        method: 'POST',
        headers: {
          authorization: request.headers.get('authorization') || '',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          action_hash: actionHash,
          executing_system: 'emilia_cloud_approval_endpoint',
        }),
      },
    );
    const response = await consumeTrustReceipt(delegated as any, {
      params: Promise.resolve({ receiptId }),
    });
    response.headers.set('cache-control', 'no-store, private');
    return response;
  } catch (error) {
    if (error instanceof CloudAuthorizationError) {
      return epProblem(403, 'approval_request_permission_required', error.message);
    }
    logger.error('[cloud/approvals] consume failed:', error);
    return epProblem(500, 'internal_error', 'Approval consumption failed');
  }
}
