// SPDX-License-Identifier: Apache-2.0

import { NextRequest } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission, CloudAuthorizationError } from '@/lib/cloud/authorize';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { GET as readTrustReceiptEvidence } from '../../../../v1/trust-receipts/[receiptId]/evidence/route.js';

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

export async function GET(request: NextRequest, { params }: { params: Promise<{ receiptId: string }> }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return epProblem(401, 'unauthorized', 'A valid Cloud API key is required');
    requirePermission(auth, 'approval_request');

    const { receiptId } = await params;
    if (!RECEIPT_ID_PATTERN.test(receiptId || '')) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }
    const delegated = new Request(
      new URL(`/api/v1/trust-receipts/${receiptId}/evidence`, request.url),
      {
        method: 'GET',
        headers: { authorization: request.headers.get('authorization') || '' },
      },
    );
    const response = await readTrustReceiptEvidence(delegated, {
      params: Promise.resolve({ receiptId }),
    });
    response.headers.set('cache-control', 'no-store, private');
    return response;
  } catch (error) {
    if (error instanceof CloudAuthorizationError) {
      return epProblem(403, 'approval_request_permission_required', error.message);
    }
    logger.error('[cloud/approvals] evidence failed:', error);
    return epProblem(500, 'internal_error', 'Approval evidence export failed');
  }
}
