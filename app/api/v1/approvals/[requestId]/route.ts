// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import {
  ApprovalEvidenceError,
  loadApprovalStatus,
} from '@/lib/approval-acquisition/evidence.js';
import { approvalJson, approvalProblem } from '@/lib/approval-acquisition/response.js';
import {
  ApprovalStorageError,
  findApprovalRequest,
} from '@/lib/approval-acquisition/store.js';
import {
  APPROVAL_POLL_TOKEN_PATTERN,
  APPROVAL_REQUEST_ID_PATTERN,
  hashPollToken,
} from '@/lib/approval-acquisition/token.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';

export const dynamic = 'force-dynamic';

const NOT_FOUND_DETAIL = 'Approval request not found';

function notFound(): NextResponse {
  return approvalProblem(404, 'approval_not_found', NOT_FOUND_DETAIL);
}

function authenticateApprovalPollCapability(request: Request): string | null {
  const header = request.headers.get('authorization') || '';
  const match = header.match(/^EP-Approval ([^\s]+)$/);
  return match && APPROVAL_POLL_TOKEN_PATTERN.test(match[1]) ? match[1] : null;
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ requestId: string }> | { requestId: string } },
): Promise<NextResponse> {
  try {
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) {
      return approvalProblem(429, 'rate_limited', 'Too many approval polling requests');
    }
    const params = await context.params;
    const requestId = params?.requestId || '';
    const token = authenticateApprovalPollCapability(request);
    if (!APPROVAL_REQUEST_ID_PATTERN.test(requestId) || !token) return notFound();

    const row = await findApprovalRequest(requestId, hashPollToken(token));
    if (!row) return notFound();
    const result = await loadApprovalStatus(row, new Date());
    if (result.status === 'not_ready') {
      return approvalProblem(503, 'approval_receipt_not_ready', 'A verifiable Class-A approval receipt is not available');
    }
    if (result.status === 'approved') {
      return approvalJson({ request_id: requestId, status: result.status, receipt: result.receipt });
    }
    return approvalJson({ request_id: requestId, status: result.status });
  } catch (error) {
    logger.error('[approval-acquisition] GET failed', {
      kind: error instanceof ApprovalStorageError
        ? error.code
        : error instanceof ApprovalEvidenceError
          ? 'approval_evidence_unavailable'
          : 'approval_poll_failed',
    });
    return approvalProblem(503, 'approval_acquisition_unavailable', 'Approval acquisition is temporarily unavailable');
  }
}
