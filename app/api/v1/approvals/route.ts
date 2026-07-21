// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import {
  parseApprovalCreateRequest,
  SUPPORTED_APPROVAL_ACTION_TYPES,
} from '@/lib/approval-acquisition/contract.js';
import { approvalProblem } from '@/lib/approval-acquisition/response.js';
import { initializeApprovalRequest } from '@/lib/approval-acquisition/service.js';
import { ApprovalStorageError } from '@/lib/approval-acquisition/store.js';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { CloudAuthorizationError, requirePermission } from '@/lib/cloud/authorize';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '@/lib/logger.js';
import { checkRateLimit } from '@/lib/rate-limit';

export const dynamic = 'force-dynamic';

const MAX_BODY_BYTES = 32 * 1024;
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return approvalProblem(415, 'invalid_content_type', 'EP-APPROVAL-v1 requests require application/json');
    }
    const auth = await authenticateCloudRequest(request);
    if (!auth) return approvalProblem(401, 'unauthorized', 'A valid Cloud API key is required');
    requirePermission(auth, 'approval_request');

    const limited = await checkRateLimit(`cloud:${auth.tenantId}:${auth.keyId}`, 'cloud_write');
    if (!limited.allowed) {
      return approvalProblem(429, 'rate_limited', 'Too many approval acquisition requests');
    }
    const parsedJson = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsedJson.ok) {
      return approvalProblem(parsedJson.status, parsedJson.code, parsedJson.detail);
    }
    const parsed = parseApprovalCreateRequest(parsedJson.value);
    if (!parsed.ok) return approvalProblem(parsed.status, parsed.code, parsed.detail, {
      supported_action_types: SUPPORTED_APPROVAL_ACTION_TYPES,
    });

    return initializeApprovalRequest(request, auth, parsed.value);
  } catch (error) {
    if (error instanceof CloudAuthorizationError) {
      return approvalProblem(403, 'approval_request_permission_required', 'The Cloud key lacks approval_request permission');
    }
    logger.error('[approval-acquisition] POST failed', {
      kind: error instanceof ApprovalStorageError ? error.code : 'approval_initialization_failed',
    });
    return approvalProblem(503, 'approval_acquisition_unavailable', 'Approval acquisition is temporarily unavailable');
  }
}
