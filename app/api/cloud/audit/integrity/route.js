import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { verifyIntegrity } from '@/lib/cloud/event-explorer';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/audit/integrity?from=...&to=...
 *
 * Run integrity verification across event tables.
 * Returns anomaly list and integrity score.
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const url = new URL(request.url);
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');

    const result = await verifyIntegrity({ from, to });

    return NextResponse.json({
      ...result,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/audit/integrity] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
