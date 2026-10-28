/**
 * /api/orcarouter/connect/cancel
 *
 * POST { attempt_id }
 *
 * @license Apache-2.0
 *
 * Releases a pending authorization attempt. Idempotent.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { cancelOrcaRouterAuthorization } from '@/lib/providers/orcarouter-pkce';
import { NO_STORE, crossOriginRefused, readJsonBody, requireOrcaRouterAdmin } from '../../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function POST(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return parsed.response;
  const attemptId = parsed.value?.attempt_id;
  if (typeof attemptId !== 'string' || !attemptId) {
    return epProblem(400, 'invalid_request', 'attempt_id is required');
  }
  try {
    const cancelled = cancelOrcaRouterAuthorization(attemptId, guard.admin.reviewerId);
    return NextResponse.json({ cancelled }, { headers: NO_STORE });
  } catch (error: any) {
    if (error?.message === 'credential_write_locked') {
      return epProblem(409, 'credential_busy', 'Another credential update is in progress');
    }
    if (error?.code === 'wrong_principal') {
      return epProblem(403, 'wrong_principal', error.message);
    }
    if (error?.code === 'attempt_unreadable') {
      return epProblem(503, 'attempt_unreadable', 'Could not confirm the authorization state');
    }
    return epProblem(503, 'cancel_failed', 'Could not confirm cancellation');
  }
}
