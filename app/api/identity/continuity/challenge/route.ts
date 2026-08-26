import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { challengeContinuity } from '@/lib/ep-ix';
import { EP_ERRORS, epDbError, epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

// This route is auth-gated per middleware.js (useAuth: true,
// dispute_write category). The route was previously NOT calling
// authenticateRequest(), making it an auth-bypass — middleware does the
// rate-limiting + write-guard check but the actual handler accepted
// arbitrary challenger_id from the body. Sibling routes
// (/identity/continuity, .../resolve) authenticate; this one must too.
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();
    const challengerId = authEntityId(auth).trim();
    if (!challengerId) {
      return epProblem(403, 'forbidden', 'Identity continuity challenge requires an authenticated entity identity');
    }

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;
    if (!body.continuity_id) return EP_ERRORS.BAD_REQUEST('continuity_id is required');
    if (!body.reason) return EP_ERRORS.BAD_REQUEST('reason is required');

    // Neither challenger identity nor challenger role is caller-asserted.
    // Identity comes from authentication; the atomic database boundary
    // derives a relationship-backed role. The only privileged input is this
    // server-derived admin bit from the authenticated API-key record, which
    // the RPC still validates against the claim endpoint organization.
    const permissions = Array.isArray(auth.permissions) ? auth.permissions : [];
    const result = await challengeContinuity({
      continuity_id: body.continuity_id,
      challenger_id: challengerId,
      reason: body.reason,
      evidence: body.evidence,
      enterprise_admin_authorized: permissions.includes('admin'),
    });
    if (result.error) {
      if ((result.status || 500) >= 500) return epDbError(result.status || 500, 'identity_continuity_challenge_failed', result.error, 'identity/continuity/challenge');
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Continuity challenge error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
