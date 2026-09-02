import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { authEntityId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { EP_ERRORS, epProblem, epDbError } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * GET /api/signoff/[challengeId]
 *
 * Retrieve details of a signoff challenge by ID.
 * The guarded client is used for reads to enforce write discipline.
 *
 * signoff_challenges carries tenant_id (supabase/migrations/072), so a
 * challenge_id-only lookup is a cross-tenant read. Cloud tenant keys are bound
 * to their own tenant exactly like app/api/cloud/signoff/escalate does.
 * Protocol-plane keys carry no tenant at all, so their global
 * `operator` / `signoff.view` permission is not a tenant comparison and can
 * never stand in for one on a tenant-owned challenge.
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ challengeId: string }> },
): Promise<NextResponse> {
  try {
    const { challengeId } = await params;
    const auth = await authenticateRequest(request);

    if (auth.error) {
      // Cloud tenant keys live in tenant_api_keys, not api_keys, so they never
      // authenticate above. Serve them from the same tenant-scoped read the
      // rest of the cloud plane uses.
      const cloudAuth = await authenticateCloudRequest(request);
      if (!cloudAuth) return EP_ERRORS.UNAUTHORIZED();
      requirePermission(cloudAuth, 'read');

      const { data: scoped, error: scopedError } = await getGuardedClient()
        .from('signoff_challenges')
        .select('*')
        .eq('tenant_id', cloudAuth.tenantId)
        .eq('challenge_id', challengeId)
        .maybeSingle();

      if (scopedError) {
        return epDbError(500, 'signoff_challenge_fetch_failed', scopedError, 'signoff/challenge');
      }
      if (!scoped) {
        return EP_ERRORS.NOT_FOUND('Signoff challenge');
      }
      return NextResponse.json(scoped);
    }

    const { data: challenge, error } = await getGuardedClient()
      .from('signoff_challenges')
      .select('*')
      .eq('challenge_id', challengeId)
      .maybeSingle();

    if (error) {
      return epDbError(500, 'signoff_challenge_fetch_failed', error, 'signoff/challenge');
    }

    if (!challenge) {
      return EP_ERRORS.NOT_FOUND('Signoff challenge');
    }

    // ── Authorization: caller must be the accountable actor or have operator permissions ──
    const callerEntityId = authEntityId(auth as any);
    const isAccountableActor = callerEntityId && callerEntityId === challenge.accountable_actor_ref;

    if (!isAccountableActor && challenge.tenant_id) {
      // Tenant-owned row, untenanted caller: do not confirm that it exists.
      return EP_ERRORS.NOT_FOUND('Signoff challenge');
    }

    const hasOperatorPermission = auth.permissions?.includes('signoff.view') || auth.permissions?.includes('operator');

    if (!isAccountableActor && !hasOperatorPermission) {
      return epProblem(403, 'forbidden', 'You must be the accountable actor or have operator permissions to view this challenge');
    }

    return NextResponse.json(challenge);
  } catch (err) {
    if ((err as any)?.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', (err as any).message);
    }
    logger.error('Signoff challenge fetch error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
