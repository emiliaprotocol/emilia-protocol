import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../../lib/logger.js';

/**
 * POST /api/cloud/policies/[policyId]/rollout
 *
 * Initiate a rollout of a policy version to the specified environment.
 * Requires: admin permission (deployment-level action).
 *
 * Body: { version: number, environment: string, strategy?: 'immediate' | 'canary' }
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'admin');

    const { policyId } = await params;
    const body = await request.json();

    if (!body.version || !body.environment) {
      return epProblem(400, 'missing_rollout_params', 'Both "version" and "environment" are required');
    }

    const supabase = getGuardedClient();

    // Verify the policy and version exist
    const { data: version, error: vErr } = await supabase
      .from('policy_versions')
      .select('*')
      .eq('policy_id', policyId)
      .eq('version', body.version)
      .maybeSingle();

    if (vErr) {
      logger.error('[cloud/policies/rollout] Version query error:', vErr);
      return epProblem(500, 'rollout_query_failed', vErr.message);
    }

    if (!version) {
      return epProblem(404, 'version_not_found', `Policy version ${body.version} not found`);
    }

    return NextResponse.json({
      policy_id: policyId,
      version: body.version,
      environment: body.environment,
      strategy: body.strategy || 'immediate',
      status: 'initiated',
      initiated_at: new Date().toISOString(),
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/policies/rollout] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
