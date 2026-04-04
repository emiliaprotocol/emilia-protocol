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
 * Body:
 *   version     {number}  — policy version number (must exist in policy_versions)
 *   environment {string}  — target environment (e.g. "production", "staging")
 *   strategy    {'immediate'|'canary'}  — default: 'immediate'
 *   canary_pct  {number}  — traffic % for canary rollouts (1–99, required if canary)
 *   metadata    {object}  — optional operator-supplied context
 *
 * Immediate rollouts supersede any prior active rollout for the same
 * (policy_id, environment) pair. Canary rollouts coexist with the active rollout.
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

    const strategy = body.strategy || 'immediate';
    if (!['immediate', 'canary'].includes(strategy)) {
      return epProblem(400, 'invalid_strategy', 'strategy must be "immediate" or "canary"');
    }

    if (strategy === 'canary') {
      const pct = body.canary_pct;
      if (pct == null || typeof pct !== 'number' || pct < 1 || pct > 99) {
        return epProblem(400, 'invalid_canary_pct', 'canary_pct must be an integer between 1 and 99');
      }
    }

    const supabase = getGuardedClient();

    // Verify the policy and version exist.
    const { data: version, error: vErr } = await supabase
      .from('policy_versions')
      .select('*')
      .eq('tenant_id', auth.tenantId)
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

    const now = new Date().toISOString();

    // For immediate rollouts, supersede any currently active rollout for this
    // (policy_id, environment) combination. Canary rollouts coexist.
    if (strategy === 'immediate') {
      await supabase
        .from('policy_rollouts')
        .update({ status: 'superseded', completed_at: now })
        .eq('tenant_id', auth.tenantId)
        .eq('policy_id', policyId)
        .eq('environment', body.environment)
        .eq('status', 'active');
    }

    const { data: rollout, error: insertErr } = await supabase
      .from('policy_rollouts')
      .insert({
        policy_id: policyId,
        version: body.version,
        environment: body.environment,
        strategy,
        status: 'active',
        initiated_by: auth.operatorId || auth.principalId || 'unknown',
        tenant_id: auth.tenantId || null,
        canary_pct: strategy === 'canary' ? body.canary_pct : null,
        initiated_at: now,
        metadata: body.metadata || {},
      })
      .select()
      .single();

    if (insertErr) {
      logger.error('[cloud/policies/rollout] Insert error:', insertErr);
      return epProblem(500, 'rollout_insert_failed', insertErr.message);
    }

    return NextResponse.json({
      rollout_id: rollout.rollout_id,
      policy_id: policyId,
      version: body.version,
      environment: body.environment,
      strategy,
      status: 'active',
      canary_pct: rollout.canary_pct ?? null,
      initiated_at: now,
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
