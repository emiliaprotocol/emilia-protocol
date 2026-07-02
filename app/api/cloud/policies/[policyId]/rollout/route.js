import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { loadPolicyById } from '@/lib/handshake/policy';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

/**
 * POST /api/cloud/policies/[policyId]/rollout
 *
 * Initiate a rollout of a policy version to the specified environment.
 * Requires: admin permission (deployment-level action).
 *
 * Body:
 *   version     {number}  — policy version number (must exist in handshake_policies
 *                           for this policy's policy_key)
 *   environment {string}  — target environment (e.g. "production", "staging")
 *   strategy    {'immediate'|'canary'}  — default: 'immediate'
 *   canary_pct  {number}  — traffic % for canary rollouts (1–99, required if canary)
 *   metadata    {object}  — optional operator-supplied context
 *
 * Versions live in handshake_policies (UNIQUE(policy_key, version)); each version
 * is its own row with its own policy_id. The rollout's policy_id FK points at the
 * specific version row being rolled out so the FK to handshake_policies is satisfied.
 *
 * Immediate rollouts supersede any prior active rollout for the same
 * (policy_key, environment) pair. Canary rollouts coexist with the active rollout.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'admin');

    const { policyId } = await params;
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

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

    // Resolve the route policyId to its policy_key; the version to roll out is
    // the handshake_policies row with this key and body.version.
    const policy = await loadPolicyById(supabase, policyId, { tenantId: auth.tenantId });
    if (!policy) {
      return EP_ERRORS.NOT_FOUND('Policy');
    }

    const { data: versionRow, error: vErr } = await supabase
      .from('handshake_policies')
      .select('policy_id, policy_key, version')
      .eq('tenant_id', auth.tenantId)
      .eq('policy_key', policy.policy_key)
      .eq('version', body.version)
      .maybeSingle();

    if (vErr) {
      logger.error('[cloud/policies/rollout] Version query error:', vErr);
      return epDbError(500, 'rollout_query_failed', vErr, 'cloud/policies/rollout');
    }

    if (!versionRow) {
      return epProblem(404, 'version_not_found', `Policy version ${body.version} not found`);
    }

    const now = new Date().toISOString();

    // For immediate rollouts, supersede any currently active rollout for this
    // (policy_key, environment) combination. Because each version is its own
    // handshake_policies row (its own policy_id), an "active rollout for this
    // policy" spans every version row sharing the policy_key — so we collect
    // those IDs and supersede across all of them. Canary rollouts coexist.
    if (strategy === 'immediate') {
      const { data: keyVersions, error: keyErr } = await supabase
        .from('handshake_policies')
        .select('policy_id')
        .eq('tenant_id', auth.tenantId)
        .eq('policy_key', policy.policy_key);

      if (keyErr) {
        logger.error('[cloud/policies/rollout] Key version query error:', keyErr);
        return epDbError(500, 'rollout_query_failed', keyErr, 'cloud/policies/rollout');
      }

      const keyPolicyIds = (keyVersions || []).map((r) => r.policy_id);

      await supabase
        .from('policy_rollouts')
        .update({ status: 'superseded', completed_at: now })
        .eq('tenant_id', auth.tenantId)
        .in('policy_id', keyPolicyIds)
        .eq('environment', body.environment)
        .eq('status', 'active');
    }

    const { data: rollout, error: insertErr } = await supabase
      .from('policy_rollouts')
      .insert({
        policy_id: versionRow.policy_id,
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
      return epDbError(500, 'rollout_insert_failed', insertErr, 'cloud/policies/rollout');
    }

    return NextResponse.json({
      rollout_id: rollout.rollout_id,
      policy_id: versionRow.policy_id,
      policy_key: policy.policy_key,
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
