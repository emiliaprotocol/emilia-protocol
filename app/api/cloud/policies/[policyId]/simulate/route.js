import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../../lib/logger.js';

/**
 * POST /api/cloud/policies/[policyId]/simulate
 *
 * Simulate a policy against a test scenario without applying it.
 * Requires: write permission.
 *
 * Body: { scenario: { ... } }
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const { policyId } = await params;
    const body = await request.json();

    if (!body.scenario) {
      return epProblem(400, 'missing_scenario', 'Request body must include a "scenario" object');
    }

    const supabase = getGuardedClient();

    // Fetch the current policy
    const { data: policy, error } = await supabase
      .from('policies')
      .select('*')
      .eq('id', policyId)
      .maybeSingle();

    if (error) {
      logger.error('[cloud/policies/simulate] Query error:', error);
      return epProblem(500, 'policy_query_failed', error.message);
    }

    if (!policy) {
      return EP_ERRORS.NOT_FOUND('Policy');
    }

    // Simulation is a dry-run evaluation of the policy rules against the scenario.
    // The actual simulation logic depends on the policy engine; here we return
    // the policy and scenario for the caller to evaluate.
    return NextResponse.json({
      policy_id: policyId,
      policy_type: policy.type || policy.policy_type,
      scenario: body.scenario,
      result: {
        simulated: true,
        policy_rules: policy.rules || policy.config || {},
        evaluated_at: new Date().toISOString(),
      },
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/policies/simulate] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
