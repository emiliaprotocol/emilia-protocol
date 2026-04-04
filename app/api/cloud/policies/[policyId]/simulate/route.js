import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { checkClaimsAgainstPolicy, getRequiredPartiesForMode } from '@/lib/handshake/policy';
import { checkAssuranceLevel } from '@/lib/handshake/invariants';
import { logger } from '../../../../../../lib/logger.js';

/**
 * POST /api/cloud/policies/[policyId]/simulate
 *
 * Simulate a policy against a test scenario without applying it.
 * Requires: write permission.
 *
 * Body:
 *   scenario.parties — array of { role, claims, assurance_level }
 *
 * Returns per-role evaluation results: which claims pass/fail, whether
 * assurance is sufficient, and an overall pass/fail decision.
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

    const { data: policy, error } = await supabase
      .from('handshake_policies')
      .select('*')
      .eq('tenant_id', auth.tenantId)
      .eq('policy_id', policyId)
      .maybeSingle();

    if (error) {
      logger.error('[cloud/policies/simulate] Query error:', error);
      return epProblem(500, 'policy_query_failed', error.message);
    }

    if (!policy) {
      return EP_ERRORS.NOT_FOUND('Policy');
    }

    const scenarioParties = Array.isArray(body.scenario.parties) ? body.scenario.parties : [];
    const requiredRoles = getRequiredPartiesForMode(policy);
    const roleResults = {};
    let passed = true;

    for (const role of requiredRoles) {
      const roleReqs = policy.rules?.required_parties?.[role];
      if (!roleReqs) continue;

      const party = scenarioParties.find((p) => p.role === role);
      const claims = party?.claims || {};
      const assuranceLevel = party?.assurance_level || null;

      const claimsResult = checkClaimsAgainstPolicy(claims, roleReqs);

      let assuranceResult = null;
      if (roleReqs.minimum_assurance) {
        assuranceResult = assuranceLevel
          ? checkAssuranceLevel(assuranceLevel, roleReqs.minimum_assurance)
          : { ok: false, code: 'ASSURANCE_BELOW_MINIMUM', message: 'No assurance level provided' };
      }

      const rolePassed = claimsResult.satisfied && (assuranceResult == null || assuranceResult.ok);
      if (!rolePassed) passed = false;

      roleResults[role] = {
        passed: rolePassed,
        claims: claimsResult,
        assurance: assuranceResult,
      };
    }

    return NextResponse.json({
      policy_id: policyId,
      policy_key: policy.policy_key,
      policy_version: policy.version,
      scenario: body.scenario,
      result: {
        passed,
        roles: roleResults,
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
