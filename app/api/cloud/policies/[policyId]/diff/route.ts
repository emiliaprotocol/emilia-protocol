import { NextRequest, NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { loadPolicyById } from '@/lib/handshake/policy';
import { diffPolicy } from '@/lib/policy-sdk/diff.js';
import { logger } from '../../../../../../lib/logger.js';

/**
 * GET /api/cloud/policies/[policyId]/diff?v1=...&v2=...
 *
 * Compare two versions of a policy to see what changed. Versions are the
 * handshake_policies rows sharing the policy_key of the row identified by
 * policyId; their `rules` are diffed with the policy-sdk semantic diff.
 *
 * Requires: read permission.
 */
export async function GET(request: NextRequest, { params }: { params: Promise<{ policyId: string }> }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const { policyId } = await params;
    const url = new URL(request.url);
    const v1 = url.searchParams.get('v1');
    const v2 = url.searchParams.get('v2');

    if (!v1 || !v2) {
      return epProblem(400, 'missing_versions', 'Both "v1" and "v2" query parameters are required');
    }

    const supabase = getGuardedClient();

    // Resolve the route policyId to its policy_key; versions are keyed by it.
    const policy = await loadPolicyById(supabase, policyId, { tenantId: auth.tenantId });
    if (!policy) {
      return EP_ERRORS.NOT_FOUND('Policy');
    }

    const { data: versions, error } = await supabase
      .from('handshake_policies')
      .select('policy_id, policy_key, version, name, mode, status, rules, created_at, updated_at')
      .eq('tenant_id', auth.tenantId)
      .eq('policy_key', policy.policy_key)
      .in('version', (() => {
        const n1 = parseInt(v1, 10);
        const n2 = parseInt(v2, 10);
        if (!Number.isInteger(n1) || !Number.isInteger(n2) || n1 < 1 || n2 < 1) {
          return [-1]; // guaranteed no-match — handled by the < 2 check below
        }
        return [n1, n2];
      })());

    if (error) {
      logger.error('[cloud/policies/diff] Query error:', error);
      return epDbError(500, 'policy_diff_query_failed', error, 'cloud/policies/diff');
    }

    if (!versions || versions.length < 2) {
      return epProblem(404, 'versions_not_found', 'One or both versions not found');
    }

    const [version1, version2] = versions.sort((a, b) => a.version - b.version);

    // Semantic diff of the two versions' rules (loosening / tightening / neutral).
    const diff = diffPolicy(version1.rules, version2.rules);

    return NextResponse.json({
      policy_id: policyId,
      policy_key: policy.policy_key,
      v1: version1,
      v2: version2,
      diff,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/policies/diff] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
