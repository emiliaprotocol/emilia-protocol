import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';

/**
 * GET /api/cloud/policies/[policyId]/diff?v1=...&v2=...
 *
 * Compare two versions of a policy to see what changed.
 * Requires: read permission.
 */
export async function GET(request, { params }) {
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

    const { data: versions, error } = await supabase
      .from('policy_versions')
      .select('*')
      .eq('policy_id', policyId)
      .in('version', [parseInt(v1, 10), parseInt(v2, 10)]);

    if (error) {
      console.error('[cloud/policies/diff] Query error:', error);
      return epProblem(500, 'policy_diff_query_failed', error.message);
    }

    if (!versions || versions.length < 2) {
      return epProblem(404, 'versions_not_found', 'One or both versions not found');
    }

    const [version1, version2] = versions.sort((a, b) => a.version - b.version);

    return NextResponse.json({
      policy_id: policyId,
      v1: version1,
      v2: version2,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    console.error('[cloud/policies/diff] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
