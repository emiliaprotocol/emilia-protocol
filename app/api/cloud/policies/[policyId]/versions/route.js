import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../../lib/logger.js';

/**
 * GET /api/cloud/policies/[policyId]/versions
 *
 * List all versions of a policy.
 * Requires: read permission.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const { policyId } = await params;
    const supabase = getGuardedClient();

    const { data: versions, error } = await supabase
      .from('policy_versions')
      .select('*')
      .eq('policy_id', policyId)
      .order('version', { ascending: false });

    if (error) {
      logger.error('[cloud/policies/versions] Query error:', error);
      return epProblem(500, 'policy_versions_query_failed', error.message);
    }

    return NextResponse.json({
      policy_id: policyId,
      versions: versions || [],
      count: (versions || []).length,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/policies/versions] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
