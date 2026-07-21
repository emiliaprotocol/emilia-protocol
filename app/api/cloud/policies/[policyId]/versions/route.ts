import { NextResponse, NextRequest } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { loadPolicyById } from '@/lib/handshake/policy';
import { logger } from '../../../../../../lib/logger.js';

/**
 * GET /api/cloud/policies/[policyId]/versions
 *
 * List all versions of a policy. A policy's "versions" are every
 * handshake_policies row that shares the same policy_key as the row
 * identified by policyId. Ordered newest-first by version.
 *
 * Requires: read permission.
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ policyId: string }> }
) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const { policyId } = await params;
    const supabase = getGuardedClient();

    // Resolve the route policyId to its policy_key. Versions are keyed by
    // policy_key in handshake_policies (UNIQUE(policy_key, version)).
    const policy = await loadPolicyById(supabase, policyId, { tenantId: auth.tenantId });
    if (!policy) {
      return EP_ERRORS.NOT_FOUND('Policy');
    }

    // Tenant-scoped exactly like the simulate route (eq tenant_id).
    const { data: versions, error } = await supabase
      .from('handshake_policies')
      .select('policy_id, policy_key, version, name, mode, status, rules, created_at, updated_at')
      .eq('tenant_id', auth.tenantId)
      .eq('policy_key', policy.policy_key)
      .order('version', { ascending: false });

    if (error) {
      logger.error('[cloud/policies/versions] Query error:', error);
      return epDbError(500, 'policy_versions_query_failed', error, 'cloud/policies/versions');
    }

    return NextResponse.json({
      policy_id: policyId,
      policy_key: policy.policy_key,
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
