import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { readEpJson } from '@/lib/http/route-body';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { logger } from '@/lib/logger';

const MAX_BODY_BYTES = 16 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function POST(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'admin');
    if (auth.environment !== 'production') {
      return epProblem(
        403,
        'production_authority_key_required',
        'Tenant-wide rollout authority may be administered only by a production-scoped key',
      );
    }
    if (!auth.keyId) {
      return epProblem(403, 'cloud_key_identity_required', 'Authority administration requires an attributable cloud API key');
    }

    const { authorityId } = await params;
    if (!UUID_RE.test(authorityId || '')) {
      return epProblem(400, 'invalid_authority_id', 'authorityId must be a UUID');
    }

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const reason = typeof parsed.value?.reason === 'string' ? parsed.value.reason.trim() : '';
    if (!reason || reason.length > 1000) {
      return epProblem(400, 'invalid_authority_reason', 'reason is required and must be at most 1000 characters');
    }

    const supabase = getGuardedClient();
    const { data, error } = await supabase.rpc('revoke_policy_rollout_authority', {
      p_tenant_id: auth.tenantId,
      p_authority_id: authorityId,
      p_revoked_by: `key:${auth.keyId}`,
      p_reason: reason,
    });

    if (error) {
      const context = `${error.message || ''} ${error.details || ''}`;
      if (context.includes('policy_rollout_authority_not_found') || error.code === 'P0002') {
        return EP_ERRORS.NOT_FOUND('Policy rollout authority');
      }
      if (context.includes('policy_rollout_authority_already_revoked') || error.code === '23505') {
        return epProblem(409, 'policy_rollout_authority_already_revoked', 'The policy-rollout authority is already revoked');
      }
      if (context.includes('invalid_policy_rollout_authority_revoke')) {
        return epProblem(400, 'invalid_policy_rollout_authority_revoke', 'The authority revocation parameters are invalid');
      }
      return epDbError(500, 'policy_rollout_authority_revoke_failed', error, 'cloud/authorities/policy-rollout/revoke');
    }

    return NextResponse.json({ authority: data, tenant_id: auth.tenantId });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/authorities/policy-rollout/revoke] POST error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
