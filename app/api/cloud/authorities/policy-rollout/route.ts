import { NextRequest, NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { readEpJson } from '@/lib/http/route-body';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { logger } from '@/lib/logger';

const MAX_BODY_BYTES = 16 * 1024;
const ALLOWED_ROLES = new Set(['policy_admin', 'control_plane_approver']);
const MAX_GRANT_MS = 366 * 24 * 60 * 60 * 1000;

function validateGrant(body: any) {
  const approverId = typeof body?.approver_id === 'string' ? body.approver_id.trim() : '';
  const role = typeof body?.role === 'string' ? body.role : '';
  const reason = typeof body?.reason === 'string' ? body.reason.trim() : '';
  const validToMs = Date.parse(body?.valid_to);
  const now = Date.now();

  if (!approverId || approverId.length > 255) {
    return { error: epProblem(400, 'invalid_approver_id', 'approver_id is required and must be at most 255 characters') };
  }
  if (!ALLOWED_ROLES.has(role)) {
    return { error: epProblem(400, 'invalid_authority_role', 'role must be policy_admin or control_plane_approver') };
  }
  if (!reason || reason.length > 1000) {
    return { error: epProblem(400, 'invalid_authority_reason', 'reason is required and must be at most 1000 characters') };
  }
  if (!Number.isFinite(validToMs) || validToMs <= now || validToMs > now + MAX_GRANT_MS) {
    return { error: epProblem(400, 'invalid_authority_validity', 'valid_to must be in the future and no more than 366 days away') };
  }

  return {
    value: {
      approverId,
      role,
      reason,
      validTo: new Date(validToMs).toISOString(),
    },
  };
}

/**
 * GET /api/cloud/authorities/policy-rollout
 *
 * Tenant-admin preflight: list the currently usable authorities that can
 * approve a policy rollout. This is intentionally tenant-scoped and excludes
 * expired or revoked grants.
 */
export async function GET(request: NextRequest) {
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

    const now = new Date().toISOString();
    const supabase = getGuardedClient();
    const { data, error } = await supabase
      .from('authorities')
      .select('authority_id, subject_ref, role, assurance_class, action_scopes, valid_from, valid_to, status, created_at')
      .eq('organization_id', auth.tenantId)
      .eq('subject_type', 'human_approver')
      .eq('assurance_class', 'A')
      .eq('status', 'active')
      .is('revoked_at', null)
      .lte('valid_from', now)
      .or(`valid_to.is.null,valid_to.gt.${now}`)
      .contains('action_scopes', ['policy_rollout'])
      .in('role', ['policy_admin', 'control_plane_approver'])
      .order('valid_from', { ascending: false });

    if (error) {
      return epDbError(500, 'policy_rollout_authority_query_failed', error, 'cloud/authorities/policy-rollout');
    }

    const authorities = data || [];
    return NextResponse.json({
      tenant_id: auth.tenantId,
      ready: authorities.length > 0,
      authorities,
      count: authorities.length,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/authorities/policy-rollout] GET error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

/**
 * POST /api/cloud/authorities/policy-rollout
 *
 * Grant a Class-A enrolled approver the narrowly scoped policy_rollout
 * authority. The database function verifies the credential and writes the
 * grant plus append-only audit event atomically.
 */
export async function POST(request: NextRequest) {
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

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const validated = validateGrant(parsed.value);
    if (validated.error) return validated.error;

    const { approverId, role, reason, validTo } = validated.value;
    const supabase = getGuardedClient();
    const { data, error } = await supabase.rpc('grant_policy_rollout_authority', {
      p_tenant_id: auth.tenantId,
      p_approver_id: approverId,
      p_role: role,
      p_valid_to: validTo,
      p_granted_by: `key:${auth.keyId}`,
      p_reason: reason,
    });

    if (error) {
      const context = `${error.message || ''} ${error.details || ''}`;
      if (context.includes('policy_rollout_class_a_credential_required')) {
        return epProblem(409, 'class_a_credential_required', 'The approver must have an active Class-A credential before authority can be granted');
      }
      if (context.includes('policy_rollout_authority_already_active') || error.code === '23505') {
        return epProblem(409, 'policy_rollout_authority_exists', 'This approver already has an active policy-rollout authority for that role');
      }
      if (context.includes('invalid_policy_rollout_authority_grant')) {
        return epProblem(400, 'invalid_policy_rollout_authority_grant', 'The authority grant parameters are invalid');
      }
      return epDbError(500, 'policy_rollout_authority_grant_failed', error, 'cloud/authorities/policy-rollout');
    }

    return NextResponse.json({ authority: data, tenant_id: auth.tenantId }, { status: 201 });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/authorities/policy-rollout] POST error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
