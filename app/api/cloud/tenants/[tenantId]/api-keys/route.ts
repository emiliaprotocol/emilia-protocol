// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { hasApiPermission } from '@/lib/auth-permissions.js';
import {
  checkMemberRole,
  generateApiKey,
  validateTenantApiKeyPermissions,
} from '@/lib/cloud/tenant-manager.js';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '@/lib/logger.js';

const MAX_BODY_BYTES = 32 * 1024;
const ALLOWED_ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const DEFAULT_ROLLOUT_PERMISSIONS = Object.freeze(['policy_rollout']);
const DEFAULT_EXPIRY_DAYS = 90;
const MAX_EXPIRY_DAYS = 90;

/**
 * POST /api/cloud/tenants/[tenantId]/api-keys
 *
 * Issue a tenant-scoped ept_live_... or ept_test_... API key. The caller must
 * authenticate with an admin-capable EP entity key and be an owner or admin
 * member of the target tenant. The full tenant key is returned exactly once.
 *
 * Body: {
 *   name: string,
 *   environment?: 'development' | 'staging' | 'production',
 *   permissions?: ('read' | 'write' | 'admin' | 'policy_rollout')[],
 *   expires_in_days?: number
 * }
 *
 * The default ['policy_rollout'] grant can orchestrate rollout receipts and
 * activation but cannot administer tenant-wide authority or unrelated cloud
 * surfaces.
 */
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenantId: string }> }
) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    }

    // Credential minting is a privilege boundary. Tenant membership alone is
    // not enough if the authenticating EP key is read/write scoped.
    if (!hasApiPermission(auth, 'admin')) {
      return epProblem(
        403,
        'admin_permission_required',
        'Tenant API-key issuance requires an admin-capable EP API key',
      );
    }

    const userRef = authEntityId(auth);
    if (!userRef) return EP_ERRORS.FORBIDDEN('Authenticated entity identity is required');

    const { tenantId } = await params;
    if (!tenantId) return epProblem(400, 'missing_tenant_id', 'tenantId path parameter is required');

    const membership = await checkMemberRole(tenantId, userRef, 'admin');
    if (!membership.authorized) {
      if (membership.error === 'Failed to check membership') {
        return epProblem(
          503,
          'tenant_membership_unavailable',
          'Tenant membership could not be verified',
        );
      }
      return epProblem(
        403,
        'tenant_admin_required',
        'Only an owner or admin of this tenant may issue tenant API keys',
      );
    }

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    const name = typeof body?.name === 'string' ? body.name.trim() : '';
    if (!name || name.length > 120) {
      return epProblem(
        400,
        'invalid_key_name',
        'name must be a non-empty string no longer than 120 characters',
      );
    }

    const environment = body?.environment ?? 'production';
    if (typeof environment !== 'string' || !ALLOWED_ENVIRONMENTS.has(environment)) {
      return epProblem(
        400,
        'invalid_environment',
        'environment must be development, staging, or production',
      );
    }

    const requestedPermissions = body?.permissions ?? DEFAULT_ROLLOUT_PERMISSIONS;
    const permissionValidation = validateTenantApiKeyPermissions(requestedPermissions);
    if (permissionValidation.error) {
      return epProblem(
        permissionValidation.status,
        'invalid_permissions',
        permissionValidation.error,
      );
    }
    const expiresInDays = body?.expires_in_days === undefined
      ? DEFAULT_EXPIRY_DAYS
      : body.expires_in_days;
    if (!Number.isSafeInteger(expiresInDays)
        || expiresInDays < 1
        || expiresInDays > MAX_EXPIRY_DAYS) {
      return epProblem(
        400,
        'invalid_key_expiry',
        `expires_in_days must be an integer from 1 through ${MAX_EXPIRY_DAYS}`,
      );
    }
    const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString();

    const result = await generateApiKey(
      tenantId,
      environment,
      name,
      permissionValidation.permissions,
      {
        expiresAt,
        issuedBy: `entity:${userRef}`,
      },
    );
    if ('error' in result) {
      return epProblem(
        result.status || 500,
        result.status === 400 ? 'invalid_permissions' : 'tenant_api_key_issue_failed',
        result.error,
      );
    }

    return NextResponse.json({
      api_key: (result as any).api_key,
      tenant_id: tenantId,
      note: 'Store this key now; it is not retrievable after this response.',
    }, {
      status: 201,
      headers: { 'cache-control': 'no-store' },
    });
  } catch (err) {
    logger.error('[cloud/tenant-api-keys] issuance error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
