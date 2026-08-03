// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { hasApiPermission } from '@/lib/auth-permissions.js';
import { checkMemberRole, panicTenant } from '@/lib/cloud/tenant-manager.js';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '@/lib/logger.js';

const MAX_BODY_BYTES = 8 * 1024;

/** POST /api/cloud/tenants/{tenantId}/panic — irreversible receipt cut-off. */
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenantId: string }> },
) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    if (!hasApiPermission(auth, 'admin')) {
      return epProblem(403, 'admin_permission_required', 'Tenant panic requires an admin-capable EP API key');
    }
    const actorId = authEntityId(auth);
    if (!actorId) return EP_ERRORS.FORBIDDEN('Authenticated entity identity is required');
    const { tenantId } = await params;
    const membership = await checkMemberRole(tenantId, actorId, 'admin');
    if (!membership.authorized) {
      return epProblem(403, 'tenant_admin_required', 'Only a tenant owner or admin may trigger the panic control');
    }
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;
    const expected = `SUSPEND ${tenantId}`;
    if (body?.confirmation !== expected) {
      return epProblem(400, 'panic_confirmation_required', `confirmation must be exactly ${expected}`);
    }
    const reason = typeof body?.reason === 'string' ? body.reason.trim() : '';
    if (reason.length < 3 || reason.length > 500) {
      return epProblem(400, 'panic_reason_required', 'reason must contain 3 through 500 characters');
    }
    const result = await panicTenant(tenantId, `entity:${actorId}`, reason);
    if ('error' in result) return epProblem(result.status || 500, 'tenant_panic_failed', result.error);
    return NextResponse.json(result.control, {
      status: 200,
      headers: { 'cache-control': 'no-store' },
    });
  } catch (error) {
    logger.error('[cloud/tenant-panic] error:', error);
    return EP_ERRORS.INTERNAL();
  }
}
