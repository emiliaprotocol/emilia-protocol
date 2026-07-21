// SPDX-License-Identifier: Apache-2.0
import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import {
  markMobileActionIndeterminate,
  reconcileMobileActionOperation,
  resolveMobileOperation,
} from '@/lib/mobile/store.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;
const OPERATION_ID = /^[A-Za-z0-9:_.@/-]{8,256}$/;
const MEMBERS = new Set(['operation_id', 'state', 'evidence']);

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ actionReference: string }> },
): Promise<NextResponse> {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Outcome requests require application/json');
    }
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many outcome requests');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try {
      requirePermission(auth as any, 'write');
    } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const entityRef = authEntityId(auth as any);
    const limit = await checkRateLimit(entityRef, 'protocol_write');
    if (!limit.allowed) return mobileProblem(429, 'rate_limited', 'Too many outcome requests');
    // readLimitedJson's inferred parameter/return types don't yet reflect its
    // documented contract (JSDoc @returns above its definition in
    // lib/http/body-limit.ts) — cast at this call site rather than fight the
    // inference the compiler currently derives from the untyped destructure.
    const parsed = await readLimitedJson(request, 256 * 1024, { invalidValue: null } as any) as
      | { ok: true; value: any }
      | { ok: false; status: number; code: string; detail: string };
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || !Object.keys(parsed.value).every((key) => MEMBERS.has(key))
        || !OPERATION_ID.test(parsed.value.operation_id || '')
        || !['indeterminate', 'reconcile'].includes(parsed.value.state)) {
      return mobileProblem(400, 'invalid_outcome', 'Outcome request is malformed');
    }
    const { actionReference } = await params;
    if (!ACTION_REFERENCE.test(actionReference || '')) {
      return mobileProblem(400, 'invalid_action_reference', 'Action reference is malformed');
    }
    const supabase = getGuardedClient();
    const operation = await resolveMobileOperation(supabase, {
      entityRef,
      operationId: parsed.value.operation_id,
      actionReference,
    });
    if (!operation) return mobileProblem(404, 'operation_not_found', 'Action operation was not found');

    if (parsed.value.state === 'indeterminate') {
      if (parsed.value.evidence !== undefined) {
        return mobileProblem(400, 'invalid_outcome', 'Indeterminate timeout reports do not accept provider evidence');
      }
      // operation is Json (Record<string, unknown>) from resolveMobileOperation
      // — operation_id is genuinely dynamic RPC-sourced data.
      const result = await markMobileActionIndeterminate(supabase, {
        entityRef,
        operationId: operation.operation_id as string,
      });
      if (result.ok !== true) {
        const reason = result.reason as string;
        return mobileProblem(409, reason || 'outcome_refused', 'Outcome transition was refused');
      }
      return mobileJson(result, { headers: { 'cache-control': 'no-store' } });
    }

    if (!parsed.value.evidence || typeof parsed.value.evidence !== 'object'
        || Array.isArray(parsed.value.evidence)) {
      return mobileProblem(
        400,
        'missing_provider_evidence',
        'Authenticated, action-bound provider evidence is required for reconciliation',
      );
    }
    const result = await reconcileMobileActionOperation(supabase, {
      entityRef,
      operation,
      evidence: parsed.value.evidence,
    });
    if (result.ok !== true) {
      // reconcileMobileActionOperation returns Json (Record<string, unknown>) —
      // reason is genuinely dynamic RPC-sourced data.
      const reason = result.reason as string;
      return mobileProblem(
        reason === 'already_terminal' ? 409 : 422,
        reason || 'reconciliation_refused',
        'Provider evidence did not prove an exact terminal outcome',
      );
    }
    return mobileJson(result, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] action outcome failed', error);
    return mobileProblem(503, 'mobile_outcome_unavailable', 'Mobile action outcome service unavailable');
  }
}
