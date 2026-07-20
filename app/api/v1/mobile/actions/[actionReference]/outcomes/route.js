// SPDX-License-Identifier: Apache-2.0
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

export async function POST(request, context) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Outcome requests require application/json');
    }
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many outcome requests');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(/** @type {any} */ (auth), 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const entityRef = authEntityId(auth);
    const limit = await checkRateLimit(entityRef, 'protocol_write');
    if (!limit.allowed) return mobileProblem(429, 'rate_limited', 'Too many outcome requests');
    const parsed = await readLimitedJson(request, 256 * 1024, { invalidValue: null });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || !Object.keys(parsed.value).every((key) => MEMBERS.has(key))
        || !OPERATION_ID.test(parsed.value.operation_id || '')
        || !['indeterminate', 'reconcile'].includes(parsed.value.state)) {
      return mobileProblem(400, 'invalid_outcome', 'Outcome request is malformed');
    }
    const { actionReference } = await context.params;
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
      const result = await markMobileActionIndeterminate(supabase, {
        entityRef,
        operationId: operation.operation_id,
      });
      if (result.ok !== true) {
        return mobileProblem(409, result.reason || 'outcome_refused', 'Outcome transition was refused');
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
      return mobileProblem(
        result.reason === 'already_terminal' ? 409 : 422,
        result.reason || 'reconciliation_refused',
        'Provider evidence did not prove an exact terminal outcome',
      );
    }
    return mobileJson(result, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] action outcome failed', error);
    return mobileProblem(503, 'mobile_outcome_unavailable', 'Mobile action outcome service unavailable');
  }
}
