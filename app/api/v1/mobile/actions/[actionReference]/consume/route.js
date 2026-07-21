// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { consumeMobileAction } from '@/lib/mobile/store.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;
const OPERATION_ID = /^[A-Za-z0-9:_.@/-]{8,256}$/;
const EXECUTOR_ID = /^[A-Za-z0-9:_.@/-]{3,256}$/;
const MEMBERS = new Set(['operation_id', 'executor_id']);

export async function POST(request, context) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Consumption requests require application/json');
    }
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many consumption requests');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(/** @type {any} */ (auth), 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const entityRef = authEntityId(auth);
    const limit = await checkRateLimit(entityRef, 'protocol_write');
    if (!limit.allowed) return mobileProblem(429, 'rate_limited', 'Too many consumption requests');
    const parsed = await readLimitedJson(request, 8 * 1024, { invalidValue: null });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || !Object.keys(parsed.value).every((key) => MEMBERS.has(key))) {
      return mobileProblem(400, 'invalid_consumption', 'Consumption request is malformed');
    }
    const { actionReference } = await context.params;
    if (!ACTION_REFERENCE.test(actionReference || '')
        || !OPERATION_ID.test(parsed.value.operation_id || '')
        || !EXECUTOR_ID.test(parsed.value.executor_id || '')) {
      return mobileProblem(400, 'invalid_consumption', 'Action reference, operation ID, or executor ID is malformed');
    }
    const result = await consumeMobileAction(getGuardedClient(), {
      entityRef,
      actionReference,
      operationId: parsed.value.operation_id,
      consumptionNonce: `mconsume_${crypto.randomBytes(24).toString('base64url')}`,
      executorId: parsed.value.executor_id,
    });
    if (result.ok !== true) {
      return mobileProblem(
        ['already_consumed', 'superseded'].includes(result.reason) ? 409 : 422,
        result.reason || 'consumption_refused',
        result.reason === 'already_consumed'
          ? 'Execution authority was already consumed; blind replay is refused'
          : 'Action consumption was refused',
      );
    }
    return mobileJson(result, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] action consumption failed', error);
    return mobileProblem(503, 'mobile_consumption_unavailable', 'Mobile action consumption unavailable');
  }
}
