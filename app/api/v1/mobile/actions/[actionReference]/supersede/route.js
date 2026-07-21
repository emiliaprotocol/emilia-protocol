// SPDX-License-Identifier: Apache-2.0
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { supersedeMobileAction } from '@/lib/mobile/store.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;
const MEMBERS = new Set([
  'assignments', 'initiator_id', 'action', 'presentation', 'policy',
  'policy_id', 'expires_at',
]);

export async function POST(request, context) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Supersession requests require application/json');
    }
    const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many supersession requests');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(/** @type {any} */ (auth), 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const bodyResult = await readLimitedJson(request, 256 * 1024, { invalidValue: null });
    if (!bodyResult.ok) return mobileProblem(bodyResult.status, bodyResult.code, bodyResult.detail);
    const body = bodyResult.value;
    const { actionReference } = await context.params;
    if (!ACTION_REFERENCE.test(actionReference || '') || !body || typeof body !== 'object'
        || Array.isArray(body) || !Object.keys(body).every((key) => MEMBERS.has(key))
        || !Array.isArray(body.assignments) || body.assignments.length === 0
        || typeof body.initiator_id !== 'string'
        || !body.action || typeof body.action !== 'object' || Array.isArray(body.action)
        || !body.presentation || typeof body.presentation !== 'object' || Array.isArray(body.presentation)
        || !body.policy || typeof body.policy !== 'object' || Array.isArray(body.policy)
        || typeof body.policy_id !== 'string'
        || typeof body.expires_at !== 'string' || Date.parse(body.expires_at) <= Date.now()) {
      return mobileProblem(400, 'invalid_supersession', 'Action supersession request is malformed');
    }
    const result = await supersedeMobileAction(getGuardedClient(), {
      entityRef: authEntityId(auth),
      currentActionReference: actionReference,
      assignments: body.assignments,
      initiatorId: body.initiator_id,
      action: body.action,
      presentation: body.presentation,
      policy: body.policy,
      policyId: body.policy_id,
      expiresAt: body.expires_at,
    });
    return mobileJson({
      superseded: true,
      group_id: result.group_id,
      revision: result.revision,
      identity: result.identity,
      changes: result.changes,
    }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    const message = String(error?.message || '');
    if (/already_consumed|conflict|not_found|refused/.test(message)) {
      return mobileProblem(409, 'supersession_refused', 'The action cannot be superseded in its current state');
    }
    logger.error('[mobile] action supersession failed', error);
    return mobileProblem(503, 'mobile_supersession_unavailable', 'Mobile action supersession unavailable');
  }
}
