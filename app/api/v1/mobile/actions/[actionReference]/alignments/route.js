// SPDX-License-Identifier: Apache-2.0
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { recordMobileActionAlignment } from '@/lib/mobile/store.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;
const MEMBERS = new Set([
  'system', 'verdict', 'profile_id', 'profile_hash', 'native_verified',
  'evidence_digest', 'reason',
]);

export async function POST(request, context) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Alignment records require application/json');
    }
    const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many alignment records');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(/** @type {any} */ (auth), 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const parsed = await readLimitedJson(request, 32 * 1024, { invalidValue: null });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    const { actionReference } = await context.params;
    if (!ACTION_REFERENCE.test(actionReference || '') || !body || typeof body !== 'object'
        || Array.isArray(body) || !Object.keys(body).every((key) => MEMBERS.has(key))
        || typeof body.system !== 'string'
        || !['EQUIVALENT_UNDER_PROFILE', 'NOT_EQUIVALENT', 'INDETERMINATE'].includes(body.verdict)
        || (
          body.verdict !== 'INDETERMINATE'
          && !/^sha256:[0-9a-f]{64}$/.test(body.evidence_digest || '')
        )) {
      return mobileProblem(400, 'invalid_alignment', 'Alignment result is malformed');
    }
    const recorded = await recordMobileActionAlignment(getGuardedClient(), {
      entityRef: authEntityId(auth),
      actionReference,
      alignment: body,
    });
    if (!recorded) return mobileProblem(422, 'alignment_refused', 'Alignment result was refused');
    return mobileJson({ recorded: true }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] alignment recording failed', error);
    return mobileProblem(503, 'mobile_alignment_unavailable', 'Mobile action alignment unavailable');
  }
}
