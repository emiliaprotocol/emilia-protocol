// SPDX-License-Identifier: Apache-2.0
import { getGuardedClient } from '@/lib/write-guard.js';
import { authenticateMobileToken, listMobileActionHistory } from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;

export const dynamic = 'force-dynamic';

export async function GET(request, context) {
  try {
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many passport requests');
    const supabase = getGuardedClient();
    const session = await authenticateMobileToken(supabase, request.headers.get('authorization'));
    if (!session) return mobileProblem(401, 'unauthorized', 'A valid paired mobile session is required');
    const sessionLimit = await checkRateLimit(`session:${session.session_id}`, 'read');
    if (!sessionLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many passport requests');
    const { actionReference } = await context.params;
    if (!ACTION_REFERENCE.test(actionReference || '')) {
      return mobileProblem(400, 'invalid_action_reference', 'Action reference is malformed');
    }
    const actions = await listMobileActionHistory(supabase, {
      entityRef: session.entity_ref,
      approverId: session.approver_id,
    });
    const selected = actions.find((item) => item.action_reference === actionReference);
    if (!selected?.passport) return mobileProblem(404, 'passport_not_found', 'Decision passport is unavailable');
    return mobileJson({ passport: selected.passport }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] passport failed', error);
    return mobileProblem(503, 'mobile_passport_unavailable', 'Decision passport unavailable');
  }
}
