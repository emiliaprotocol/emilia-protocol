// SPDX-License-Identifier: Apache-2.0
import { getGuardedClient } from '@/lib/write-guard.js';
import { authenticateMobileToken, listMobileActions } from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { mobileActionView } from '@/lib/mobile/action-view.js';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile inbox requests');
    const supabase = getGuardedClient();
    const session = await authenticateMobileToken(supabase, request.headers.get('authorization'));
    if (!session) return mobileProblem(401, 'unauthorized', 'A valid paired mobile session is required');
    const sessionLimit = await checkRateLimit(`session:${session.session_id}`, 'read');
    if (!sessionLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile inbox requests');
    const actions = await listMobileActions(supabase, {
      entityRef: session.entity_ref,
      approverId: session.approver_id,
    });
    return mobileJson({
      approver_id: session.approver_id,
      actions: actions.map((item) => mobileActionView(item)),
    }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] inbox failed', error);
    return mobileProblem(503, 'mobile_inbox_unavailable', 'Mobile approval inbox unavailable');
  }
}
