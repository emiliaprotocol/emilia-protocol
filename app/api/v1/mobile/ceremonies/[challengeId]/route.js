// SPDX-License-Identifier: Apache-2.0
import { getGuardedClient } from '@/lib/write-guard.js';
import {
  authenticateMobileToken,
  lookupMobileCeremonyResult,
} from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const CHALLENGE_ID = /^[A-Za-z0-9:_.@-]{8,256}$/;
const UNKNOWN = Object.freeze({ committed: false, outcome: 'unknown', result: null });

export async function GET(request, { params }) {
  try {
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) {
      return mobileProblem(429, 'rate_limited', 'Too many mobile ceremony result requests');
    }

    const supabase = getGuardedClient();
    const session = await authenticateMobileToken(supabase, request.headers.get('authorization'));
    if (!session) return mobileProblem(401, 'unauthorized', 'A valid paired mobile session is required');

    const sessionLimit = await checkRateLimit(`session:${session.session_id}`, 'read');
    if (!sessionLimit.allowed) {
      return mobileProblem(429, 'rate_limited', 'Too many mobile ceremony result requests');
    }

    const { challengeId } = await params;
    if (typeof challengeId !== 'string' || !CHALLENGE_ID.test(challengeId)) {
      return mobileJson(UNKNOWN);
    }
    const result = await lookupMobileCeremonyResult(supabase, {
      entityRef: session.entity_ref,
      sessionId: session.session_id,
      approverId: session.approver_id,
      platform: session.platform,
      appId: session.app_id,
      deviceKeyId: session.device_key_id,
      challengeId,
    });
    return mobileJson(result ? {
      committed: true,
      outcome: 'committed',
      result,
    } : UNKNOWN);
  } catch (error) {
    logger.error('[mobile] ceremony result lookup failed', error);
    return mobileProblem(
      503,
      'mobile_ceremony_result_unavailable',
      'Mobile ceremony result unavailable',
    );
  }
}
