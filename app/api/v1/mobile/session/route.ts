// SPDX-License-Identifier: Apache-2.0
import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard.js';
import { authenticateMobileToken, revokeMobileSession } from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

export const dynamic = 'force-dynamic';

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  try {
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile session requests');
    const supabase = getGuardedClient();
    const session = await authenticateMobileToken(supabase, request.headers.get('authorization'));
    if (!session) return mobileProblem(401, 'unauthorized', 'A valid paired mobile session is required');
    const sessionLimit = await checkRateLimit(`session:${session.session_id}`, 'mobile_write');
    if (!sessionLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile session requests');
    const revoked = await revokeMobileSession(supabase, {
      sessionId: session.session_id,
      entityRef: session.entity_ref,
    });
    if (!revoked) return mobileProblem(409, 'session_not_active', 'The mobile session is no longer active');
    return mobileJson({ ok: true, revoked: true }, {
      headers: { 'cache-control': 'no-store' },
    });
  } catch (error) {
    logger.error('[mobile] session revocation failed', error);
    return mobileProblem(503, 'mobile_session_unavailable', 'Mobile session revocation unavailable');
  }
}
