// SPDX-License-Identifier: Apache-2.0
import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard.js';
import { authenticateMobileToken, withdrawMobileAction } from '@/lib/mobile/store.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;
const MAX_BODY_BYTES = 1024;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ actionReference: string }> },
): Promise<NextResponse> {
  try {
    const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!networkLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many withdrawal requests');
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Withdrawal requests require application/json');
    }
    const supabase = getGuardedClient();
    const session = await authenticateMobileToken(supabase, request.headers.get('authorization'));
    if (!session) return mobileProblem(401, 'unauthorized', 'A valid paired mobile session is required');
    const sessionLimit = await checkRateLimit(`session:${session.session_id}`, 'mobile_write');
    if (!sessionLimit.allowed) return mobileProblem(429, 'rate_limited', 'Too many withdrawal requests');
    // readLimitedJson's inferred parameter/return types don't yet reflect its
    // documented contract (JSDoc @returns above its definition in
    // lib/http/body-limit.ts) — cast at this call site rather than fight the
    // inference the compiler currently derives from the untyped destructure.
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: null } as any) as
      | { ok: true; value: any }
      | { ok: false; status: number; code: string; detail: string };
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || Object.keys(parsed.value).length !== 0) {
      return mobileProblem(400, 'invalid_withdrawal', 'Withdrawal request must be an empty JSON object');
    }
    const { actionReference } = await params;
    if (!ACTION_REFERENCE.test(actionReference || '')) {
      return mobileProblem(400, 'invalid_action_reference', 'Action reference is malformed');
    }
    const result = await withdrawMobileAction(supabase, {
      entityRef: session.entity_ref,
      sessionId: session.session_id,
      actionReference,
    });
    if (result.ok !== true) {
      // withdrawMobileAction returns Json (Record<string, unknown>) — reason is
      // genuinely dynamic RPC-sourced data.
      const reason = result.reason as string;
      const consumed = reason === 'already_consumed';
      return mobileProblem(
        consumed ? 409 : 422,
        reason || 'withdrawal_refused',
        consumed
          ? 'Execution authority has already been consumed; the approval cannot be withdrawn'
          : 'This approval is not withdrawable',
      );
    }
    return mobileJson({ withdrawn: true, state: (result.state as string) || 'withdrawn' }, {
      headers: { 'cache-control': 'no-store' },
    });
  } catch (error) {
    logger.error('[mobile] withdrawal failed', error);
    return mobileProblem(503, 'mobile_withdrawal_unavailable', 'Mobile approval withdrawal unavailable');
  }
}
