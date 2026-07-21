// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import {
  readReleaseLockJson,
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
  requireReleaseLockSameOrigin,
  setReleaseLockSessionCookie,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    requireReleaseLockSameOrigin(request);
    const body = await readReleaseLockJson(request);
    const { rawSessionToken, ...result } = await getReleaseLockService()
      .exchangeInvitation(body);
    const response = releaseLockJson(result);
    return setReleaseLockSessionCookie(
      response,
      rawSessionToken,
      result.session_expires_at,
      releaseLockId(result.lock_id || body.lock_id),
    );
  } catch (error) {
    return releaseLockProblem(error);
  }
}
