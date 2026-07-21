// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import {
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
  releaseLockSessionCookie,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ lockId: string }> },
): Promise<NextResponse> {
  try {
    const { lockId: rawLockId } = await params;
    const lockId = releaseLockId(rawLockId);
    const result = await getReleaseLockService().participantEvidence({
      rawSessionToken: releaseLockSessionCookie(request, lockId),
      lockId,
    });
    return releaseLockJson(result);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
