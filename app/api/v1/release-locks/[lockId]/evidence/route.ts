// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import {
  authenticateReleaseLockOrg,
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ lockId: string }> },
): Promise<NextResponse> {
  try {
    const { lockId: rawLockId } = await params;
    const caller = await authenticateReleaseLockOrg(
      request,
      undefined,
      { requiredPermission: 'read' },
    );
    const result = await getReleaseLockService().evidence({
      organizationId: caller.organizationId,
      lockId: releaseLockId(rawLockId),
    });
    return releaseLockJson(result);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
