// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import {
  authenticateReleaseLockOrg,
  readReleaseLockJson,
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ lockId: string }> },
): Promise<NextResponse> {
  try {
    const { lockId: rawLockId } = await params;
    const lockId = releaseLockId(rawLockId);
    const body = await readReleaseLockJson(request);
    const { expected_version: expectedVersion, ...changeOrder } = body;
    const caller = await authenticateReleaseLockOrg(
      request,
      changeOrder.organization_id as string | undefined,
      { requiredPermission: 'write' },
    );
    // getReleaseLockService()'s lazily-initialized singleton return type is
    // not yet resolvable from lib/release-lock/runtime.ts's own inference, so
    // TS can't see that it always returns the real service before this call
    // runs. Cast at this exact access point to the one method this route
    // calls, rather than fighting that module's own inference.
    const service = getReleaseLockService() as unknown as { amendLock: (input: Record<string, any>) => Promise<any> };
    const result = await service.amendLock({
      organizationId: caller.organizationId,
      contractorEntityId: caller.entityId,
      lockId,
      expectedVersion,
      input: changeOrder,
    });
    return releaseLockJson(result, 201);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
