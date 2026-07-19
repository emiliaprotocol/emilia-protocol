// SPDX-License-Identifier: Apache-2.0

import {
  authenticateReleaseLockOrg,
  readReleaseLockJson,
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request, { params }) {
  try {
    const { lockId: rawLockId } = await params;
    const lockId = releaseLockId(rawLockId);
    const body = await readReleaseLockJson(request);
    const caller = await authenticateReleaseLockOrg(
      request,
      body.organization_id,
      { requiredPermission: 'write' },
    );
    const result = await getReleaseLockService().stageDraw({
      organizationId: caller.organizationId,
      contractorEntityId: caller.entityId,
      lockId,
      input: body,
    });
    return releaseLockJson(result, 201);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
