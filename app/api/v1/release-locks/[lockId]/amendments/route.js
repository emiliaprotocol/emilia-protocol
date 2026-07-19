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
    const { expected_version: expectedVersion, ...changeOrder } = body;
    const caller = await authenticateReleaseLockOrg(
      request,
      changeOrder.organization_id,
      { requiredPermission: 'write' },
    );
    const result = await getReleaseLockService().amendLock({
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
