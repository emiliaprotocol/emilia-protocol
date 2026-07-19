// SPDX-License-Identifier: Apache-2.0

import {
  authenticateReleaseLockOrg,
  readReleaseLockJson,
  releaseLockJson,
  releaseLockProblem,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request) {
  try {
    const body = await readReleaseLockJson(request);
    const caller = await authenticateReleaseLockOrg(
      request,
      body.organization_id,
      { requiredPermission: 'write' },
    );
    const result = await getReleaseLockService().createLock({
      organizationId: caller.organizationId,
      contractorEntityId: caller.entityId,
      input: body,
    });
    return releaseLockJson(result, 201);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
