// SPDX-License-Identifier: Apache-2.0

import {
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
  releaseLockSessionCookie,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request, { params }) {
  try {
    const { lockId: rawLockId } = await params;
    const lockId = releaseLockId(rawLockId);
    const result = await getReleaseLockService().beginRegistration({
      rawSessionToken: releaseLockSessionCookie(request, lockId),
      lockId,
    });
    return releaseLockJson(result, 201);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
