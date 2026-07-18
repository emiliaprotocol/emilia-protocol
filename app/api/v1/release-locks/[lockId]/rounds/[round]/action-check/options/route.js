// SPDX-License-Identifier: Apache-2.0

import {
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
  releaseLockRound,
  releaseLockSessionCookie,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request, { params }) {
  try {
    const values = await params;
    const lockId = releaseLockId(values.lockId);
    const result = await getReleaseLockService().actionCheckOptions({
      rawSessionToken: releaseLockSessionCookie(request, lockId),
      lockId,
      round: releaseLockRound(values.round),
    });
    return releaseLockJson(result, 201);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
