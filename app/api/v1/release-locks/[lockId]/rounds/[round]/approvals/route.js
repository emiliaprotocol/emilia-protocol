// SPDX-License-Identifier: Apache-2.0

import {
  readReleaseLockJson,
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
    const result = await getReleaseLockService().approve({
      rawSessionToken: releaseLockSessionCookie(request, lockId),
      lockId,
      round: releaseLockRound(values.round),
      input: await readReleaseLockJson(request),
    });
    return releaseLockJson(result);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
