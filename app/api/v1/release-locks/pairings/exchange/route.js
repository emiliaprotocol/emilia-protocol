// SPDX-License-Identifier: Apache-2.0

import {
  readReleaseLockJson,
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
  requireReleaseLockSameOrigin,
  setReleaseLockSessionCookie,
} from '@/lib/release-lock/http.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request) {
  try {
    requireReleaseLockSameOrigin(request);
    const body = await readReleaseLockJson(request);
    const { rawSessionToken, ...result } = await getReleaseLockService()
      .exchangePairing(body);
    return setReleaseLockSessionCookie(
      releaseLockJson(result),
      rawSessionToken,
      result.session_expires_at,
      releaseLockId(result.lock_id || body.lock_id),
    );
  } catch (error) {
    return releaseLockProblem(error);
  }
}
