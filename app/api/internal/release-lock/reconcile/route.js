// SPDX-License-Identifier: Apache-2.0

import { authenticateOperator } from '@/lib/operator-auth.js';
import { hasPermission } from '@/lib/procedural-justice.js';
import {
  readReleaseLockJson,
  releaseLockJson,
  releaseLockProblem,
} from '@/lib/release-lock/http.js';
import { releaseLockRefusal } from '@/lib/release-lock/errors.js';
import { getReleaseLockService } from '@/lib/release-lock/runtime.js';

export async function POST(request) {
  try {
    /** @type {{ valid: boolean, operator_id?: string, role?: string|null, error?: string }} */
    const operator = authenticateOperator(request, {
      requireOperatorIdentity: true,
    });
    if (!operator.valid) {
      throw releaseLockRefusal(
        401,
        'operator_unauthorized',
        'Named operator authentication is required.',
      );
    }
    if (!hasPermission(operator.role, 'release_lock.reconcile')) {
      throw releaseLockRefusal(
        403,
        'operator_forbidden',
        'This named operator role cannot reconcile Release Lock effects.',
      );
    }
    const body = await readReleaseLockJson(request);
    if (Object.keys(body).length !== 1
        || typeof body.effect_reference !== 'string') {
      throw releaseLockRefusal(
        400,
        'invalid_request',
        'effect_reference is required.',
      );
    }
    const result = await getReleaseLockService().reconcile({
      effectReference: body.effect_reference,
    });
    return releaseLockJson(result);
  } catch (error) {
    return releaseLockProblem(error);
  }
}
