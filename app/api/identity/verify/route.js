import { NextResponse } from 'next/server';
import { authenticateOperator } from '@/lib/operator-auth';
import { hasPermission } from '@/lib/procedural-justice';
import { verifyBinding } from '@/lib/ep-ix';
import { EP_ERRORS, epProblem, epDbError } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 10 * 1024;

/**
 * POST /api/identity/verify
 *
 * @operator
 * @access operator — host-verifier action. Flipping a PENDING identity binding
 *   to `verified` is the `binding.verify` permission
 *   (OPERATOR_ROLES.host_verifier). Requires a NAMED per-operator token; the
 *   anonymous shared cron secret is refused (requireOperatorIdentity). NOT
 *   public: an authenticated ENTITY must never be able to flip an arbitrary
 *   pending binding to verified by supplying its binding_id (IDOR). If a
 *   legitimate entity self-verify flow is ever needed it belongs on a separate,
 *   ownership-checked route — not here.
 */
export async function POST(request) {
  try {
    // Host-verifier / operator only. Named identity required for the audit trail.
    const opAuth = authenticateOperator(request, { requireOperatorIdentity: true });
    if (!opAuth.valid) return EP_ERRORS.UNAUTHORIZED();
    if (!hasPermission(opAuth.role, 'binding.verify')) {
      return epProblem(403, 'forbidden', 'Operator role lacks binding.verify permission');
    }

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.binding_id) return EP_ERRORS.BAD_REQUEST('binding_id is required');

    const result = await verifyBinding(body.binding_id, opAuth.operator_id);
    if (result.error) {
      if ((result.status || 500) >= 500) return epDbError(result.status || 500, 'identity_verify_failed', result.error, 'identity/verify');
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Identity verify error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
