import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { issueChallenge } from '@/lib/signoff/challenge';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validateSignoffChallenge } from '@/lib/validation/schemas';

/**
 * POST /api/signoff/challenge
 *
 * Issue a new Accountable Signoff challenge. A challenge represents a
 * request for a human entity to review and attest to an action before
 * it may proceed.
 *
 * Required body fields:
 *   - handshakeId:         The handshake this signoff is bound to
 *   - accountableActorRef: The entity_ref of the accountable human
 *   - signoffPolicyId:     The policy governing this signoff
 *   - expiresAt:           ISO 8601 expiration timestamp
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();

    // ── Schema validation (early gate) ────────────────────────────────
    const { valid, data, errors } = validateSignoffChallenge(body);
    if (!valid) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, errors.join('; '));
    }

    // ── Manual validation (belt-and-suspenders fallback) ──────────────
    const required = ['handshakeId', 'accountableActorRef', 'signoffPolicyId', 'expiresAt'];
    for (const field of required) {
      if (!body[field]) {
        return EP_ERRORS.BAD_REQUEST(`Missing required field: ${field}`);
      }
    }

    const result = await issueChallenge({
      actor: auth.entity,
      ...data,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_challenge_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    return NextResponse.json({ _err: err.message, _code: err.code }, { status: 500 });
  }
}
