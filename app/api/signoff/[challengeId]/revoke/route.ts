import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityActor } from '@/lib/auth-projections.js';
import { revokeChallenge, revokeAttestation } from '@/lib/signoff/revoke';
import { SignoffError } from '@/lib/signoff/errors.js';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 32 * 1024;

/**
 * POST /api/signoff/[challengeId]/revoke
 *
 * Revoke a signoff challenge or its attestation. If `revokeAttestation` is
 * true in the body, the caller's attestation on this challenge is revoked;
 * otherwise the challenge itself is revoked.
 *
 * Body:
 *   revokeAttestation {boolean} — revoke the attestation instead of the challenge
 *   signoffId         {string}  — optional. Names the attestation explicitly.
 *                                 Required only when the caller holds more than
 *                                 one attestation on this challenge, which
 *                                 otherwise fails closed with 409
 *                                 AMBIGUOUS_ATTESTATION. The named attestation
 *                                 must belong to this challenge.
 *   reason            {string}  — required reason for revocation
 */
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ challengeId: string }> },
): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { challengeId } = await params;
    // readEpJson's own return type is presently inferred (its source module
    // has not been given explicit type annotations yet), which loses the
    // `ok`-discriminated union shape its JSDoc has always documented. Pin the
    // real, unchanged contract here so this call site narrows correctly.
    const parsed = (await readEpJson(request, MAX_BODY_BYTES, { invalidValue: {} })) as
      | { ok: false; response: NextResponse; error: any }
      | { ok: true; value: any };
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    let result: any;
    if (body.revokeAttestation) {
      // challengeId comes from the URL; the attestation's own signoff_id is
      // resolved from it (a challenge may carry one attestation per quorum
      // approver, so resolution is scoped to the caller's own signature).
      // body.signoffId disambiguates explicitly and is validated to belong
      // to this challenge.
      result = await revokeAttestation({
        // authEntityActor's return type includes null for the case where
        // auth.entity is absent, but that case cannot occur here: the
        // `auth.error` check above already returned UNAUTHORIZED for any
        // failed authentication, and authenticateRequest only omits `error`
        // when it also sets `entity` from the resolved actor. If entity_id
        // were ever missing, revokeAttestation's own `!actor?.entity_id`
        // guard throws MISSING_ACTOR, so this cast changes no behavior.
        actor: authEntityActor(auth as any) as { id: string; entity_id: string },
        challengeId,
        signoffId: typeof body.signoffId === 'string' ? body.signoffId : undefined,
        reason: body.reason || null,
      });
    } else {
      result = await revokeChallenge({
        // See the matching cast above: authEntityActor's `| null` case is
        // unreachable past the `auth.error` guard, and revokeChallenge's own
        // `!actor?.entity_id` check throws MISSING_ACTOR if it were ever wrong.
        actor: authEntityActor(auth as any) as { id: string; entity_id: string },
        challengeId,
        reason: body.reason || null,
      });
    }

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_revocation_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    // revoke.js signals refusals by throwing SignoffError with a real HTTP
    // status (403 FORBIDDEN, 404 ATTESTATION_NOT_FOUND, 409 on terminal state
    // or ambiguity). Collapsing those into 500 would report every authorization
    // and state refusal on a revocation path as a server fault, so the caller
    // cannot tell "you may not revoke this" from "we broke". Map them through;
    // anything else is still an opaque 500.
    if (err instanceof SignoffError) {
      return epProblem(err.status || 400, err.code.toLowerCase(), err.message);
    }
    logger.error('Signoff revocation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
