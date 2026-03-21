import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { revokeChallenge, revokeAttestation } from '@/lib/signoff/revoke';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/signoff/[challengeId]/revoke
 *
 * Revoke a signoff challenge or its attestation. If the challenge has
 * an active attestation and `revokeAttestation` is true in the body,
 * the attestation is revoked; otherwise the challenge itself is revoked.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { challengeId } = await params;
    const body = await request.json().catch(() => ({}));

    let result;
    if (body.revokeAttestation) {
      result = await revokeAttestation({
        actor: auth.entity,
        challengeId,
        reason: body.reason || null,
      });
    } else {
      result = await revokeChallenge({
        actor: auth.entity,
        challengeId,
        reason: body.reason || null,
      });
    }

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_revocation_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Signoff revocation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
