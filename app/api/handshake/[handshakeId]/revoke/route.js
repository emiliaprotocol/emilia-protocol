import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { revokeHandshake } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/handshake/[handshakeId]/revoke
 *
 * Revoke an active handshake. Only parties to the handshake may revoke it.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { handshakeId } = await params;
    const body = await request.json();

    if (!body.reason) {
      return EP_ERRORS.BAD_REQUEST('reason is required');
    }

    const result = await revokeHandshake(handshakeId, body.reason, auth.entity);

    if (result.error) {
      return epProblem(result.status || 500, 'handshake_revocation_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Handshake revocation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
