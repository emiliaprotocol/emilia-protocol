import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { verifyHandshake } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/handshake/[handshakeId]/verify
 *
 * Evaluate a handshake — check all presentations against the policy
 * and return a result (accepted, rejected, or partial).
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { handshakeId } = await params;
    const body = await request.json().catch(() => ({}));

    const result = await verifyHandshake(handshakeId, {
      actor: auth.entity,
      payload_hash: body.payload_hash || null,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'handshake_verification_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Handshake verification error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
