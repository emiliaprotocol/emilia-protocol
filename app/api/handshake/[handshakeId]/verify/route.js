import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { verifyHandshake } from '@/lib/handshake';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';

/**
 * POST /api/handshake/[handshakeId]/verify
 *
 * Evaluate a handshake — check all presentations against the policy
 * and return a result (accepted, rejected, or partial).
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const { handshakeId } = await params;
    const body = await request.json().catch(() => ({}));

    const result = await verifyHandshake(handshakeId, {
      actor: auth.entity,
      payload_hash: body.payload_hash || null,
      nonce: body.nonce || null,
    });

    if (result.error) {
      return epError(EP_ERROR_CODES.HANDSHAKE_VERIFICATION_FAILED, result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Handshake verification error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
