import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getHandshake } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * GET /api/handshake/[handshakeId]
 *
 * Get full handshake state including parties, presentations, binding, and result.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { handshakeId } = await params;

    const result = await getHandshake(handshakeId, null, auth.entity);

    if (result.error) {
      return epProblem(result.status || 404, 'handshake_not_found', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Handshake detail error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
