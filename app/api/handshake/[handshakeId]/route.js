import { NextResponse } from 'next/server';
import { authenticateRequest, getServiceClient } from '@/lib/supabase';
import { getHandshake } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * GET /api/handshake/[handshakeId]
 *
 * Get full handshake state including parties, presentations, binding, and result.
 * Access restricted to parties of the handshake.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { handshakeId } = await params;

    // Access control: only parties to the handshake may view it
    const supabase = getServiceClient();
    const entityId = typeof auth.entity === 'object'
      ? (auth.entity.entity_id || auth.entity.id)
      : auth.entity;

    const { data: party } = await supabase
      .from('handshake_parties')
      .select('id')
      .eq('handshake_id', handshakeId)
      .eq('entity_ref', entityId)
      .maybeSingle();

    if (!party) {
      return epProblem(403, 'not_party', 'Only parties to the handshake may view it');
    }

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
