import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { getHandshake } from '@/lib/handshake';
import { epProblem } from '@/lib/errors';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { logger } from '../../../../lib/logger.js';

/**
 * GET /api/handshake/[handshakeId]
 *
 * Get full handshake state including parties, presentations, binding, and result.
 * Access restricted to parties of the handshake.
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ handshakeId: string }> }
): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const { handshakeId } = await params;

    // Access control: only parties to the handshake may view it
    const supabase = getGuardedClient();
    const entityId = authEntityId(auth);

    const { data: party } = await supabase
      .from('handshake_parties')
      .select('id')
      .eq('handshake_id', handshakeId)
      .eq('entity_ref', entityId)
      .maybeSingle();

    if (!party) {
      return epError(EP_ERROR_CODES.FORBIDDEN, 'Only parties to the handshake may view it');
    }

    const result: any = await getHandshake(handshakeId, entityId);

    if (result.error) {
      return epError(EP_ERROR_CODES.HANDSHAKE_NOT_FOUND, result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Handshake detail error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
