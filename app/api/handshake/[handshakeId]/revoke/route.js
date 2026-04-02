import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { revokeHandshake } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { validateRevokeBody } from '@/lib/handshake/schema';
import { logger } from '../../../../../lib/logger.js';

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

    const validation = validateRevokeBody(body);
    if (!validation.valid) {
      return EP_ERRORS.BAD_REQUEST(validation.error);
    }

    // Access control: only parties to the handshake may revoke it
    const supabase = getGuardedClient();
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
      return epProblem(403, 'not_party', 'Only parties to the handshake may revoke it');
    }

    const result = await revokeHandshake(handshakeId, validation.sanitized.reason, auth.entity);

    if (result.error) {
      return epProblem(result.status || 500, 'handshake_revocation_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Handshake revocation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
