import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { revokeHandshake } from '@/lib/handshake';
import { EP_ERRORS, epProblem, epDbError } from '@/lib/errors';
import { validateRevokeBody } from '@/lib/handshake/schema';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 32 * 1024;

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
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    const validation = validateRevokeBody(body);
    if (!validation.valid) {
      return EP_ERRORS.BAD_REQUEST(validation.error);
    }

    // Access control: only parties to the handshake may revoke it
    const supabase = getGuardedClient();
    const entityId = authEntityId(auth);

    const { data: party } = await supabase
      .from('handshake_parties')
      .select('id')
      .eq('handshake_id', handshakeId)
      .eq('entity_ref', entityId)
      .maybeSingle();

    if (!party) {
      return epProblem(403, 'not_party', 'Only parties to the handshake may revoke it');
    }

    // validation.valid === true here guarantees `sanitized` is populated
    // (see lib/handshake/schema.js#validateRevokeBody); TS can't see that
    // cross-module invariant, so assert the type it already has at runtime.
    const sanitized = /** @type {{ reason: string }} */ (validation.sanitized);
    const result = await revokeHandshake(handshakeId, sanitized.reason, entityId);

    if (result.error) {
      // The writer/DB error can carry internal detail; epDbError logs it
      // server-side and returns a generic client-facing message. (LOW audit finding.)
      return epDbError(result.status || 500, 'handshake_revocation_failed', result.error, 'handshake:revoke');
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Handshake revocation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
