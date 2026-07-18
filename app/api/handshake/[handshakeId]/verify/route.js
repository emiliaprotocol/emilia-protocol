import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { verifyHandshake } from '@/lib/handshake';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { authorizeHandshakeVerify } from '@/lib/handshake-auth';
import { getGuardedClient } from '@/lib/write-guard';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 256 * 1024;

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

    // ── Authorization: caller must be a party or have verify permission ──
    const actorId = authEntityId(auth);
    const supabase = getGuardedClient();
    await authorizeHandshakeVerify(supabase, actorId, handshakeId);

    const parsed = await readEpJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    const result = await verifyHandshake(handshakeId, {
      actor: actorId,
      payload: body.payload || null,
      nonce: body.nonce || null,
      action_hash: body.action_hash || null,
      policy_hash: body.policy_hash || null,
    });

    if (result.error) {
      // Same info-leak posture as the present route: the verifier/DB error can
      // carry internal detail. Log server-side; return a generic code with no
      // client-facing detail. (LOW audit finding.)
      logger.error('[handshake:verify] Verification failed:', result.error);
      return epError(EP_ERROR_CODES.HANDSHAKE_VERIFICATION_FAILED);
    }

    return NextResponse.json(result);
  } catch (err) {
    if (err.name === 'HandshakeError' && err.status === 403) {
      return epError(EP_ERROR_CODES.FORBIDDEN, err.message);
    }
    logger.error('Handshake verification error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
