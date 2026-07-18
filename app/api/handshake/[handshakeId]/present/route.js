import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { addPresentation } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validatePresentBody } from '@/lib/handshake/schema';
import { validatePresent } from '@/lib/validation/schemas';
import { authorizeHandshakePresent } from '@/lib/handshake-auth';
import { getGuardedClient } from '@/lib/write-guard';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../../lib/logger.js';

// Presentations carry identity-claim payloads (credentials), so allow more than
// the 10KB identity routes — but still bounded to prevent unbounded-body DoS.
const MAX_BODY_BYTES = 100 * 1024;

/**
 * POST /api/handshake/[handshakeId]/present
 *
 * Add an identity presentation (proof) to a handshake.
 * Each party presents their identity claims for evaluation.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const { handshakeId } = await params;
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;

    // ── Schema validation (early gate) ────────────────────────────────
    const { valid, data, errors } = validatePresent(body);
    if (!valid) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, errors.join('; '));
    }

    // ── Manual validation (belt-and-suspenders fallback) ──────────────
    const validation = validatePresentBody(body);
    if (!validation.valid) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, validation.error);
    }

    const { party_role, presentation_type, claims, issuer_ref, disclosure_mode } = data;

    // ── Authorization: caller must OWN the party_role they present as ─────
    // Without this, any authenticated entity could post a presentation to any
    // handshake as any role (IDOR) — impersonating a counterparty or injecting
    // fake identity proofs. addPresentation only validates the role is a valid
    // enum, not that the caller owns it. Mirrors the verify route's guard.
    const actorId = authEntityId(auth);
    const supabase = getGuardedClient();
    await authorizeHandshakePresent(supabase, actorId, handshakeId, party_role);

    const result = await addPresentation(
      handshakeId,
      party_role,
      {
        type: presentation_type,
        data: claims,
        issuer_ref,
        disclosure_mode,
      },
      actorId
    );

    if (result.error) {
      // The writer/DB error can carry internal detail (table/column names, raw
      // Postgres/RPC messages). Log it server-side; return a generic INTERNAL
      // with no client-facing detail so nothing internal leaks. (LOW audit finding.)
      logger.error('[handshake:present] Presentation write failed:', result.error);
      return epError(EP_ERROR_CODES.INTERNAL);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    if (err.name === 'HandshakeError' && err.status === 403) {
      return epError(EP_ERROR_CODES.FORBIDDEN, err.message);
    }
    logger.error('Handshake presentation error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
