import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { addPresentation } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validatePresentBody } from '@/lib/handshake/schema';
import { validatePresent } from '@/lib/validation/schemas';

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
    const body = await request.json();

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

    const result = await addPresentation(
      handshakeId,
      party_role,
      {
        type: presentation_type,
        data: claims,
        issuer_ref,
        disclosure_mode,
      },
      auth.entity
    );

    if (result.error) {
      return epError(EP_ERROR_CODES.INTERNAL, result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Handshake presentation error:', err.message);
    return NextResponse.json({ _err: err.message }, { status: 500 });
  }
}
