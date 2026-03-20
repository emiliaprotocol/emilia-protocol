import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { addPresentation } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { validatePresentBody } from '@/lib/handshake/schema';

/**
 * POST /api/handshake/[handshakeId]/present
 *
 * Add an identity presentation (proof) to a handshake.
 * Each party presents their identity claims for evaluation.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { handshakeId } = await params;
    const body = await request.json();

    const validation = validatePresentBody(body);
    if (!validation.valid) {
      return EP_ERRORS.BAD_REQUEST(validation.error);
    }

    const { party_role, presentation_type, claims, issuer_ref, disclosure_mode } = validation.sanitized;

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
      return epProblem(result.status || 500, 'presentation_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Handshake presentation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
