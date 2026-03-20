import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { addPresentation } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';

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

    if (!body.party_role) {
      return EP_ERRORS.BAD_REQUEST('party_role is required');
    }
    if (!body.presentation_type) {
      return EP_ERRORS.BAD_REQUEST('presentation_type is required');
    }
    if (!body.claims || typeof body.claims !== 'object') {
      return EP_ERRORS.BAD_REQUEST('claims is required and must be an object');
    }

    const result = await addPresentation(handshakeId, {
      party_role: body.party_role,
      presentation_type: body.presentation_type,
      issuer_ref: body.issuer_ref || null,
      claims: body.claims,
      disclosure_mode: body.disclosure_mode || null,
    }, auth.entity);

    if (result.error) {
      return epProblem(result.status || 500, 'presentation_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Handshake presentation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
