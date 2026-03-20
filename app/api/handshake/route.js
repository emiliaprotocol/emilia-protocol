import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { initiateHandshake, listHandshakes } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { validateInitiateBody } from '@/lib/handshake/schema';

/**
 * POST /api/handshake
 *
 * Initiate a new EP Handshake — a structured identity exchange between parties.
 * The handshake coordinates mutual presentation of identity proofs before
 * a trust decision can be made.
 *
 * Authorization: validates that exactly one initiator exists and its entity_ref
 * matches the authenticated entity.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();

    const validation = validateInitiateBody(body);
    if (!validation.valid) {
      return EP_ERRORS.BAD_REQUEST(validation.error);
    }

    // ── Authorization: enforce initiator ownership ──────────────────────
    const initiators = validation.sanitized.parties.filter((p) => p.role === 'initiator');
    if (initiators.length !== 1) {
      return EP_ERRORS.BAD_REQUEST('Exactly one initiator party is required');
    }
    if (initiators[0].entity_ref !== auth.entity) {
      return epProblem(403, 'unauthorized_handshake_access',
        'Initiator entity_ref must match the authenticated entity');
    }

    const result = await initiateHandshake({
      actor: auth.entity,
      ...validation.sanitized,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'handshake_initiation_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Handshake initiation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

/**
 * GET /api/handshake
 *
 * List handshakes, optionally filtered by status or mode.
 * Reads are scoped to the authenticated entity — the entity_ref filter is
 * always forced to match auth.entity regardless of query parameters.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { searchParams } = new URL(request.url);
    const filters = {
      entity_ref: auth.entity, // forced — callers may only list their own handshakes
      status: searchParams.get('status') || null,
      mode: searchParams.get('mode') || null,
    };

    const result = await listHandshakes(filters, auth.entity);

    if (result.error) {
      return epProblem(result.status || 500, 'handshake_list_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Handshake list error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
