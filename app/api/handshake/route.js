import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { initiateHandshake, listHandshakes } from '@/lib/handshake';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/handshake
 *
 * Initiate a new EP Handshake — a structured identity exchange between parties.
 * The handshake coordinates mutual presentation of identity proofs before
 * a trust decision can be made.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();

    if (!body.mode) {
      return EP_ERRORS.BAD_REQUEST('mode is required');
    }
    if (!body.policy_id) {
      return EP_ERRORS.BAD_REQUEST('policy_id is required');
    }
    if (!body.parties || !Array.isArray(body.parties) || body.parties.length < 2) {
      return EP_ERRORS.BAD_REQUEST('parties is required and must contain at least 2 entries');
    }

    const result = await initiateHandshake({
      actor: auth.entity,
      mode: body.mode,
      policy_id: body.policy_id,
      parties: body.parties,
      payload: body.payload || {},
      interaction_id: body.interaction_id || null,
      binding: body.binding || null,
      binding_ttl_ms: body.binding_ttl_ms || undefined,
      idempotency_key: body.idempotency_key || null,
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
 * List handshakes, optionally filtered by entity_ref, status, or mode.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { searchParams } = new URL(request.url);
    const filters = {
      entity_ref: searchParams.get('entity_ref') || null,
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
