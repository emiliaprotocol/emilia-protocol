import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { initiateHandshake, listHandshakes } from '@/lib/handshake';
import { epProblem } from '@/lib/errors'; // retained for edge-case compat
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validateInitiateBody } from '@/lib/handshake/schema';
import { validateHandshakeCreate } from '@/lib/validation/schemas';

// ── Overload backpressure ────────────────────────────────────────────────────
// Fast-fail under concurrency pressure instead of slow timeout collapse.
// Per-instance counter — each serverless function instance tracks its own load.
let _inflight = 0;
const MAX_CONCURRENT = 50;

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
  // Overload guard: prefer fast 503 over slow timeout
  if (_inflight >= MAX_CONCURRENT) {
    return NextResponse.json(
      { error: 'Service overloaded', retry_after: 2 },
      { status: 503, headers: { 'Retry-After': '2' } },
    );
  }
  _inflight++;
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const body = await request.json();

    // ── Schema validation (early gate) ────────────────────────────────
    const { valid, data, errors } = validateHandshakeCreate(body);
    if (!valid) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, errors.join('; '));
    }

    // ── Manual validation (belt-and-suspenders fallback) ──────────────
    const validation = validateInitiateBody(body);
    if (!validation.valid) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, validation.error);
    }

    // ── Authorization: enforce initiator ownership ──────────────────────
    const initiators = data.parties.filter((p) => p.role === 'initiator');
    if (initiators.length !== 1) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, 'Exactly one initiator party is required');
    }
    if (initiators[0].entity_ref !== auth.entity.entity_id) {
      return epError(EP_ERROR_CODES.UNAUTHORIZED_HANDSHAKE,
        'Initiator entity_ref must match the authenticated entity');
    }

    const result = await initiateHandshake({
      actor: auth.entity,
      ...data,
    });

    if (result.error) {
      return epError(EP_ERROR_CODES.HANDSHAKE_INITIATION_FAILED, result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Handshake initiation error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  } finally {
    _inflight--;
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
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const { searchParams } = new URL(request.url);
    const filters = {
      entity_ref: auth.entity, // forced — callers may only list their own handshakes
      status: searchParams.get('status') || null,
      mode: searchParams.get('mode') || null,
    };

    const result = await listHandshakes(filters, auth.entity);

    if (result.error) {
      return epError(EP_ERROR_CODES.INTERNAL, result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Handshake list error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
