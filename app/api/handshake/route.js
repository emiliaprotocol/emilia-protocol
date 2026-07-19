import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { initiateHandshake, listHandshakes } from '@/lib/handshake';
import { epProblem } from '@/lib/errors'; // retained for edge-case compat
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validateInitiateBody } from '@/lib/handshake/schema';
import { validateHandshakeCreate } from '@/lib/validation/schemas';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../lib/logger.js';

const MAX_BODY_BYTES = 256 * 1024;

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
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    // ── Schema validation (early gate) ────────────────────────────────
    const { valid, data, errors } = /** @type {
      | { valid: true, data: { mode: string, policy_id: string, parties: any[], payload?: any, interaction_id?: string|null, binding?: any, binding_ttl_ms?: number, idempotency_key?: string|null, action_type?: string|null, resource_ref?: string|null, intent_ref?: string|null }, errors?: undefined }
      | { valid: false, data?: undefined, errors: string[] }
    } */ (validateHandshakeCreate(body));
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
    const actorId = authEntityId(auth);
    if (initiators[0].entity_ref !== actorId) {
      return epError(EP_ERROR_CODES.UNAUTHORIZED_HANDSHAKE,
        'Initiator entity_ref must match the authenticated entity');
    }

    const result = /** @type {import('@/lib/handshake/create').InitiateHandshakeResult & { error?: any }} */ (await initiateHandshake({
      actor: actorId,
      ...data,
    }));

    if (result.error) {
      logger.error('[handshake] Initiation failed:', result.error);
      return epError(EP_ERROR_CODES.HANDSHAKE_INITIATION_FAILED);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Handshake initiation error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}

/**
 * GET /api/handshake
 *
 * List handshakes, optionally filtered by status or mode.
 * Reads are scoped to the authenticated entity — the entity_ref filter is
 * always forced to match the authenticated actor regardless of query parameters.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const { searchParams } = new URL(request.url);
    const actorId = authEntityId(auth);
    const filters = {
      entity_ref: actorId, // forced — callers may only list their own handshakes
      status: searchParams.get('status') || null,
      mode: searchParams.get('mode') || null,
    };

    const result = await listHandshakes(filters, actorId);

    if (result.error) {
      // The query/DB error can carry internal detail. Log server-side; return a
      // generic INTERNAL with no client-facing detail. (LOW audit finding.)
      logger.error('[handshake:list] List query failed:', result.error);
      return epError(EP_ERROR_CODES.INTERNAL);
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Handshake list error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
