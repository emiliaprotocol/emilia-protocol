import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityActor } from '@/lib/auth-projections.js';
import { createAttestation } from '@/lib/signoff/attest';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validateSignoffAttest } from '@/lib/validation/schemas';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 256 * 1024;

/**
 * POST /api/signoff/[challengeId]/attest
 *
 * Create a signoff attestation — the accountable human entity confirms
 * they have reviewed and approve the challenged action.
 *
 * Required body fields:
 *   - humanEntityRef:  The entity_ref of the attesting human
 *   - authMethod:      Authentication method used (e.g. 'api_key', 'oauth')
 *   - assuranceLevel:  Level of identity assurance (e.g. 'high', 'medium')
 *   - channel:         Channel through which attestation was made
 *   - attestationHash: Cryptographic hash binding the attestation
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { challengeId } = await params;
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    // ── Schema validation (early gate) ────────────────────────────────
    const { valid, data, errors } = validateSignoffAttest(body);
    if (!valid) {
      return epError(EP_ERROR_CODES.INVALID_INPUT, errors.join('; '));
    }

    // ── Manual validation (belt-and-suspenders fallback) ──────────────
    const required = ['humanEntityRef', 'authMethod', 'assuranceLevel', 'channel', 'attestationHash'];
    for (const field of required) {
      if (!body[field]) {
        return EP_ERRORS.BAD_REQUEST(`Missing required field: ${field}`);
      }
    }

    // The human named by an attestation is a security identity, not display
    // metadata. Do not let an authenticated actor submit an attestation for a
    // different humanEntityRef and launder that identity into the audit trail.
    const actor = authEntityActor(auth);
    if (!actor?.entity_id || body.humanEntityRef !== actor.entity_id) {
      return epProblem(403, 'attestation_identity_mismatch', 'humanEntityRef must match the authenticated actor');
    }

    const result = await createAttestation({
      actor,
      challengeId,
      ...data,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_attestation_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    // Log the raw error server-side only; never echo err.message/err.code back
    // to the client (may carry DB/internal detail — LOW audit finding).
    logger.error('Signoff attestation error:', { message: err.message, code: err.code });
    return NextResponse.json({
      error: { code: 'EP-9001', message: 'Attestation could not be processed.', detail: null }
    }, { status: err.status || 500 });
  }
}
