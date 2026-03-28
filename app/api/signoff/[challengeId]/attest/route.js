import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { createAttestation } from '@/lib/signoff/attest';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { validateSignoffAttest } from '@/lib/validation/schemas';

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
    const body = await request.json();

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

    const result = await createAttestation({
      actor: auth.entity,
      challengeId,
      ...data,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_attestation_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    return NextResponse.json({ _e: err.message, _c: err.code }, { status: 500 });
  }
}
