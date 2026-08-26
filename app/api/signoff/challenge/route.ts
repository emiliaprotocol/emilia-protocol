import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * POST /api/signoff/challenge
 *
 * Issue a new Accountable Signoff challenge. A challenge represents a
 * request for a human entity to review and attest to an action before
 * it may proceed.
 *
 * Public issuance is intentionally unavailable while the legacy signoff
 * channel has no production ceremony-evidence writer. The service-level
 * lifecycle remains implemented for a future verified WebAuthn or secure-app
 * producer, but the API must not mint challenges that callers cannot safely
 * complete.
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    return epProblem(
      503,
      'verified_ceremony_unavailable',
      'Accountable Signoff challenge issuance is unavailable until a server-verified WebAuthn or secure-application ceremony producer is configured.',
    );
  } catch (err) {
    logger.error('Signoff challenge error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
