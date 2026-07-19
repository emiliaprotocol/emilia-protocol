import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { resolveContinuity } from '@/lib/ep-ix';
import { EP_ERRORS, epDbError } from '@/lib/errors';
import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    if (!auth.permissions?.includes('dispute.review')) {
      return epProblem(403, 'forbidden', 'Identity continuity resolution requires dispute.review permission');
    }

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;
    if (!body.continuity_id) return EP_ERRORS.BAD_REQUEST('continuity_id is required');
    if (!body.decision) return EP_ERRORS.BAD_REQUEST('decision is required (approved_full, approved_partial, rejected, rejected_laundering)');

    const result = await resolveContinuity(body.continuity_id, body.decision, body.reasoning, authEntityId(auth) || 'operator');
    if (result.error) {
      if ((result.status || 500) >= 500) return epDbError(result.status || 500, 'identity_continuity_resolve_failed', result.error, 'identity/continuity/resolve');
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Continuity resolve error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
