import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { fileContinuityClaim } from '@/lib/ep-ix';
import { EP_ERRORS, epProblem, epDbError } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 10 * 1024;

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.principal_id) return EP_ERRORS.BAD_REQUEST('principal_id is required');
    if (!body.old_entity_id) return EP_ERRORS.BAD_REQUEST('old_entity_id is required');
    if (!body.new_entity_id) return EP_ERRORS.BAD_REQUEST('new_entity_id is required');
    if (!body.reason) return EP_ERRORS.BAD_REQUEST('reason is required');
    const actorEntityId = authEntityId(auth).trim();
    if (!actorEntityId) {
      return epProblem(403, 'not_authorized', 'Identity continuity filing requires an authenticated entity identity');
    }

    const result = await fileContinuityClaim({
      principal_id: body.principal_id,
      old_entity_id: body.old_entity_id,
      new_entity_id: body.new_entity_id,
      reason: body.reason,
      continuity_mode: body.continuity_mode,
      proofs: body.proofs,
      transfer_budget: body.transfer_budget,
    }, actorEntityId);
    if (result.error) {
      if ((result.status || 500) >= 500) return epDbError(result.status || 500, 'identity_continuity_failed', result.error, 'identity/continuity');
      return NextResponse.json({ error: result.error, frozen: result.frozen, active_disputes: result.active_disputes }, { status: result.status });
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Continuity claim error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
