import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityDbId, authEntityId } from '@/lib/auth-projections.js';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 10 * 1024;

/**
 * POST /api/disputes/respond
 *
 * Receipt submitter responds to a dispute. Routes through protocol write.
 */
export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.dispute_id || !body.response) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and response are required');
    }

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESPOND_DISPUTE,
      input: {
        dispute_id: body.dispute_id,
        responder_id: authEntityDbId(auth),
        response: body.response,
        evidence: body.evidence,
      },
      actor: authEntityId(auth),
    });

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    return NextResponse.json({
      ...result,
      _message: 'Response recorded. Dispute is now under review.',
    });
  } catch (err) {
    logger.error('Dispute response error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
