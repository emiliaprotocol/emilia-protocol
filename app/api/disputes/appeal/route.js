import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/disputes/appeal
 *
 * Appeal a dispute resolution. Requires entity auth.
 * Only dispute participants (filer or subject entity) may appeal.
 *
 * "Trust must never be more powerful than appeal."
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.dispute_id || !body.reason) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and reason are required. reason must be at least 10 characters.');
    }

    const result = await protocolWrite({
      type: COMMAND_TYPES.APPEAL_DISPUTE,
      input: {
        dispute_id: body.dispute_id,
        reason: body.reason,
        evidence: body.evidence || null,
        appealer_id: auth.entity.id,
      },
      actor: auth.entity,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'appeal_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Appeal filing error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
