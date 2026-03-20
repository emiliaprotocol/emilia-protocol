import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/disputes/respond
 *
 * Receipt submitter responds to a dispute. Routes through protocol write.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.dispute_id || !body.response) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and response are required');
    }

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESPOND_DISPUTE,
      input: {
        dispute_id: body.dispute_id,
        responder_id: auth.entity.id,
        response: body.response,
        evidence: body.evidence,
      },
      actor: auth.entity,
    });

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    return NextResponse.json({
      ...result,
      _message: 'Response recorded. Dispute is now under review.',
    });
  } catch (err) {
    console.error('Dispute response error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
