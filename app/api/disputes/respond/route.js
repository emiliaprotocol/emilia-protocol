import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { canonicalRespondDispute } from '@/lib/canonical-writer';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/disputes/respond
 * 
 * Receipt submitter responds to a dispute. Routes through canonical writer.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.dispute_id || !body.response) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and response are required');
    }

    const result = await canonicalRespondDispute(
      body.dispute_id, auth.entity.id, body.response, body.evidence
    );

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
