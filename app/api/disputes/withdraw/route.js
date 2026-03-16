import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { canonicalWithdrawDispute } from '@/lib/canonical-writer';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/disputes/withdraw
 * 
 * Withdraw an open dispute. Only the filer can withdraw.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.dispute_id) {
      return EP_ERRORS.BAD_REQUEST('dispute_id is required');
    }

    const result = await canonicalWithdrawDispute(body.dispute_id, auth.entity);

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Dispute withdrawal error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
