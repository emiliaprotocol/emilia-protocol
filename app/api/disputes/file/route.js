import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { canonicalFileDispute } from '@/lib/canonical-writer';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/disputes/file
 * 
 * File a dispute against a receipt. Routes through canonical writer.
 * "Trust must never be more powerful than appeal."
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.receipt_id || !body.reason) {
      return EP_ERRORS.BAD_REQUEST('receipt_id and reason are required');
    }

    const validReasons = [
      'fraudulent_receipt', 'inaccurate_signals', 'identity_dispute',
      'context_mismatch', 'duplicate_transaction', 'coerced_receipt', 'other',
    ];
    if (!validReasons.includes(body.reason)) {
      return EP_ERRORS.BAD_REQUEST(`Invalid reason. Must be one of: ${validReasons.join(', ')}`);
    }

    const result = await canonicalFileDispute(body, auth.entity);

    if (result.error) {
      const status = result.status || 500;
      return NextResponse.json({ error: result.error, existing_dispute: result.existing_dispute }, { status });
    }

    return NextResponse.json({
      ...result,
      _message: 'Dispute filed. The receipt submitter has 7 days to respond.',
    }, { status: 201 });
  } catch (err) {
    console.error('Dispute filing error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
