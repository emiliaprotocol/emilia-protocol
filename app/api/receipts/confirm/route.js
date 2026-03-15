import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { canonicalBilateralConfirm } from '@/lib/canonical-writer';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/receipts/confirm
 * 
 * Bilateral attestation confirmation. Routes through canonical writer.
 * The entity that the receipt is ABOUT confirms or disputes the claim.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.receipt_id || body.confirm === undefined) {
      return EP_ERRORS.BAD_REQUEST('receipt_id and confirm (boolean) are required');
    }

    const result = await canonicalBilateralConfirm(
      body.receipt_id, auth.entity.id, body.confirm
    );

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    const message = body.confirm
      ? 'Both parties confirmed. Receipt upgraded to bilateral provenance (0.8x weight).'
      : 'Counterparty disputed the receipt. Provenance remains self_attested (0.3x weight).';

    return NextResponse.json({ ...result, _message: message });
  } catch (err) {
    console.error('Bilateral confirmation error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
