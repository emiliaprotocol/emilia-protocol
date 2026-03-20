import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
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

    const result = await protocolWrite({
      type: COMMAND_TYPES.CONFIRM_RECEIPT,
      input: {
        receipt_id: body.receipt_id,
        confirming_entity_id: auth.entity.id,
        confirm: body.confirm,
      },
      actor: auth.entity,
    });

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
