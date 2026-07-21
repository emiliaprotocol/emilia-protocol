import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityActor } from '@/lib/auth-projections.js';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 10 * 1024;

/**
 * POST /api/disputes/file
 *
 * File a dispute against a receipt. Routes through protocol write.
 * "Trust must never be more powerful than appeal."
 */
export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
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

    const result = await protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: body,
      actor: authEntityActor(auth),
    });

    if (result.error) {
      return epProblem(result.status || 500, 'dispute_filing_failed', result.error, {
        existing_dispute: result.existing_dispute,
      });
    }

    return NextResponse.json({
      ...result,
      _message: 'Dispute filed. The receipt submitter has 7 days to respond.',
    }, { status: 201 });
  } catch (err) {
    logger.error('Dispute filing error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
