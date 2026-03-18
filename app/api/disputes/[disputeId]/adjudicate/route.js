/**
 * POST /api/disputes/[disputeId]/adjudicate
 *
 * Triggers trust-graph adjudication for a dispute.
 *
 * Authorization:
 *   - CRON_SECRET bearer token (for automated cron-based adjudication after
 *     the 48h response window, or periodic re-adjudication sweeps)
 *   - The authenticated entity who filed the dispute (after 48h response window)
 *
 * The 48h window: giving the accused entity time to respond before the trust
 * graph is consulted is a procedural justice requirement. Adjudication by the
 * graph does not replace response — it supplements it when response is absent.
 *
 * Returns:
 *   - adjudication_result: { recommendation, confidence, voucher_count, weighted_vote }
 *   - The result is stored in disputes.adjudication_result (JSONB) and does NOT
 *     automatically change the dispute status — operators retain final authority.
 *
 * Response codes:
 *   200 — adjudication complete (result in body)
 *   202 — adjudication triggered but dispute is too fresh (< 48h), result is advisory
 *   400 — missing disputeId or dispute in wrong state
 *   401 — not authorized
 *   403 — dispute too fresh and caller is not cron (no override)
 *   404 — dispute not found
 *   409 — dispute already in terminal state
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { adjudicateDispute } from '@/lib/dispute-adjudication';
import { EP_ERRORS } from '@/lib/errors';

// Minimum age before a filer can trigger adjudication themselves.
// 48 hours: gives the accused entity a fair response window.
// Cron/operator calls bypass this gate.
const FILER_ADJUDICATION_WINDOW_HOURS = 48;
const FILER_ADJUDICATION_WINDOW_MS = FILER_ADJUDICATION_WINDOW_HOURS * 60 * 60 * 1000;

export async function POST(request, { params }) {
  try {
    const { disputeId } = await params;

    if (!disputeId) {
      return EP_ERRORS.BAD_REQUEST('disputeId is required');
    }

    const supabase = getServiceClient();

    // -------------------------------------------------------------------
    // Authorization: CRON_SECRET or authenticated filer
    // -------------------------------------------------------------------
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    const isCron = cronSecret && authHeader === `Bearer ${cronSecret}`;

    let callerEntity = null;
    let callerIsFiler = false;
    let triggeredBy = 'cron';

    if (!isCron) {
      // Try entity auth
      const auth = await authenticateRequest(request);
      if (auth.error) {
        return EP_ERRORS.UNAUTHORIZED();
      }
      callerEntity = auth.entity;
      triggeredBy = callerEntity.entity_id;
    }

    // -------------------------------------------------------------------
    // Fetch dispute to validate state and authorization
    // -------------------------------------------------------------------
    const { data: dispute, error: disputeError } = await supabase
      .from('disputes')
      .select(`
        dispute_id,
        entity_id,
        filed_by,
        status,
        created_at,
        response_deadline,
        adjudication_result,
        adjudicated_at
      `)
      .eq('dispute_id', disputeId)
      .single();

    if (disputeError || !dispute) {
      return EP_ERRORS.NOT_FOUND('Dispute');
    }

    // Check terminal state
    const adjudicatableStates = ['open', 'under_review'];
    if (!adjudicatableStates.includes(dispute.status)) {
      return EP_ERRORS.CONFLICT(
        `Dispute is '${dispute.status}' — adjudication only applies to open or under_review disputes`
      );
    }

    // -------------------------------------------------------------------
    // Timing gate: enforce 48h window for filer-triggered adjudication
    // -------------------------------------------------------------------
    const disputeAge = Date.now() - new Date(dispute.created_at).getTime();
    const isTooFresh = disputeAge < FILER_ADJUDICATION_WINDOW_MS;

    if (!isCron) {
      // Non-cron caller must be the filer
      if (callerEntity.id !== dispute.filed_by) {
        // Allow operators (future: check for operator permission)
        // For now, only the filer and cron can trigger adjudication
        return EP_ERRORS.FORBIDDEN(
          'Only the dispute filer or the protocol cron can trigger adjudication'
        );
      }
      callerIsFiler = true;

      if (isTooFresh) {
        // Return 403: filers must wait 48h to give the accused a fair window
        const hoursRemaining = Math.ceil(
          (FILER_ADJUDICATION_WINDOW_MS - disputeAge) / (60 * 60 * 1000)
        );
        return EP_ERRORS.FORBIDDEN(
          `Adjudication cannot be triggered until ${FILER_ADJUDICATION_WINDOW_HOURS}h after filing. ` +
          `${hoursRemaining}h remaining. This window allows the other party to respond.`
        );
      }
    }

    // -------------------------------------------------------------------
    // Run trust-graph adjudication
    // -------------------------------------------------------------------
    const result = await adjudicateDispute(disputeId, supabase);

    if (result.error) {
      const status = result.status || 500;
      return NextResponse.json({ error: result.error }, { status });
    }

    // For fresh disputes triggered by cron, mark result as advisory
    const isAdvisory = isCron && isTooFresh;
    const responseStatus = isAdvisory ? 202 : 200;

    const response = {
      dispute_id: result.dispute_id,
      disputed_entity_id: result.disputed_entity_id,
      receipt_id: result.receipt_id,

      adjudication: result.adjudication,

      // Voucher summary (entity slugs, not UUIDs — safe to expose publicly)
      vouchers: result.vouchers,

      adjudicated_at: result.adjudicated_at,
      triggered_by: triggeredBy,

      _protocol: 'EP trust-graph adjudication v1',
      _note: isAdvisory
        ? 'Advisory: dispute is less than 48h old. Adjudication complete but response window still open.'
        : 'Adjudication complete. Result stored in dispute record. Operator retains final resolution authority.',

      // Human-readable interpretation of the recommendation
      _interpretation: interpretRecommendation(result.adjudication),
    };

    return NextResponse.json(response, { status: responseStatus });

  } catch (err) {
    console.error('Adjudication route error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

// =============================================================================
// interpretRecommendation — human-readable explanation for callers
// =============================================================================

/**
 * Produce a plain-language interpretation of the adjudication result.
 * This goes in the API response so callers don't need to parse vote math.
 */
function interpretRecommendation(adjudication) {
  const { recommendation, confidence, voucher_count, participating_count } = adjudication;
  const pct = adjudication.weighted_vote?.uphold_fraction != null
    ? `${Math.round(adjudication.weighted_vote.uphold_fraction * 100)}% uphold weight`
    : 'no decisive votes cast';

  if (voucher_count === 0) {
    return 'The trust graph has no high-confidence entities with shared transaction history. ' +
           'This entity may be new or isolated. Human review recommended.';
  }

  const voucherSummary = `${participating_count} of ${voucher_count} vouchers had behavioral data (${pct}).`;

  switch (recommendation) {
    case 'uphold_dispute':
      return `Trust graph recommends UPHOLDING this dispute. ${voucherSummary} ` +
             `High-confidence counterparties report behavioral patterns consistent with the dispute claim. ` +
             `Confidence: ${Math.round(confidence * 100)}%.`;
    case 'dismiss_dispute':
      return `Trust graph recommends DISMISSING this dispute. ${voucherSummary} ` +
             `High-confidence counterparties report consistently positive interactions with this entity. ` +
             `Confidence: ${Math.round(confidence * 100)}%.`;
    case 'inconclusive':
      return `Trust graph result is INCONCLUSIVE. ${voucherSummary} ` +
             `Voucher sentiment is mixed or insufficient for a decisive recommendation. ` +
             `Human operator review required.`;
    default:
      return 'Adjudication complete. See adjudication.recommendation for result.';
  }
}
