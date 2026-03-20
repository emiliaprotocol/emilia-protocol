/**
 * EP Canonical Write Engine
 * 
 * ONE function for every trust-changing write action.
 * Same discipline as the canonical evaluator, but for writes.
 * 
 * Every write goes through here:
 *   - Receipt submission
 *   - Dispute filing
 *   - Dispute resolution
 *   - Bilateral confirmation
 *   - Human reports
 * 
 * This provides:
 *   - Single enforcement point for idempotency
 *   - Single enforcement point for fraud checks
 *   - Single enforcement point for provenance validation
 *   - Single place to add webhooks, audit logging, event sourcing later
 *   - Single place to trigger trust profile materialization
 * 
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { createReceipt } from '@/lib/create-receipt';
import { ProtocolWriteError } from '@/lib/errors';

/**
 * Event types for audit/webhook purposes.
 * Every canonical write produces an event.
 */
export const WRITE_EVENTS = {
  RECEIPT_SUBMITTED: 'receipt.submitted',
  RECEIPT_DEDUPLICATED: 'receipt.deduplicated',
  RECEIPT_BILATERAL_CONFIRMED: 'receipt.bilateral.confirmed',
  RECEIPT_BILATERAL_DISPUTED: 'receipt.bilateral.disputed',
  RECEIPT_BILATERAL_EXPIRED: 'receipt.bilateral.expired',
  DISPUTE_FILED: 'dispute.filed',
  DISPUTE_RESPONDED: 'dispute.responded',
  DISPUTE_RESOLVED: 'dispute.resolved',
  DISPUTE_APPEALED: 'dispute.appealed',
  DISPUTE_APPEAL_RESOLVED: 'dispute.appeal.resolved',
  REPORT_FILED: 'report.filed',
  ENTITY_REGISTERED: 'entity.registered',
  TRUST_RECOMPUTED: 'trust.recomputed',
};


/**
 * Persist an event to the protocol_events table in Supabase.
 * Fire-and-forget — never awaited in the hot path.
 *
 * // Non-truth-bearing: safe to degrade
 * Event persistence is audit/observability — it does not affect trust state.
 * Failure here must not block trust-bearing writes.
 */
async function persistEvent(event) {
  try {
    const supabase = getServiceClient();
    await supabase.from('protocol_events').insert({
      event_id: `ep_evt_${crypto.randomBytes(8).toString('hex')}`,
      event_type: event.type,
      payload: event,
      occurred_at: event.timestamp,
    });
  } catch (e) {
    // Non-truth-bearing: safe to degrade
    const isMissingTable = e.message?.includes('does not exist') || e.message?.includes('relation');
    if (!isMissingTable) console.warn('Event persistence failed (non-truth-bearing, degrading gracefully):', e.message);
  }
}

function emitEvent(type, payload) {
  const event = {
    type,
    timestamp: new Date().toISOString(),
    ...payload,
  };
  // Persist durably to Supabase — fire-and-forget, non-blocking
  persistEvent(event);
  return event;
}

/**
 * Submit a receipt through the canonical write path.
 * 
 * Enforces: idempotency, fraud checks, provenance validation,
 * self-score prevention, and trust recomputation.
 */
export async function canonicalSubmitReceipt(params, submitterEntity) {
  const result = await createReceipt({
    targetEntitySlug: params.entity_id,
    submitter: submitterEntity,
    transactionRef: params.transaction_ref,
    transactionType: params.transaction_type,
    signals: {
      delivery_accuracy: params.delivery_accuracy ?? null,
      product_accuracy: params.product_accuracy ?? null,
      price_integrity: params.price_integrity ?? null,
      return_processing: params.return_processing ?? null,
      agent_satisfaction: params.agent_satisfaction ?? null,
    },
    agentBehavior: params.agent_behavior || null,
    claims: params.claims || null,
    evidence: params.evidence || {},
    context: params.context || null,
    provenanceTier: params.provenance_tier || 'self_attested',
    requestBilateral: params.request_bilateral || false,
  });

  if (result.error) return result;

  // Emit event
  const eventType = result.deduplicated
    ? WRITE_EVENTS.RECEIPT_DEDUPLICATED
    : WRITE_EVENTS.RECEIPT_SUBMITTED;

  emitEvent(eventType, {
    receipt_id: result.receipt?.receipt_id,
    entity_id: params.entity_id,
    submitted_by: submitterEntity.entity_id,
    deduplicated: !!result.deduplicated,
  });

  // Trigger materialization if not deduplicated
  if (!result.deduplicated) {
    await materializeTrustProfile(result.receipt?.entity_id);
  }

  return result;
}

/**
 * Submit an auto-generated receipt through the canonical write path.
 *
 * Thin wrapper around canonicalSubmitReceipt. Normalizes the lighter schema
 * produced by AutoReceiptMiddleware into the standard params format, then
 * delegates to the EXACT same code path that manual submission uses.
 *
 * There is ONE receipt write path. This function does not touch the DB —
 * it only normalizes fields and calls canonicalSubmitReceipt.
 *
 * Auto-receipts are always:
 *   - provenance_tier: 'self_attested'
 *   - auto_generated: true
 *   - provenance: 'unilateral'
 *   - bilateral_status: null  (cannot claim bilateral without confirmation)
 *
 * @param {object} raw          - Raw receipt from the MCP auto-receipt pipeline.
 * @param {object} submitterEntity - Authenticated machine entity (from api_keys lookup).
 * @returns {Promise<object>}   - { receipt, entityScore, warnings } or { error, status }
 */
export async function canonicalSubmitAutoReceipt(raw, submitterEntity) {
  // Derive agent_behavior from outcome signals if not explicitly set.
  let agentBehavior = raw.agent_behavior || null;
  if (!agentBehavior && raw.outcome) {
    if (raw.outcome.completed === true) agentBehavior = 'completed';
    else if (raw.outcome.error_occurred === true) agentBehavior = 'abandoned';
  }

  // Normalize auto-receipt fields into the standard params format and
  // delegate to the ONE canonical receipt submission path.
  const normalizedParams = {
    entity_id: raw.entity_id,
    transaction_ref: raw.transaction_ref,
    transaction_type: raw.transaction_type || 'service',
    delivery_accuracy: raw.delivery_accuracy ?? null,
    product_accuracy: raw.product_accuracy ?? null,
    price_integrity: raw.price_integrity ?? null,
    return_processing: raw.return_processing ?? null,
    agent_satisfaction: raw.agent_satisfaction ?? null,
    agent_behavior: agentBehavior,
    claims: raw.claims || null,
    evidence: raw.evidence || {},
    context: raw.context || null,
    provenance_tier: 'self_attested',   // always self_attested for auto-generated
    request_bilateral: false,           // never bilateral for auto-generated
  };

  return canonicalSubmitReceipt(normalizedParams, submitterEntity);
}

/**
 * Resolve a dispute through the canonical write path.
 *
 * Enforces: score recomputation on reversal, event emission,
 * and materialization cascade.
 */
export async function canonicalResolveDispute(disputeId, resolution, rationale, operatorId) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  // Fetch dispute
  const { data: dispute } = await supabase
    .from('disputes')
    .select('*')
    .eq('dispute_id', disputeId)
    .single();

  if (!dispute) return { error: 'Dispute not found', status: 404 };
  if (!['open', 'under_review'].includes(dispute.status)) {
    return { error: `Dispute is already ${dispute.status}`, status: 409 };
  }

  const validResolutions = ['upheld', 'reversed', 'dismissed'];
  if (!validResolutions.includes(resolution)) {
    return { error: `resolution must be one of: ${validResolutions.join(', ')}`, status: 400 };
  }

  // Update dispute
  await supabase
    .from('disputes')
    .update({
      status: resolution,
      resolution,
      resolution_rationale: rationale,
      resolved_by: operatorId,
      resolved_at: now,
      updated_at: now,
    })
    .eq('dispute_id', disputeId);

  // Apply resolution effects
  if (resolution === 'reversed') {
    await supabase
      .from('receipts')
      .update({ graph_weight: 0.0, dispute_status: 'reversed' })
      .eq('receipt_id', dispute.receipt_id);

    // Recompute stored score — due process must actually undo harm.
    // Trust-bearing: MUST fail closed. A reversed receipt with a stale score
    // means the entity is still penalized despite winning their dispute.
    const { data: newScore, error: scoreError } = await supabase.rpc('compute_emilia_score', {
      p_entity_id: dispute.entity_id,
    });
    if (scoreError) {
      throw new ProtocolWriteError(
        `Score recomputation after reversal failed: ${scoreError.message}`,
        { code: 'SCORE_RECOMPUTATION_FAILED', cause: scoreError }
      );
    }
    if (newScore !== null && newScore !== undefined) {
      const { error: updateError } = await supabase
        .from('entities')
        .update({ emilia_score: newScore, updated_at: now })
        .eq('id', dispute.entity_id);
      if (updateError) {
        throw new ProtocolWriteError(
          `Score update after reversal failed: ${updateError.message}`,
          { code: 'SCORE_UPDATE_FAILED', cause: updateError }
        );
      }
    }

    // Rematerialize trust profile
    await materializeTrustProfile(dispute.entity_id);
  } else if (resolution === 'upheld') {
    await supabase
      .from('receipts')
      .update({ dispute_status: 'upheld' })
      .eq('receipt_id', dispute.receipt_id);
  } else {
    await supabase
      .from('receipts')
      .update({ dispute_status: 'dismissed' })
      .eq('receipt_id', dispute.receipt_id);
  }

  emitEvent(WRITE_EVENTS.DISPUTE_RESOLVED, {
    dispute_id: disputeId,
    resolution,
    entity_id: dispute.entity_id,
    receipt_id: dispute.receipt_id,
  });

  return { dispute_id: disputeId, resolution, resolved_at: now };
}

/**
 * Confirm or dispute a bilateral receipt through the canonical write path.
 */
export async function canonicalBilateralConfirm(receiptId, confirmingEntityId, confirm) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: receipt } = await supabase
    .from('receipts')
    .select('receipt_id, entity_id, submitted_by, bilateral_status, confirmation_deadline')
    .eq('receipt_id', receiptId)
    .single();

  if (!receipt) return { error: 'Receipt not found', status: 404 };
  if (receipt.entity_id !== confirmingEntityId) {
    return { error: 'Only the subject entity can confirm', status: 403 };
  }
  // Prevent submitter from confirming their own receipt (would inflate provenance tier fraudulently)
  if (receipt.submitted_by === confirmingEntityId) {
    return { error: 'The receipt submitter cannot confirm their own receipt', status: 403 };
  }
  if (receipt.bilateral_status !== 'pending_confirmation') {
    return { error: `Status is '${receipt.bilateral_status}', not pending`, status: 409 };
  }
  if (receipt.confirmation_deadline && new Date(receipt.confirmation_deadline) < new Date()) {
    await supabase.from('receipts').update({ bilateral_status: 'expired' }).eq('receipt_id', receiptId);
    emitEvent(WRITE_EVENTS.RECEIPT_BILATERAL_EXPIRED, { receipt_id: receiptId });
    return { error: 'Confirmation deadline expired', status: 410 };
  }

  if (confirm) {
    await supabase.from('receipts').update({
      bilateral_status: 'confirmed',
      provenance_tier: 'bilateral',
      confirmed_by: confirmingEntityId,
      confirmed_at: now,
    }).eq('receipt_id', receiptId);

    emitEvent(WRITE_EVENTS.RECEIPT_BILATERAL_CONFIRMED, { receipt_id: receiptId });
    await materializeTrustProfile(receipt.entity_id);

    return { receipt_id: receiptId, bilateral_status: 'confirmed', provenance_tier: 'bilateral' };
  } else {
    await supabase.from('receipts').update({
      bilateral_status: 'disputed',
      confirmed_by: confirmingEntityId,
      confirmed_at: now,
    }).eq('receipt_id', receiptId);

    emitEvent(WRITE_EVENTS.RECEIPT_BILATERAL_DISPUTED, { receipt_id: receiptId });
    return { receipt_id: receiptId, bilateral_status: 'disputed', provenance_tier: 'self_attested' };
  }
}

/**
 * Retry helper with exponential backoff.
 * Attempts fn up to maxAttempts times, doubling the delay after each failure.
 */
async function withRetry(fn, maxAttempts = 3, baseDelayMs = 200) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (e) {
      if (attempt === maxAttempts) throw e;
      await new Promise(r => setTimeout(r, baseDelayMs * attempt));
    }
  }
}

/**
 * Materialize (cache) a trust profile after a write event.
 * 
 * Stores the full trust snapshot as JSONB on the entity row.
 * The canonical evaluator checks trust_materialized_at — if fresh
 * (< 5 min), it returns the snapshot without recomputing from receipts.
 * 
 * This is the hook where caching, webhooks, and event dispatch
 * would be wired in.
 */
async function materializeTrustProfile(entityDbId) {
  if (!entityDbId) return;
  const supabase = getServiceClient();

  // Trust-bearing: MUST fail closed. A failed materialization means the
  // cached trust snapshot is stale, leading to incorrect trust decisions.

  // Recompute score via SQL
  const { data: newScore, error: scoreError } = await supabase.rpc('compute_emilia_score', {
    p_entity_id: entityDbId,
  });
  if (scoreError) {
    throw new ProtocolWriteError(
      `Trust materialization failed — score recomputation error: ${scoreError.message}`,
      { code: 'MATERIALIZATION_SCORE_FAILED', cause: scoreError }
    );
  }

  // Fetch receipts for full profile snapshot
  const { data: receipts, error: receiptsError } = await supabase
    .from('receipts')
    .select('*')
    .eq('entity_id', entityDbId)
    .order('created_at', { ascending: false })
    .limit(200);
  if (receiptsError) {
    throw new ProtocolWriteError(
      `Trust materialization failed — receipt fetch error: ${receiptsError.message}`,
      { code: 'MATERIALIZATION_RECEIPTS_FAILED', cause: receiptsError }
    );
  }

  // Compute the full trust profile
  const { computeTrustProfile } = await import('@/lib/scoring-v2');
  const { data: entity, error: entityError } = await supabase
    .from('entities')
    .select('*')
    .eq('id', entityDbId)
    .single();
  if (entityError) {
    throw new ProtocolWriteError(
      `Trust materialization failed — entity fetch error: ${entityError.message}`,
      { code: 'MATERIALIZATION_ENTITY_FAILED', cause: entityError }
    );
  }

  const profile = computeTrustProfile(receipts || [], entity || {});

  const now = new Date().toISOString();
  const snapshot = {
    score: profile.score,
    confidence: profile.confidence,
    effectiveEvidence: profile.effectiveEvidence,
    uniqueSubmitters: profile.uniqueSubmitters,
    receiptCount: profile.receiptCount,
    profile: profile.profile,
    anomaly: profile.anomaly,
  };

  // Retry with exponential backoff — trust snapshot persistence is critical
  await withRetry(async () => {
    const { error: updateError } = await supabase
      .from('entities')
      .update({
        emilia_score: newScore ?? profile.score,
        trust_snapshot: snapshot,
        trust_materialized_at: now,
        updated_at: now,
      })
      .eq('id', entityDbId);
    if (updateError) {
      throw new ProtocolWriteError(
        `Trust materialization failed — snapshot update error: ${updateError.message}`,
        { code: 'MATERIALIZATION_UPDATE_FAILED', cause: updateError }
      );
    }
  });

  // Non-truth-bearing: safe to degrade — event emission is observability only
  emitEvent(WRITE_EVENTS.TRUST_RECOMPUTED, {
    entity_id: entityDbId,
    new_score: newScore ?? profile.score,
    confidence: profile.confidence,
  });
}

export { materializeTrustProfile };

/**
 * File a dispute through the canonical write path.
 * 
 * Enforces: deduplication (no active dispute on same receipt),
 * filer type classification, receipt status update, event emission.
 */
export async function canonicalFileDispute(params, filerEntity) {
  const supabase = getServiceClient();
  const { randomBytes } = await import('crypto');

  // Validate receipt
  const { data: receipt } = await supabase
    .from('receipts')
    .select('receipt_id, entity_id, submitted_by')
    .eq('receipt_id', params.receipt_id)
    .single();

  if (!receipt) return { error: 'Receipt not found', status: 404 };

  // Check for active dispute on same receipt
  const { data: existing } = await supabase
    .from('disputes')
    .select('dispute_id, status')
    .eq('receipt_id', params.receipt_id)
    .in('status', ['open', 'under_review'])
    .limit(1);

  if (existing && existing.length > 0) {
    return {
      error: 'This receipt already has an active dispute',
      existing_dispute: existing[0].dispute_id,
      status: 409,
    };
  }

  // Classify filer
  let filedByType = 'third_party';
  if (filerEntity.id === receipt.entity_id) filedByType = 'receipt_subject';
  else if (filerEntity.id === receipt.submitted_by) filedByType = 'affected_entity';

  const disputeId = `ep_disp_${randomBytes(16).toString('hex')}`;

  const { data: dispute, error: insertError } = await supabase
    .from('disputes')
    .insert({
      dispute_id: disputeId,
      receipt_id: params.receipt_id,
      entity_id: receipt.entity_id,
      filed_by: filerEntity.id,
      filed_by_type: filedByType,
      reason: params.reason,
      description: params.description || null,
      evidence: params.evidence || null,
    })
    .select()
    .single();

  if (insertError) return { error: 'Failed to file dispute', status: 500, _raw: insertError };

  // Mark receipt as challenged
  await supabase
    .from('receipts')
    .update({ dispute_status: 'challenged' })
    .eq('receipt_id', params.receipt_id);

  emitEvent(WRITE_EVENTS.DISPUTE_FILED, {
    dispute_id: disputeId,
    receipt_id: params.receipt_id,
    entity_id: receipt.entity_id,
    filed_by: filerEntity.entity_id,
    filed_by_type: filedByType,
  });

  return {
    dispute_id: dispute.dispute_id,
    receipt_id: dispute.receipt_id,
    status: dispute.status,
    reason: dispute.reason,
    filed_by_type: filedByType,
    response_deadline: dispute.response_deadline,
  };
}

/**
 * Respond to a dispute through the canonical write path.
 * 
 * Enforces: only receipt submitter can respond, deadline check,
 * status transition open → under_review, event emission.
 */
export async function canonicalRespondDispute(disputeId, responderId, response, evidence) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: dispute } = await supabase
    .from('disputes')
    .select('*, receipt:receipts!disputes_receipt_id_fkey(submitted_by)')
    .eq('dispute_id', disputeId)
    .single();

  if (!dispute) return { error: 'Dispute not found', status: 404 };

  if (dispute.receipt?.submitted_by !== responderId) {
    return { error: 'Only the entity that submitted the disputed receipt can respond', status: 403 };
  }
  if (dispute.status !== 'open') {
    return { error: `Dispute is ${dispute.status}, not open for response`, status: 409 };
  }
  if (new Date(dispute.response_deadline) < new Date()) {
    return { error: 'Response deadline has passed (7 days from filing)', status: 410 };
  }

  await supabase
    .from('disputes')
    .update({
      response,
      response_evidence: evidence || null,
      responded_at: now,
      status: 'under_review',
      updated_at: now,
    })
    .eq('dispute_id', disputeId);

  await supabase
    .from('receipts')
    .update({ dispute_status: 'under_review' })
    .eq('receipt_id', dispute.receipt_id);

  emitEvent(WRITE_EVENTS.DISPUTE_RESPONDED, {
    dispute_id: disputeId,
    entity_id: dispute.entity_id,
    receipt_id: dispute.receipt_id,
  });

  return { dispute_id: disputeId, status: 'under_review' };
}

/**
 * File a human report through the canonical write path.
 * 
 * No auth required — this is the human appeal channel.
 * Reports do not directly affect trust. They create review objects.
 * 
 * Enforces: entity existence check, event emission.
 */
export async function canonicalFileReport(params) {
  const supabase = getServiceClient();
  const { randomBytes } = await import('crypto');

  // Verify entity exists
  const { data: entity } = await supabase
    .from('entities')
    .select('id, entity_id, display_name')
    .eq('entity_id', params.entity_id)
    .single();

  if (!entity) return { error: 'Entity not found', status: 404 };

  const reportId = `ep_rpt_${randomBytes(16).toString('hex')}`;

  const { error: insertError } = await supabase
    .from('trust_reports')
    .insert({
      report_id: reportId,
      entity_id: entity.id,
      report_type: params.report_type,
      description: params.description,
      contact_email: params.contact_email || null,
      evidence: params.evidence || null,
      reporter_ip_hash: params.reporter_ip_hash || null,
    });

  if (insertError) return { error: 'Failed to file report', status: 500, _raw: insertError };

  emitEvent(WRITE_EVENTS.REPORT_FILED, {
    report_id: reportId,
    entity_id: params.entity_id,
    report_type: params.report_type,
  });

  return {
    report_id: reportId,
    entity_id: params.entity_id,
    display_name: entity.display_name,
  };
}


/**
 * Appeal a dispute resolution. Any affected party can appeal.
 * Transitions: upheld → appealed, reversed → appealed, dismissed → appealed
 * 
 * "Trust must never be more powerful than appeal."
 */
export async function canonicalAppealDispute(disputeId, appealerEntity, reason, evidence) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: dispute } = await supabase
    .from('disputes')
    .select('*')
    .eq('dispute_id', disputeId)
    .single();

  if (!dispute) return { error: 'Dispute not found', status: 404 };

  // Only resolved disputes can be appealed
  if (!['upheld', 'reversed', 'dismissed'].includes(dispute.status)) {
    return { error: `Cannot appeal a dispute in state "${dispute.status}". Only upheld, reversed, or dismissed disputes may be appealed.`, status: 409 };
  }

  // Validate the appealer is a party to the dispute
  const isParty = [
    dispute.entity_id,
    dispute.filed_by,
  ].includes(appealerEntity.id);

  if (!isParty) {
    return { error: 'Only dispute participants may appeal a resolution.', status: 403 };
  }

  if (!reason || reason.trim().length < 10) {
    return { error: 'Appeal reason must be at least 10 characters.', status: 400 };
  }

  // Transition to appealed
  const { error: updateError } = await supabase
    .from('disputes')
    .update({
      status: 'appealed',
      appeal_reason: reason,
      appeal_evidence: evidence || null,
      appealed_at: now,
      appealed_by: appealerEntity.id,
      updated_at: now,
    })
    .eq('dispute_id', disputeId);

  if (updateError) {
    console.error('Appeal update error:', updateError);
    return { error: 'Failed to file appeal', status: 500 };
  }

  // If the original resolution was 'reversed', the receipt was neutralized.
  // Mark receipt as under appeal — the reversal stands until appeal is resolved.
  await supabase
    .from('receipts')
    .update({ dispute_status: 'appealed' })
    .eq('receipt_id', dispute.receipt_id);

  emitEvent(WRITE_EVENTS.DISPUTE_APPEALED, {
    dispute_id: disputeId,
    resolution: 'appealed',
    entity_id: dispute.entity_id,
    appealed_by: appealerEntity.id,
  });

  return {
    dispute_id: disputeId,
    status: 'appealed',
    appealed_at: now,
    _message: 'Appeal filed. An appeal reviewer will evaluate the original resolution.',
  };
}

/**
 * Resolve an appeal. Operator-level action.
 * Transitions: appealed → appeal_upheld | appeal_reversed | appeal_dismissed
 */
export async function canonicalResolveAppeal(disputeId, resolution, rationale, operatorId) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: dispute } = await supabase
    .from('disputes')
    .select('*')
    .eq('dispute_id', disputeId)
    .single();

  if (!dispute) return { error: 'Dispute not found', status: 404 };
  if (dispute.status !== 'appealed') {
    return { error: `Cannot resolve appeal — dispute is in state "${dispute.status}", not "appealed".`, status: 409 };
  }

  const validResolutions = ['appeal_upheld', 'appeal_reversed', 'appeal_dismissed'];
  if (!validResolutions.includes(resolution)) {
    return { error: `resolution must be one of: ${validResolutions.join(', ')}`, status: 400 };
  }

  await supabase
    .from('disputes')
    .update({
      status: resolution,
      appeal_resolution: resolution,
      appeal_rationale: rationale,
      appeal_resolved_by: operatorId,
      appeal_resolved_at: now,
      updated_at: now,
    })
    .eq('dispute_id', disputeId);

  // Apply appeal resolution effects
  if (resolution === 'appeal_reversed') {
    // The appeal overturns the original resolution.
    // If original was 'upheld' (receipt stood) → now reverse the receipt
    if (dispute.resolution === 'upheld') {
      await supabase
        .from('receipts')
        .update({ graph_weight: 0.0, dispute_status: 'appeal_reversed' })
        .eq('receipt_id', dispute.receipt_id);
      // Trust-bearing: MUST fail closed — appeal reversal must recompute score
      const { data: newScore, error: scoreError } = await supabase.rpc('compute_emilia_score', {
        p_entity_id: dispute.entity_id,
      });
      if (scoreError) {
        throw new ProtocolWriteError(
          `Score recomputation after appeal reversal failed: ${scoreError.message}`,
          { code: 'SCORE_RECOMPUTATION_FAILED', cause: scoreError }
        );
      }
      if (newScore !== null && newScore !== undefined) {
        const { error: updateError } = await supabase
          .from('entities')
          .update({ emilia_score: newScore, updated_at: now })
          .eq('id', dispute.entity_id);
        if (updateError) {
          throw new ProtocolWriteError(
            `Score update after appeal reversal failed: ${updateError.message}`,
            { code: 'SCORE_UPDATE_FAILED', cause: updateError }
          );
        }
      }
      await materializeTrustProfile(dispute.entity_id);
    }
    // If original was 'reversed' (receipt was neutralized) → restore the receipt
    if (dispute.resolution === 'reversed') {
      await supabase
        .from('receipts')
        .update({ graph_weight: 1.0, dispute_status: 'appeal_reversed' })
        .eq('receipt_id', dispute.receipt_id);
      // Trust-bearing: MUST fail closed — appeal reversal must recompute score
      const { data: newScore, error: scoreError } = await supabase.rpc('compute_emilia_score', {
        p_entity_id: dispute.entity_id,
      });
      if (scoreError) {
        throw new ProtocolWriteError(
          `Score recomputation after appeal reversal failed: ${scoreError.message}`,
          { code: 'SCORE_RECOMPUTATION_FAILED', cause: scoreError }
        );
      }
      if (newScore !== null && newScore !== undefined) {
        const { error: updateError } = await supabase
          .from('entities')
          .update({ emilia_score: newScore, updated_at: now })
          .eq('id', dispute.entity_id);
        if (updateError) {
          throw new ProtocolWriteError(
            `Score update after appeal reversal failed: ${updateError.message}`,
            { code: 'SCORE_UPDATE_FAILED', cause: updateError }
          );
        }
      }
      await materializeTrustProfile(dispute.entity_id);
    }
  } else {
    // appeal_upheld or appeal_dismissed — original resolution stands
    await supabase
      .from('receipts')
      .update({ dispute_status: resolution })
      .eq('receipt_id', dispute.receipt_id);
  }

  emitEvent(WRITE_EVENTS.DISPUTE_APPEAL_RESOLVED, {
    dispute_id: disputeId,
    resolution,
    entity_id: dispute.entity_id,
    appeal_overturns: resolution === 'appeal_reversed' ? dispute.resolution : null,
  });

  return {
    dispute_id: disputeId,
    status: resolution,
    appeal_resolved_at: now,
    original_resolution: dispute.resolution,
    _message: resolution === 'appeal_reversed'
      ? 'Appeal granted — original resolution overturned. Trust state recomputed.'
      : 'Appeal resolved — original resolution stands.',
  };
}

/**
 * Withdraw a dispute. Only the filer can withdraw, and only from open state.
 */
export async function canonicalWithdrawDispute(disputeId, withdrawerEntity) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: dispute } = await supabase
    .from('disputes')
    .select('*')
    .eq('dispute_id', disputeId)
    .single();

  if (!dispute) return { error: 'Dispute not found', status: 404 };
  if (dispute.status !== 'open') {
    return { error: `Cannot withdraw — dispute is "${dispute.status}", not "open".`, status: 409 };
  }
  if (dispute.filed_by !== withdrawerEntity.id) {
    return { error: 'Only the filer can withdraw a dispute.', status: 403 };
  }

  await supabase
    .from('disputes')
    .update({ status: 'withdrawn', updated_at: now })
    .eq('dispute_id', disputeId);

  await supabase
    .from('receipts')
    .update({ dispute_status: null })
    .eq('receipt_id', dispute.receipt_id);

  return { dispute_id: disputeId, status: 'withdrawn', _message: 'Dispute withdrawn.' };
}
