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

import { getServiceClient } from '@/lib/supabase';
import { createReceipt } from '@/lib/create-receipt';

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
  REPORT_FILED: 'report.filed',
  ENTITY_REGISTERED: 'entity.registered',
  TRUST_RECOMPUTED: 'trust.recomputed',
};

/**
 * In-memory event log for this request lifecycle.
 * In production, this would be an event bus / webhook dispatcher.
 */
const eventLog = [];

function emitEvent(type, payload) {
  const event = {
    type,
    timestamp: new Date().toISOString(),
    ...payload,
  };
  eventLog.push(event);
  // Future: dispatch to webhook subscriptions, audit log, event store
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

    // Recompute stored score — due process must actually undo harm
    try {
      const { data: newScore } = await supabase.rpc('compute_emilia_score', {
        p_entity_id: dispute.entity_id,
      });
      if (newScore !== null && newScore !== undefined) {
        await supabase
          .from('entities')
          .update({ emilia_score: newScore, updated_at: now })
          .eq('id', dispute.entity_id);
      }
    } catch (e) {
      console.warn('Score recomputation after reversal failed:', e.message);
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
    .select('receipt_id, entity_id, bilateral_status, confirmation_deadline')
    .eq('receipt_id', receiptId)
    .single();

  if (!receipt) return { error: 'Receipt not found', status: 404 };
  if (receipt.entity_id !== confirmingEntityId) {
    return { error: 'Only the subject entity can confirm', status: 403 };
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
  try {
    // Recompute score via SQL
    const { data: newScore } = await supabase.rpc('compute_emilia_score', {
      p_entity_id: entityDbId,
    });

    // Fetch receipts for full profile snapshot
    const { data: receipts } = await supabase
      .from('receipts')
      .select('*')
      .eq('entity_id', entityDbId)
      .order('created_at', { ascending: false })
      .limit(200);

    // Compute the full trust profile
    const { computeTrustProfile } = await import('@/lib/scoring-v2');
    const { data: entity } = await supabase
      .from('entities')
      .select('*')
      .eq('id', entityDbId)
      .single();

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

    await supabase
      .from('entities')
      .update({
        emilia_score: newScore ?? profile.score,
        trust_snapshot: snapshot,
        trust_materialized_at: now,
        updated_at: now,
      })
      .eq('id', entityDbId);

    emitEvent(WRITE_EVENTS.TRUST_RECOMPUTED, {
      entity_id: entityDbId,
      new_score: newScore ?? profile.score,
      confidence: profile.confidence,
    });
  } catch (e) {
    console.warn('Trust materialization failed:', e.message);
  }
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
