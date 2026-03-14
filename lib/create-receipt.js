/**
 * EMILIA Protocol — Receipt Creation Helper
 *
 * ONE receipt creation engine. ONE truth path.
 * Both /api/receipts/submit and /api/needs/[id]/rate MUST use this.
 */

import { getServiceClient } from '@/lib/supabase';
import { computeReceiptComposite, computeReceiptHash, behaviorToSatisfaction, computeScoresFromClaims } from '@/lib/scoring';
import { runReceiptFraudChecks } from '@/lib/sybil';
import crypto from 'crypto';

/**
 * Create a receipt through the canonical trust path.
 *
 * @param {Object} params
 * @param {string} params.targetEntitySlug - entity_id slug or UUID of entity being scored
 * @param {Object} params.submitter - Authenticated submitter entity object (from auth)
 * @param {string} params.transactionRef - Required external transaction reference
 * @param {string} params.transactionType - purchase | service | task_completion | delivery | return
 * @param {Object} [params.signals] - { delivery_accuracy, product_accuracy, price_integrity, return_processing, agent_satisfaction }
 * @param {string} [params.agentBehavior] - completed | retried_same | retried_different | abandoned | disputed
 * @param {Object} [params.claims] - v2 structured claims
 * @param {Object} [params.evidence] - Supporting evidence
 * @returns {Object} { receipt, entityScore, warnings } or { error, status }
 */
export async function createReceipt(params) {
  const {
    targetEntitySlug,
    submitter,
    transactionRef,
    transactionType,
    signals = {},
    agentBehavior,
    claims,
    evidence = {},
    context = null,
    provenanceTier = 'self_attested',
    requestBilateral = false, // If true, sets bilateral_status to 'pending_confirmation'
  } = params;

  const supabase = getServiceClient();

  // === RESOLVE TARGET ENTITY ===
  const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetEntitySlug);
  const { data: targetEntity } = await supabase
    .from('entities')
    .select('id, entity_id')
    .eq(isUuid ? 'id' : 'entity_id', targetEntitySlug)
    .single();

  if (!targetEntity) {
    return { error: 'Target entity not found', status: 404 };
  }

  const targetEntityId = targetEntity.id;

  // === SELF-SCORE CHECK ===
  if (targetEntityId === submitter.id) {
    return { error: 'An entity cannot submit receipts for itself', status: 403 };
  }

  // === IDEMPOTENCY / DEDUPLICATION ===
  // Same transaction_ref + same submitter + same entity = duplicate.
  // Returns the existing receipt instead of creating a new one.
  // This makes receipt submission safe to retry.
  const { data: existingReceipt } = await supabase
    .from('receipts')
    .select('receipt_id, receipt_hash, created_at')
    .eq('entity_id', targetEntityId)
    .eq('submitted_by', submitter.id)
    .eq('transaction_ref', transactionRef)
    .single();

  if (existingReceipt) {
    return {
      receipt: existingReceipt,
      deduplicated: true,
      _message: 'Receipt already exists for this transaction_ref. Returning existing receipt (idempotent).',
    };
  }

  // === FRAUD CHECKS (graph analysis wired in) ===
  const fraudCheck = await runReceiptFraudChecks(supabase, targetEntityId, submitter.id);
  if (!fraudCheck.allowed) {
    return {
      error: fraudCheck.detail,
      flags: fraudCheck.flags,
      status: 429,
    };
  }

  // === SUBMITTER CREDIBILITY (via canonical DB function) ===
  const submitterScore = submitter.emilia_score ?? 50;

  let submitterEstablished = false;
  try {
    const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: submitter.id });
    if (estData && estData[0]) {
      submitterEstablished = estData[0].established;
    }
  } catch {
    // Fallback if function doesn't exist yet (pre-migration)
    submitterEstablished = false;
  }

  // === BEHAVIORAL SATISFACTION ===
  let agentSatisfaction = signals.agent_satisfaction ?? null;
  if (agentBehavior) {
    agentSatisfaction = behaviorToSatisfaction(agentBehavior);
  }

  // === EVIDENCE-BASED SCORING (v2) ===
  let deliveryAccuracy = signals.delivery_accuracy ?? null;
  let productAccuracy = signals.product_accuracy ?? null;
  let priceIntegrity = signals.price_integrity ?? null;
  let returnProcessing = signals.return_processing ?? null;

  if (claims) {
    const claimScores = computeScoresFromClaims(claims);
    if (claimScores.delivery_accuracy != null) deliveryAccuracy = claimScores.delivery_accuracy;
    if (claimScores.product_accuracy != null) productAccuracy = claimScores.product_accuracy;
    if (claimScores.price_integrity != null) priceIntegrity = claimScores.price_integrity;
    if (claimScores.return_processing != null) returnProcessing = claimScores.return_processing;
  }

  // Post-processing validation: ensure receipt has at least one meaningful signal
  const hasAnySignal = [deliveryAccuracy, productAccuracy, priceIntegrity,
    returnProcessing, agentSatisfaction].some(v => v != null);
  if (!hasAnySignal) {
    return { error: 'Receipt produced no meaningful signals. Claims must include recognized fields (delivered, on_time, price_honored, as_described, return_accepted).', status: 400 };
  }

  // === COMPOSITE SCORE ===
  const composite = computeReceiptComposite({
    delivery_accuracy: deliveryAccuracy,
    product_accuracy: productAccuracy,
    price_integrity: priceIntegrity,
    return_processing: returnProcessing,
    agent_satisfaction: agentSatisfaction,
  });

  // === CHAIN LINKING ===
  const { data: prevReceipt } = await supabase
    .from('receipts')
    .select('receipt_hash')
    .eq('entity_id', targetEntityId)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  const previousHash = prevReceipt?.receipt_hash || null;
  const receiptId = `ep_rcpt_${crypto.randomBytes(16).toString('hex')}`;

  // === CANONICAL HASH (all truth-bearing fields) ===
  const receiptData = {
    entity_id: targetEntityId,
    submitted_by: submitter.id,
    transaction_ref: transactionRef,
    transaction_type: transactionType,
    context: context || null,
    delivery_accuracy: deliveryAccuracy,
    product_accuracy: productAccuracy,
    price_integrity: priceIntegrity,
    return_processing: returnProcessing,
    agent_satisfaction: agentSatisfaction,
    agent_behavior: agentBehavior || null,
    claims: claims || null,
    evidence: evidence,
    submitter_score: submitterScore,
    submitter_established: submitterEstablished,
  };

  const receiptHash = await computeReceiptHash(receiptData, previousHash);

  // === INSERT ===
  const { data: receipt, error: insertError } = await supabase
    .from('receipts')
    .insert({
      receipt_id: receiptId,
      entity_id: targetEntityId,
      submitted_by: submitter.id,
      transaction_ref: transactionRef,
      transaction_type: transactionType,
      context: context || null,
      delivery_accuracy: deliveryAccuracy,
      product_accuracy: productAccuracy,
      price_integrity: priceIntegrity,
      return_processing: returnProcessing,
      agent_satisfaction: agentSatisfaction,
      agent_behavior: agentBehavior || null,
      evidence: evidence,
      claims: claims || null,
      submitter_score: submitterScore,
      submitter_established: submitterEstablished,
      graph_weight: fraudCheck.graphWeight ?? 1.0,
      provenance_tier: provenanceTier,
      bilateral_status: requestBilateral ? 'pending_confirmation' : null,
      confirmation_deadline: requestBilateral ? new Date(Date.now() + 48 * 3600000).toISOString() : null,
      composite_score: composite,
      receipt_hash: receiptHash,
      previous_hash: previousHash,
    })
    .select()
    .single();

  if (insertError) {
    console.error('Receipt insert error:', insertError);
    return { error: 'Failed to submit receipt', status: 500 };
  }

  // === GET UPDATED SCORE ===
  const { data: updatedEntity } = await supabase
    .from('entities')
    .select('emilia_score, total_receipts')
    .eq('id', targetEntityId)
    .single();

  const result = {
    receipt: {
      receipt_id: receipt.receipt_id,
      entity_id: receipt.entity_id,
      composite_score: receipt.composite_score,
      receipt_hash: receipt.receipt_hash,
      created_at: receipt.created_at,
    },
    entityScore: {
      emilia_score: updatedEntity?.emilia_score,
      total_receipts: updatedEntity?.total_receipts,
    },
  };

  if (fraudCheck.flags.length > 0) {
    result.warnings = fraudCheck.flags;
  }

  return result;
}
