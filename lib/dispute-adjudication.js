/**
 * EP Trust-Graph Dispute Adjudication
 * @license Apache-2.0
 *
 * The immune system of the trust ledger. When a dispute enters adjudication,
 * the trust graph itself renders a verdict — entities who have actually
 * transacted with the disputed party vote with their receipts, weighted by
 * their own credibility. This is adversarially robust: you can't manufacture
 * a favorable vote without manufacturing real transaction history first.
 *
 * Adjudication flow:
 * 1. Identify vouchers: entities with confidence >= 'confident' who have
 *    submitted receipts for (or received receipts from) the disputed entity
 * 2. For each voucher, compute their behavioral sentiment toward the disputed
 *    entity by examining their shared receipt history
 * 3. Weight their implicit votes by their own confidence_score (0.0–1.0)
 * 4. Aggregate: weighted_uphold_mass vs weighted_dismiss_mass
 * 5. Produce: uphold_dispute | dismiss_dispute | inconclusive
 *
 * Vote inference logic:
 * - A voucher's receipts with the disputed entity reveal ground truth:
 *   - High completion rate in shared history → implicit DISMISS (entity is trustworthy)
 *   - Disputes/abandons in shared history → implicit UPHOLD (entity is problematic)
 * - Weight = voucher's own confidence_score derived from their trust_snapshot
 * - Threshold: weighted_uphold_fraction > 0.6 → UPHOLD
 *              weighted_uphold_fraction < 0.4 → DISMISS
 *              otherwise → INCONCLUSIVE
 *
 * Constitutional constraint: adjudication never overwrites human appeal.
 * The result is a RECOMMENDATION stored in adjudication_result JSONB.
 * Human operators retain final authority.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';

// =============================================================================
// CONFIDENCE TIER → NUMERIC SCORE
// Maps the string confidence tier to a 0.0–1.0 voting weight.
// Uses the midpoint of each tier's evidence range, calibrated to scoring-v2:
//   pending:      0 effective evidence   → weight 0 (cannot vote)
//   insufficient: <1 effective evidence  → weight 0 (cannot vote)
//   provisional:  1–5, not established   → weight 0.3
//   emerging:     5–20, established      → weight 0.6
//   confident:    >=20, established      → weight 1.0
//
// Only 'confident' and 'emerging' entities are admitted as vouchers.
// 'established' is an alias for 'confident' in legacy snapshots.
// =============================================================================

const CONFIDENCE_WEIGHT = {
  pending:      0.0,
  insufficient: 0.0,
  provisional:  0.3,
  emerging:     0.6,
  confident:    1.0,
  established:  1.0, // legacy alias
};

// Voucher admission gate: only these confidence tiers can vote.
const VOUCHER_MIN_TIERS = new Set(['confident', 'emerging', 'established']);

// Behavior values matching scoring-v2.js BEHAVIOR_VALUES — used to infer sentiment.
// Higher = positive sentiment toward the disputed entity (dismiss), lower = negative (uphold).
const BEHAVIOR_SENTIMENT = {
  completed:         1.0,  // Strong positive — entity delivered
  retried_same:      0.5,  // Neutral-positive — had to retry but stayed
  retried_different: 0.15, // Negative — had to switch away
  abandoned:         0.0,  // Strong negative — walked away entirely
  disputed:         -0.2,  // Very negative — formally contested
};

// Adjudication thresholds
const UPHOLD_THRESHOLD  = 0.60; // weighted_uphold_fraction > 0.60 → uphold
const DISMISS_THRESHOLD = 0.40; // weighted_uphold_fraction < 0.40 → dismiss
const MIN_VOUCHERS_FOR_DECISION = 2; // need at least 2 vouchers to make a call
const VOUCHER_LIMIT = 20;        // cap at 20 most-recent vouchers

// =============================================================================
// findVouchers
// =============================================================================

/**
 * Find high-confidence entities who have transaction history with the disputed entity.
 *
 * A "voucher" is an entity that appears as the submitter on a receipt where
 * the disputed entity is the subject — i.e., they have directly experienced
 * transacting with that entity and have the receipts to prove it.
 *
 * We also check the reverse direction: receipts where the disputed entity
 * submitted about the voucher. This bidirectional check catches cases where
 * the disputed entity is a service provider who submits receipts about buyers,
 * or an agent who submitted receipts about merchants they used.
 *
 * @param {string} disputedEntityId - UUID of entity under dispute (entities.id)
 * @param {object} supabase - Supabase client
 * @returns {Promise<Array<{
 *   entity_id: string,       // entities.id (UUID)
 *   entity_slug: string,     // entities.entity_id (human slug)
 *   confidence: string,      // confidence tier string
 *   confidence_score: number, // 0.0–1.0 weight for this voucher's vote
 *   receipt_count: number,   // how many shared receipts with disputed entity
 *   direction: string,       // 'submitted_about' | 'received_from' | 'both'
 * }>}
 */
export async function findVouchers(disputedEntityId, supabase) {
  // --- Direction 1: voucher submitted receipts ABOUT the disputed entity ---
  // receipts.submitted_by = voucher, receipts.entity_id = disputed
  const { data: submitterRows } = await supabase
    .from('receipts')
    .select('submitted_by, entity_id')
    .eq('entity_id', disputedEntityId)
    .neq('submitted_by', disputedEntityId) // exclude self-receipts
    .order('created_at', { ascending: false })
    .limit(200); // broad fetch; we'll deduplicate and filter after

  // --- Direction 2: disputed entity submitted receipts ABOUT the voucher ---
  // receipts.submitted_by = disputed, receipts.entity_id = voucher
  const { data: receiverRows } = await supabase
    .from('receipts')
    .select('submitted_by, entity_id')
    .eq('submitted_by', disputedEntityId)
    .neq('entity_id', disputedEntityId)
    .order('created_at', { ascending: false })
    .limit(200);

  // Tally counterparty UUIDs and their direction
  // Map: entity_uuid → { as_submitter: count, as_subject: count }
  const counterpartyTally = new Map();

  for (const row of (submitterRows || [])) {
    const id = row.submitted_by;
    if (!counterpartyTally.has(id)) counterpartyTally.set(id, { as_submitter: 0, as_subject: 0 });
    counterpartyTally.get(id).as_submitter += 1;
  }
  for (const row of (receiverRows || [])) {
    const id = row.entity_id;
    if (!counterpartyTally.has(id)) counterpartyTally.set(id, { as_submitter: 0, as_subject: 0 });
    counterpartyTally.get(id).as_subject += 1;
  }

  if (counterpartyTally.size === 0) return [];

  // Fetch entity records with trust snapshots for all candidate counterparties
  const candidateIds = Array.from(counterpartyTally.keys());
  const { data: entityRows } = await supabase
    .from('entities')
    .select('id, entity_id, display_name, trust_snapshot, emilia_score, status')
    .in('id', candidateIds)
    .eq('status', 'active');

  if (!entityRows || entityRows.length === 0) return [];

  // Filter to admitted confidence tiers and build voucher list
  const vouchers = [];
  for (const entity of entityRows) {
    // Read confidence from trust_snapshot (materialized) or fall back to a
    // safe default. We never trust self-reported confidence.
    const snapshot = entity.trust_snapshot;
    const confidence = snapshot?.confidence ?? 'pending';

    if (!VOUCHER_MIN_TIERS.has(confidence)) continue;

    const confidenceScore = CONFIDENCE_WEIGHT[confidence] ?? 0;
    const tally = counterpartyTally.get(entity.id);
    const receiptCount = (tally?.as_submitter ?? 0) + (tally?.as_subject ?? 0);

    let direction;
    if (tally.as_submitter > 0 && tally.as_subject > 0) direction = 'both';
    else if (tally.as_submitter > 0) direction = 'submitted_about';
    else direction = 'received_from';

    vouchers.push({
      entity_id: entity.id,
      entity_slug: entity.entity_id,
      display_name: entity.display_name,
      confidence,
      confidence_score: confidenceScore,
      receipt_count: receiptCount,
      direction,
    });
  }

  // Sort by receipt_count DESC (most experienced vouchers first), then
  // by confidence_score DESC as tiebreaker — most credible voices first.
  vouchers.sort((a, b) => {
    if (b.receipt_count !== a.receipt_count) return b.receipt_count - a.receipt_count;
    return b.confidence_score - a.confidence_score;
  });

  return vouchers.slice(0, VOUCHER_LIMIT);
}

// =============================================================================
// fetchVoucherSentiment
// =============================================================================

/**
 * Fetch a voucher's receipts with the disputed entity and compute their
 * behavioral sentiment toward that entity.
 *
 * Sentiment is derived from agent_behavior fields — the same behavioral signal
 * that scoring-v2.js treats as Tier 1 (harder to fake, more aligned).
 *
 * @param {string} voucherEntityId - UUID of the voucher (entities.id)
 * @param {string} disputedEntityId - UUID of the disputed entity (entities.id)
 * @param {object} supabase - Supabase client
 * @returns {Promise<{ sentiment: number, receipt_count: number, behavior_breakdown: object }>}
 *   sentiment: 0.0 (very negative) to 1.0 (very positive)
 */
async function fetchVoucherSentiment(voucherEntityId, disputedEntityId, supabase) {
  // Receipts where voucher submitted about disputed entity
  const { data: submittedAbout } = await supabase
    .from('receipts')
    .select('agent_behavior, composite_score')
    .eq('entity_id', disputedEntityId)
    .eq('submitted_by', voucherEntityId)
    .order('created_at', { ascending: false })
    .limit(50);

  // Receipts where disputed entity submitted about voucher
  // These also carry signal — if the disputed entity was consistently
  // marking others as 'completed', they behaved professionally.
  // But we weight these lower since they're the disputed party's own submissions.
  const { data: receivedFrom } = await supabase
    .from('receipts')
    .select('agent_behavior, composite_score')
    .eq('entity_id', voucherEntityId)
    .eq('submitted_by', disputedEntityId)
    .order('created_at', { ascending: false })
    .limit(25);

  const behaviorCounts = {};
  let totalWeightedSentiment = 0;
  let totalWeight = 0;

  // Primary weight: receipts the voucher submitted (their own experience)
  for (const receipt of (submittedAbout || [])) {
    const behavior = receipt.agent_behavior;
    if (!behavior) continue;
    behaviorCounts[behavior] = (behaviorCounts[behavior] || 0) + 1;
    const raw = BEHAVIOR_SENTIMENT[behavior] ?? 0.5;
    // Normalize from [-0.2, 1.0] to [0, 1] for cleaner math
    const normalized = (raw + 0.2) / 1.2;
    totalWeightedSentiment += normalized * 1.0; // full weight
    totalWeight += 1.0;
  }

  // Secondary weight: receipts the disputed entity submitted (0.4x weight)
  // A disputed entity who consistently completed transactions for the voucher
  // is a mild positive signal, but we don't let the accused entity's own
  // self-serving submissions carry much weight in their own adjudication.
  for (const receipt of (receivedFrom || [])) {
    const behavior = receipt.agent_behavior;
    if (!behavior) continue;
    const raw = BEHAVIOR_SENTIMENT[behavior] ?? 0.5;
    const normalized = (raw + 0.2) / 1.2;
    totalWeightedSentiment += normalized * 0.4;
    totalWeight += 0.4;
  }

  const receiptCount = (submittedAbout?.length ?? 0) + (receivedFrom?.length ?? 0);

  if (totalWeight === 0 || receiptCount === 0) {
    // No behavioral data — sentiment is unknown, don't include in vote
    return { sentiment: null, receipt_count: 0, behavior_breakdown: {} };
  }

  const sentiment = totalWeightedSentiment / totalWeight;

  return {
    sentiment: Math.round(sentiment * 1000) / 1000,
    receipt_count: receiptCount,
    behavior_breakdown: behaviorCounts,
  };
}

// =============================================================================
// computeWeightedVote
// =============================================================================

/**
 * Compute the final weighted vote from vouchers and their sentiments.
 *
 * Vote logic:
 * - Each voucher has a sentiment score (0.0–1.0) toward the disputed entity
 *   - High sentiment (>= 0.65) → implicit DISMISS vote (entity behaved well)
 *   - Low sentiment (< 0.35) → implicit UPHOLD vote (entity behaved badly)
 *   - Middle sentiment (0.35–0.65) → abstain (mixed signals, don't force a call)
 * - Each vote is weighted by the voucher's confidence_score (0.0–1.0)
 * - weighted_uphold_fraction = sum(uphold_weight) / sum(all_participating_weight)
 *
 * Abstaining vouchers reduce the total participating weight but don't
 * shift the vote in either direction — they add uncertainty, correctly
 * pushing ambiguous cases toward INCONCLUSIVE.
 *
 * @param {Array} voucherSentiments - Array of { voucher, sentiment, receipt_count }
 * @returns {{
 *   recommendation: 'uphold_dispute' | 'dismiss_dispute' | 'inconclusive',
 *   confidence: number,       // 0.0–1.0, how decisive the result is
 *   weighted_uphold: number,  // raw weighted mass for uphold
 *   weighted_dismiss: number, // raw weighted mass for dismiss
 *   weighted_abstain: number, // raw weighted mass for abstain
 *   voucher_count: number,    // total vouchers queried
 *   participating_count: number, // vouchers with behavioral data
 *   uphold_fraction: number,  // weighted_uphold / (weighted_uphold + weighted_dismiss)
 * }}
 */
export function computeWeightedVote(voucherSentiments) {
  let weightedUphold  = 0;
  let weightedDismiss = 0;
  let weightedAbstain = 0;
  let participatingCount = 0;

  for (const { voucher, sentiment } of voucherSentiments) {
    if (sentiment === null) {
      // Voucher had no behavioral data — skip entirely, don't penalize
      continue;
    }

    participatingCount += 1;
    const w = voucher.confidence_score;

    // Sentiment is in [0, 1] after normalization:
    //   < 0.35 → entity behaved badly → UPHOLD the dispute
    //   > 0.65 → entity behaved well  → DISMISS the dispute
    //   0.35–0.65 → mixed / unclear   → ABSTAIN
    if (sentiment < 0.35) {
      weightedUphold += w;
    } else if (sentiment > 0.65) {
      weightedDismiss += w;
    } else {
      weightedAbstain += w;
    }
  }

  const totalDeciding = weightedUphold + weightedDismiss;
  const voucherCount  = voucherSentiments.length;

  // If no vouchers cast a decisive vote, the graph is inconclusive
  if (totalDeciding === 0 || participatingCount < MIN_VOUCHERS_FOR_DECISION) {
    return {
      recommendation: 'inconclusive',
      confidence: 0,
      weighted_uphold: Math.round(weightedUphold * 1000) / 1000,
      weighted_dismiss: Math.round(weightedDismiss * 1000) / 1000,
      weighted_abstain: Math.round(weightedAbstain * 1000) / 1000,
      voucher_count: voucherCount,
      participating_count: participatingCount,
      uphold_fraction: null,
    };
  }

  const upholdFraction = weightedUphold / totalDeciding;

  let recommendation;
  if (upholdFraction > UPHOLD_THRESHOLD) {
    recommendation = 'uphold_dispute';
  } else if (upholdFraction < DISMISS_THRESHOLD) {
    recommendation = 'dismiss_dispute';
  } else {
    recommendation = 'inconclusive';
  }

  // Confidence: how far the result is from the ambiguous middle (0.5).
  // At upholdFraction = 0.0 or 1.0 → confidence = 1.0 (unanimous)
  // At upholdFraction = 0.5 → confidence = 0.0 (coin flip)
  // Scaled so the thresholds (0.6, 0.4) correspond to roughly 0.2 confidence.
  const distanceFromMiddle = Math.abs(upholdFraction - 0.5) * 2; // [0, 1]
  // Penalize low participation: confidence scales with participating fraction
  const participationRatio = Math.min(1, participatingCount / Math.max(1, voucherCount));
  const rawConfidence = distanceFromMiddle * participationRatio;
  const confidence = Math.round(rawConfidence * 1000) / 1000;

  return {
    recommendation,
    confidence,
    weighted_uphold: Math.round(weightedUphold * 1000) / 1000,
    weighted_dismiss: Math.round(weightedDismiss * 1000) / 1000,
    weighted_abstain: Math.round(weightedAbstain * 1000) / 1000,
    voucher_count: voucherCount,
    participating_count: participatingCount,
    uphold_fraction: Math.round(upholdFraction * 1000) / 1000,
  };
}

// =============================================================================
// adjudicateDispute  (main entry point)
// =============================================================================

/**
 * Run trust evaluation for a dispute.
 *
 * This is the function that makes EP's adjudication adversarially robust.
 * It cannot be gamed without forging real transaction history across multiple
 * high-confidence entities — which is exactly what Sybil resistance prevents.
 *
 * @param {string} disputeId - The dispute_id string (ep_dispute_...)
 * @param {object} [supabaseOverride] - Optional Supabase client (defaults to service client)
 * @returns {Promise<{
 *   dispute_id: string,
 *   disputed_entity_id: string,
 *   receipt_id: string,
 *   adjudication: {
 *     recommendation: 'uphold_dispute' | 'dismiss_dispute' | 'inconclusive',
 *     confidence: number,
 *     voucher_count: number,
 *     participating_count: number,
 *     weighted_vote: { uphold_fraction, weighted_uphold, weighted_dismiss, weighted_abstain },
 *   },
 *   vouchers: Array,
 *   adjudicated_at: string,
 * } | { error: string, status: number }>}
 */
export async function adjudicateDispute(disputeId, supabaseOverride) {
  const supabase = supabaseOverride ?? getServiceClient();

  // -------------------------------------------------------------------
  // Step 1: Fetch the dispute record
  // -------------------------------------------------------------------
  const { data: dispute, error: disputeError } = await supabase
    .from('disputes')
    .select(`
      id,
      dispute_id,
      receipt_id,
      entity_id,
      filed_by,
      status,
      adjudication_result,
      adjudicated_at,
      created_at,
      response_deadline
    `)
    .eq('dispute_id', disputeId)
    .single();

  if (disputeError || !dispute) {
    return { error: 'Dispute not found', status: 404 };
  }

  // Adjudication is valid for open or under_review disputes.
  // Terminal states don't need re-adjudication.
  const adjudicatableStates = ['open', 'under_review'];
  if (!adjudicatableStates.includes(dispute.status)) {
    return {
      error: `Dispute is ${dispute.status} — adjudication only applies to open or under_review disputes`,
      status: 409,
    };
  }

  // -------------------------------------------------------------------
  // Step 2: Find vouchers — high-confidence entities with shared history
  // -------------------------------------------------------------------
  const vouchers = await findVouchers(dispute.entity_id, supabase);

  if (vouchers.length === 0) {
    // No vouchers means the trust graph has no opinion.
    // This is a valid outcome — graph is sparse for this entity.
    const result = {
      recommendation: 'inconclusive',
      confidence: 0,
      voucher_count: 0,
      participating_count: 0,
      weighted_vote: {
        uphold_fraction: null,
        weighted_uphold: 0,
        weighted_dismiss: 0,
        weighted_abstain: 0,
      },
      graph_note: 'No high-confidence vouchers found. Entity may be new or isolated in the trust graph.',
    };

    await persistAdjudicationResult(supabase, dispute.dispute_id, result, 'trust_graph');

    return {
      dispute_id: dispute.dispute_id,
      disputed_entity_id: dispute.entity_id,
      receipt_id: dispute.receipt_id,
      adjudication: result,
      vouchers: [],
      adjudicated_at: new Date().toISOString(),
    };
  }

  // -------------------------------------------------------------------
  // Step 3: Fetch each voucher's behavioral sentiment toward the disputed entity
  // -------------------------------------------------------------------
  const voucherSentiments = await Promise.all(
    vouchers.map(async (voucher) => {
      const sentimentData = await fetchVoucherSentiment(
        voucher.entity_id,
        dispute.entity_id,
        supabase
      );
      return {
        voucher,
        sentiment: sentimentData.sentiment,
        receipt_count: sentimentData.receipt_count,
        behavior_breakdown: sentimentData.behavior_breakdown,
      };
    })
  );

  // -------------------------------------------------------------------
  // Step 4: Compute the weighted vote
  // -------------------------------------------------------------------
  const voteResult = computeWeightedVote(voucherSentiments);

  // -------------------------------------------------------------------
  // Step 5: Assemble adjudication result
  // -------------------------------------------------------------------
  const adjudicationResult = {
    recommendation: voteResult.recommendation,
    confidence: voteResult.confidence,
    voucher_count: voteResult.voucher_count,
    participating_count: voteResult.participating_count,
    weighted_vote: {
      uphold_fraction: voteResult.uphold_fraction,
      weighted_uphold: voteResult.weighted_uphold,
      weighted_dismiss: voteResult.weighted_dismiss,
      weighted_abstain: voteResult.weighted_abstain,
    },
    // Summary of who voted and how — useful for operator review
    voucher_summary: voucherSentiments.map(({ voucher, sentiment, receipt_count, behavior_breakdown }) => ({
      entity_slug: voucher.entity_slug,
      confidence: voucher.confidence,
      confidence_score: voucher.confidence_score,
      sentiment,
      receipt_count,
      behavior_breakdown,
      direction: voucher.direction,
    })),
  };

  // -------------------------------------------------------------------
  // Step 6: Persist adjudication result to disputes table
  // -------------------------------------------------------------------
  await persistAdjudicationResult(supabase, dispute.dispute_id, adjudicationResult, 'trust_graph');

  return {
    dispute_id: dispute.dispute_id,
    disputed_entity_id: dispute.entity_id,
    receipt_id: dispute.receipt_id,
    adjudication: adjudicationResult,
    vouchers: voucherSentiments.map(({ voucher, sentiment, receipt_count }) => ({
      entity_slug: voucher.entity_slug,
      confidence: voucher.confidence,
      confidence_score: voucher.confidence_score,
      sentiment,
      receipt_count,
      direction: voucher.direction,
    })),
    adjudicated_at: new Date().toISOString(),
  };
}

// =============================================================================
// persistAdjudicationResult  (internal)
// =============================================================================

/**
 * Write the adjudication result back to the disputes table.
 * Fire-and-forget safe — errors are logged but don't break adjudication.
 *
 * @param {object} supabase
 * @param {string} disputeId
 * @param {object} result
 * @param {string} triggeredBy - 'trust_graph' | 'cron' | entity slug of triggering party
 */
async function persistAdjudicationResult(supabase, disputeId, result, triggeredBy) {
  try {
    const now = new Date().toISOString();
    await supabase
      .from('disputes')
      .update({
        adjudication_result: result,
        adjudicated_at: now,
        adjudication_triggered_by: triggeredBy,
        updated_at: now,
      })
      .eq('dispute_id', disputeId);
  } catch (err) {
    // Columns may not exist yet if migration 025 hasn't run — log and continue.
    const isMissingColumn = err.message?.includes('column') || err.message?.includes('does not exist');
    if (!isMissingColumn) {
      console.error('Adjudication result persistence failed:', err.message);
    } else {
      console.warn('Adjudication columns not yet present (run migration 025_dispute_adjudication.sql)');
    }
  }
}
