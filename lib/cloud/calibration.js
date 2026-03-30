/**
 * EP Cloud — Scoring Weight Calibration Engine
 *
 * Analyzes dispute resolution outcomes to generate weight adjustment
 * recommendations. Upheld disputes are labeled ground truth: the entity
 * was found at fault, so the pre-dispute score was too high. The engine
 * identifies which signal dimensions were overweighted and proposes
 * corrections within hard bounds.
 *
 * This is Level 2 adaptive scoring: recommendations, not automation.
 * All recommendations flow through the policy rollout pipeline
 * (simulate → review → signoff → deploy). No automatic weight changes.
 *
 * See docs/architecture/ADAPTIVE_SCORING.md for full design rationale.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { EP_WEIGHTS_V2, WEIGHT_BOUNDS, validateScoringWeights } from '@/lib/scoring-v2';

// =============================================================================
// Minimum sample thresholds — no recommendation below these
// =============================================================================

const MIN_RESOLVED_DISPUTES = 50;
const MIN_TOTAL_RECEIPTS = 500;
const MIN_DISPUTED_ENTITIES = 20;

// Overweight ratio thresholds for triggering recommendations
const OVERWEIGHT_THRESHOLD = 1.3;  // signal contributing 30%+ more than baseline
const UNDERWEIGHT_THRESHOLD = 0.7; // signal contributing 30%+ less than baseline

// =============================================================================
// Data collection
// =============================================================================

/**
 * Collect calibration data: resolved disputes joined with receipts and entities.
 *
 * Returns an array of calibration records, each containing the dispute outcome,
 * the disputed receipt's signal values, and the entity's trust profile at
 * resolution time.
 *
 * @param {string} tenantId - Operator tenant ID (for multi-tenant isolation)
 * @param {number} windowDays - Rolling window in days (default: 90)
 * @returns {Promise<{ data: Array, stats: Object }>}
 */
export async function collectCalibrationData(tenantId, windowDays = 90) {
  const supabase = getServiceClient();
  const cutoff = new Date(Date.now() - windowDays * 86400000).toISOString();

  // Fetch resolved disputes with their receipts
  const { data: disputes, error } = await supabase
    .from('disputes')
    .select(`
      dispute_id,
      receipt_id,
      entity_id,
      status,
      resolution,
      reason,
      adjudication_result,
      resolved_at,
      created_at
    `)
    .in('status', ['upheld', 'dismissed', 'reversed'])
    .gte('resolved_at', cutoff)
    .order('resolved_at', { ascending: false });

  if (error) throw new Error(`Calibration data fetch failed: ${error.message}`);

  if (!disputes || disputes.length === 0) {
    return {
      data: [],
      stats: { resolved: 0, upheld: 0, dismissed: 0, reversed: 0, windowDays },
    };
  }

  // Collect unique receipt IDs and entity IDs
  const receiptIds = [...new Set(disputes.map(d => d.receipt_id).filter(Boolean))];
  const entityIds = [...new Set(disputes.map(d => d.entity_id).filter(Boolean))];

  // Batch-fetch receipts (signal values live here)
  const { data: receipts } = await supabase
    .from('receipts')
    .select(`
      receipt_id,
      entity_id,
      composite_score,
      delivery_accuracy,
      product_accuracy,
      price_integrity,
      return_processing,
      agent_behavior,
      agent_satisfaction,
      submitter_score,
      submitter_established,
      graph_weight,
      provenance_tier
    `)
    .in('receipt_id', receiptIds);

  const receiptMap = new Map((receipts || []).map(r => [r.receipt_id, r]));

  // Batch-fetch entity trust snapshots (dimensions at resolution time)
  const { data: entities } = await supabase
    .from('entities')
    .select('id, entity_id, trust_snapshot, emilia_score')
    .in('id', entityIds);

  const entityMap = new Map((entities || []).map(e => [e.id, e]));

  // Build calibration records
  const data = disputes.map(d => {
    const receipt = receiptMap.get(d.receipt_id);
    const entity = entityMap.get(d.entity_id);
    return {
      dispute_id: d.dispute_id,
      outcome: d.status, // upheld, dismissed, reversed
      resolution: d.resolution,
      reason: d.reason,
      resolved_at: d.resolved_at,
      adjudication_confidence: d.adjudication_result?.confidence ?? null,
      adjudication_recommendation: d.adjudication_result?.recommendation ?? null,
      // Receipt signals (what the entity did in this transaction)
      receipt: receipt ? {
        composite_score: receipt.composite_score,
        delivery_accuracy: receipt.delivery_accuracy,
        product_accuracy: receipt.product_accuracy,
        price_integrity: receipt.price_integrity,
        return_processing: receipt.return_processing,
        agent_behavior: receipt.agent_behavior,
        submitter_score: receipt.submitter_score,
        submitter_established: receipt.submitter_established,
        provenance_tier: receipt.provenance_tier,
      } : null,
      // Entity trust snapshot (scoring state at the time)
      entity_score: entity?.emilia_score ?? null,
      entity_snapshot: entity?.trust_snapshot ?? null,
    };
  });

  const stats = {
    resolved: disputes.length,
    upheld: disputes.filter(d => d.status === 'upheld').length,
    dismissed: disputes.filter(d => d.status === 'dismissed').length,
    reversed: disputes.filter(d => d.status === 'reversed').length,
    uniqueEntities: entityIds.length,
    windowDays,
  };

  return { data, stats };
}

// =============================================================================
// Weight recommendation algorithm
// =============================================================================

/**
 * Behavior value mapping (mirrors scoring-v2.js BEHAVIOR_VALUES).
 * Used to derive behavioral score from agent_behavior field.
 */
const BEHAVIOR_VALUES = {
  completed: 95,
  retried_same: 75,
  retried_different: 40,
  abandoned: 15,
  disputed: 5,
};

/**
 * Extract signal dimension contributions from a receipt.
 * Returns the per-dimension values that would feed into the composite score.
 *
 * @param {Object} receipt - Receipt signal values
 * @returns {{ behavioral: number, consistency: number|null, delivery: number|null, product: number|null, price: number|null, returns: number|null }}
 */
function extractDimensions(receipt) {
  if (!receipt) return null;
  return {
    behavioral: BEHAVIOR_VALUES[receipt.agent_behavior] ?? 50,
    // Consistency cannot be derived from a single receipt — use entity snapshot
    consistency: null,
    delivery: receipt.delivery_accuracy ?? null,
    product: receipt.product_accuracy ?? null,
    price: receipt.price_integrity ?? null,
    returns: receipt.return_processing ?? null,
  };
}

/**
 * Compute the weighted contribution of each dimension to a composite score.
 * Uses the current EP_WEIGHTS_V2 to show what each dimension "contributed."
 *
 * @param {Object} dimensions - Per-dimension scores (0-100)
 * @param {Object} weights - Weight configuration (defaults to EP_WEIGHTS_V2)
 * @returns {{ [dimension]: number }} - Contribution of each dimension (0-100 scale)
 */
function computeContributions(dimensions, weights = EP_WEIGHTS_V2) {
  const contributions = {};
  let totalWeight = 0;

  for (const [dim, w] of Object.entries(weights)) {
    const val = dimensions[dim];
    if (val != null && Number.isFinite(val)) {
      contributions[dim] = val * w;
      totalWeight += w;
    }
  }

  // Normalize so contributions sum to the composite score
  if (totalWeight > 0 && totalWeight < 1.0) {
    for (const dim of Object.keys(contributions)) {
      contributions[dim] /= totalWeight;
    }
  }

  return contributions;
}

/**
 * Compute weight recommendations from calibration data.
 *
 * Algorithm:
 * 1. For each upheld dispute, extract signal dimensions from the receipt
 * 2. Compute per-dimension contribution under current weights
 * 3. Compare upheld-entity dimension contributions to population baseline
 * 4. Dimensions that contributed disproportionately to high scores of
 *    at-fault entities are overweighted → recommend reduction
 *
 * @param {Array} calibrationData - From collectCalibrationData()
 * @param {Object} stats - From collectCalibrationData()
 * @returns {{ recommendation: Object|null, analysis: Object, sufficient_data: boolean }}
 */
export function computeWeightRecommendation(calibrationData, stats) {
  // Check minimum sample thresholds
  if (stats.resolved < MIN_RESOLVED_DISPUTES) {
    return {
      recommendation: null,
      sufficient_data: false,
      reason: `Insufficient resolved disputes: ${stats.resolved} < ${MIN_RESOLVED_DISPUTES} required`,
      analysis: { stats },
    };
  }
  if (stats.uniqueEntities < MIN_DISPUTED_ENTITIES) {
    return {
      recommendation: null,
      sufficient_data: false,
      reason: `Insufficient disputed entities: ${stats.uniqueEntities} < ${MIN_DISPUTED_ENTITIES} required`,
      analysis: { stats },
    };
  }

  // Separate upheld vs dismissed disputes
  const upheld = calibrationData.filter(d => d.outcome === 'upheld' && d.receipt);
  const dismissed = calibrationData.filter(d => d.outcome === 'dismissed' && d.receipt);
  const all = calibrationData.filter(d => d.receipt);

  if (upheld.length < 10) {
    return {
      recommendation: null,
      sufficient_data: false,
      reason: `Insufficient upheld disputes with receipt data: ${upheld.length} < 10 required`,
      analysis: { stats, upheld_with_receipts: upheld.length },
    };
  }

  // Extract dimensions for each group
  const upheldDimensions = upheld.map(d => extractDimensions(d.receipt)).filter(Boolean);
  const allDimensions = all.map(d => extractDimensions(d.receipt)).filter(Boolean);

  // Compute mean contribution per dimension for each group
  const dimensions = ['behavioral', 'delivery', 'product', 'price', 'returns'];

  function meanContribution(records, dim) {
    const values = records
      .map(d => computeContributions(d, EP_WEIGHTS_V2)[dim])
      .filter(v => v != null && Number.isFinite(v));
    if (values.length === 0) return null;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  const analysis = {};
  for (const dim of dimensions) {
    const upheldMean = meanContribution(upheldDimensions, dim);
    const baselineMean = meanContribution(allDimensions, dim);

    if (upheldMean == null || baselineMean == null || baselineMean === 0) {
      analysis[dim] = { upheldMean: null, baselineMean: null, ratio: null, signal: 'insufficient_data' };
      continue;
    }

    const ratio = upheldMean / baselineMean;
    let signal = 'neutral';
    if (ratio > OVERWEIGHT_THRESHOLD) signal = 'overweighted';
    else if (ratio < UNDERWEIGHT_THRESHOLD) signal = 'underweighted';

    analysis[dim] = {
      upheldMean: Math.round(upheldMean * 100) / 100,
      baselineMean: Math.round(baselineMean * 100) / 100,
      ratio: Math.round(ratio * 100) / 100,
      signal,
    };
  }

  // Generate proposed weights based on analysis
  const proposedWeights = { ...EP_WEIGHTS_V2 };
  let adjustmentsMade = false;

  for (const dim of dimensions) {
    const a = analysis[dim];
    if (a.signal === 'overweighted') {
      // Reduce weight by 20% of the excess ratio
      const reduction = (a.ratio - 1.0) * 0.20 * proposedWeights[dim];
      proposedWeights[dim] = Math.max(WEIGHT_BOUNDS[dim].min, proposedWeights[dim] - reduction);
      adjustmentsMade = true;
    } else if (a.signal === 'underweighted') {
      // Increase weight by 20% of the deficit
      const increase = (1.0 - a.ratio) * 0.20 * proposedWeights[dim];
      proposedWeights[dim] = Math.min(WEIGHT_BOUNDS[dim].max, proposedWeights[dim] + increase);
      adjustmentsMade = true;
    }
  }

  // Consistency is not receipt-level — carry forward from defaults
  // (consistency adjustments require entity-level analysis, not receipt-level)

  if (!adjustmentsMade) {
    return {
      recommendation: null,
      sufficient_data: true,
      reason: 'Current weights are well-calibrated — no adjustment needed',
      analysis: { stats, dimensions: analysis },
    };
  }

  // Normalize proposed weights to sum to 1.0
  const rawSum = Object.values(proposedWeights).reduce((a, b) => a + b, 0);
  for (const dim of Object.keys(proposedWeights)) {
    proposedWeights[dim] = Math.round((proposedWeights[dim] / rawSum) * 1000) / 1000;
  }

  // Final adjustment to ensure exact sum = 1.000
  const finalSum = Object.values(proposedWeights).reduce((a, b) => a + b, 0);
  const drift = 1.0 - finalSum;
  if (Math.abs(drift) > 0.0001) {
    // Add drift to the largest weight (least sensitive to rounding)
    const largest = Object.entries(proposedWeights).sort((a, b) => b[1] - a[1])[0][0];
    proposedWeights[largest] = Math.round((proposedWeights[largest] + drift) * 1000) / 1000;
  }

  // Validate the proposed weights against bounds
  const validation = validateScoringWeights(proposedWeights);
  if (!validation.valid) {
    return {
      recommendation: null,
      sufficient_data: true,
      reason: `Generated weights failed validation: ${validation.errors.join('; ')}`,
      analysis: { stats, dimensions: analysis, proposedWeights, validationErrors: validation.errors },
    };
  }

  // Compute confidence based on sample sizes
  const sampleConfidence = Math.min(1.0, Math.sqrt(upheld.length / 100));
  const diversityConfidence = Math.min(1.0, stats.uniqueEntities / 50);
  const overallConfidence = Math.round(((sampleConfidence + diversityConfidence) / 2) * 100) / 100;

  // Compute weight deltas for readability
  const deltas = {};
  for (const dim of Object.keys(EP_WEIGHTS_V2)) {
    const delta = proposedWeights[dim] - EP_WEIGHTS_V2[dim];
    if (Math.abs(delta) > 0.001) {
      deltas[dim] = {
        current: EP_WEIGHTS_V2[dim],
        proposed: proposedWeights[dim],
        delta: Math.round(delta * 1000) / 1000,
        direction: delta > 0 ? 'increase' : 'decrease',
      };
    }
  }

  return {
    recommendation: {
      weights: validation.weights,
      deltas,
      confidence: overallConfidence,
      sample_size: upheld.length,
      entity_count: stats.uniqueEntities,
      window_days: stats.windowDays,
      generated_at: new Date().toISOString(),
    },
    sufficient_data: true,
    reason: `Recommendation generated from ${upheld.length} upheld disputes across ${stats.uniqueEntities} entities`,
    analysis: { stats, dimensions: analysis },
  };
}

// =============================================================================
// Vertical pack presets
// =============================================================================

/**
 * Pre-calibrated weight presets for common verticals.
 * These are starting points, not mandates. Operators can customize further.
 * All presets pass validateScoringWeights().
 */
export const VERTICAL_PACKS = {
  government: {
    name: 'Government',
    description: 'Optimized for procurement: higher consistency and delivery, lower behavioral (sole-source vendors)',
    weights: {
      behavioral: 0.25,
      consistency: 0.30,
      delivery: 0.20,
      product: 0.10,
      price: 0.12,
      returns: 0.03,
    },
  },
  financial: {
    name: 'Financial Services',
    description: 'Optimized for financial products: higher consistency and price integrity, lower delivery (digital)',
    weights: {
      behavioral: 0.35,
      consistency: 0.30,
      delivery: 0.10,
      product: 0.08,
      price: 0.15,
      returns: 0.02,
    },
  },
  agent_governance: {
    name: 'Agent Governance',
    description: 'Optimized for autonomous agents: highest behavioral weight (agent routing is the purest signal)',
    weights: {
      behavioral: 0.45,
      consistency: 0.25,
      delivery: 0.10,
      product: 0.08,
      price: 0.07,
      returns: 0.05,
    },
  },
  ecommerce: {
    name: 'E-Commerce',
    description: 'Balanced for standard online commerce — protocol defaults',
    weights: { ...EP_WEIGHTS_V2 },
  },
};

// =============================================================================
// Exports
// =============================================================================

export {
  MIN_RESOLVED_DISPUTES,
  MIN_TOTAL_RECEIPTS,
  MIN_DISPUTED_ENTITIES,
  extractDimensions,
  computeContributions,
};
