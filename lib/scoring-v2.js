/**
 * EMILIA Protocol — v2 Scoring Architecture
 *
 * What every AI missed. What makes EP actually different from "reviews with hashes."
 *
 * SIX FUNDAMENTAL CHANGES:
 *
 * 1. BEHAVIORAL-FIRST SCORING
 *    The behavioral signal (did the agent come back?) is the strongest Phase 1
 *    signal because it's harder to fake credibly and more aligned with real
 *    routing outcomes. It should be primary, not a 10% tiebreaker.
 *    New weights: behavioral 40%, consistency 20%, claims-backed 30%, self-reported 10%.
 *
 * 2. TRUST PROFILES, NOT SCORES
 *    A single 0-100 number destroys information. EP outputs a multi-dimensional
 *    trust profile that consuming agents can evaluate against their own criteria.
 *
 * 3. TRUST POLICIES AS FIRST-CLASS OBJECTS
 *    Agents don't just check scores — they evaluate against policies.
 *    "min_score > 70 AND delivery_accuracy > 80 AND dispute_rate < 5%"
 *
 * 4. RELATIONSHIP TRUST
 *    "How does entity A trust entity B?" is different from "What's B's global score?"
 *    Pairwise trust scores for repeated counterparties.
 *
 * 5. ANOMALY DETECTION
 *    Score velocity matters more than absolute score. A 20-point drop in a week
 *    is a stronger signal than a static 70.
 *
 * 6. RECEIPT VELOCITY AS STRATEGY
 *    The moat is the ledger, not the algorithm. Optimize for receipt ingestion.
 *
 * @license Apache-2.0
 */

// =============================================================================
// v2 WEIGHTS — behavioral-first
// =============================================================================

/**
 * Phase 1 weights: behavioral signals get primary weight because they are
 * harder to fake credibly and more aligned with future routing behavior
 * than self-reported numeric signals.
 *
 * Self-reported numeric signals (delivery_accuracy: 78) are opinions dressed
 * as numbers. They get minimum weight until Phase 2 evidence backs them.
 */
export const EP_WEIGHTS_V2 = {
  // TIER 1: Harder to fake, more aligned with real outcomes
  behavioral:   0.40,  // Did they come back? Switch? Abandon? Dispute?
  consistency:  0.25,  // Low variance = reliable. Mathematical, not self-reported.

  // TIER 2: Claims-backed (verifiable in Phase 2, self-reported in Phase 1)
  delivery:     0.12,  // Delivery timing
  product:      0.10,  // Product accuracy
  price:        0.08,  // Price integrity
  returns:      0.05,  // Return processing
  // Total: 1.00

  // TIER 3: Future (oracle-verified in Phase 3)
  // These weights shift as verification improves:
  // Phase 2: behavioral 30%, claims 40%, consistency 20%, self-reported 10%
  // Phase 3: behavioral 20%, verified 50%, consistency 20%, oracle 10%
};

// =============================================================================
// TRUST PROFILE — multi-dimensional output
// =============================================================================

/**
 * Compute a full trust profile for an entity.
 * This replaces the single 0-100 score with a multi-dimensional profile
 * that consuming agents can evaluate against their own criteria.
 *
 * @param {Array} receipts - Receipt history, most recent first
 * @param {Object} entityMeta - { created_at, total_receipts }
 * @returns {Object} Trust profile
 */
export function computeTrustProfile(receipts, entityMeta = {}) {
  const now = Date.now();

  if (!receipts || receipts.length === 0) {
    return {
      score: 50,
      confidence: 'pending',
      profile: null,
      anomaly: null,
      effectiveEvidence: 0,
      established: false,
    };
  }

  const window = receipts.slice(0, 200);

  // === BEHAVIORAL ANALYSIS (Tier 1 — harder to fake, more aligned) ===
  const behaviors = window.map(r => r.agent_behavior).filter(Boolean);
  const behaviorCounts = {};
  for (const b of behaviors) {
    behaviorCounts[b] = (behaviorCounts[b] || 0) + 1;
  }
  const totalBehaviors = behaviors.length;

  // Behavioral score: weighted by behavior type
  const BEHAVIOR_VALUES = {
    completed: 95,
    retried_same: 75,
    retried_different: 40,
    abandoned: 15,
    disputed: 5,
  };

  let behavioralScore = 50; // default if no behaviors
  if (totalBehaviors > 0) {
    let bSum = 0;
    for (const [b, count] of Object.entries(behaviorCounts)) {
      bSum += (BEHAVIOR_VALUES[b] ?? 50) * count;
    }
    behavioralScore = bSum / totalBehaviors;
  }

  // Completion rate, retry rate, dispute rate — these are the REAL trust signals
  const completionRate = totalBehaviors > 0
    ? (behaviorCounts.completed || 0) / totalBehaviors
    : null;
  const retryRate = totalBehaviors > 0
    ? ((behaviorCounts.retried_same || 0) + (behaviorCounts.retried_different || 0)) / totalBehaviors
    : null;
  const abandonRate = totalBehaviors > 0
    ? (behaviorCounts.abandoned || 0) / totalBehaviors
    : null;
  const disputeRate = totalBehaviors > 0
    ? (behaviorCounts.disputed || 0) / totalBehaviors
    : null;

  // === SIGNAL ANALYSIS (Tier 2 — self-reported, claims-backed in v2) ===
  let effectiveEvidence = 0;
  const signalAccum = {
    delivery: { sum: 0, weight: 0 },
    product: { sum: 0, weight: 0 },
    price: { sum: 0, weight: 0 },
    returns: { sum: 0, weight: 0 },
  };

  const signalMap = {
    delivery_accuracy: 'delivery',
    product_accuracy: 'product',
    price_integrity: 'price',
    return_processing: 'returns',
  };

  for (const r of window) {
    const submitterWeight = r.submitter_established ? Math.max(0.1, (r.submitter_score ?? 50) / 100) : 0.1;
    const ageDays = Math.max(0, (now - new Date(r.created_at).getTime()) / 86400000);
    const timeWeight = Math.max(0.05, Math.pow(0.5, ageDays / 90));
    const graphWeight = r.graph_weight ?? 1.0;
    const w = submitterWeight * timeWeight * graphWeight;
    effectiveEvidence += w;

    for (const [field, key] of Object.entries(signalMap)) {
      if (r[field] != null && !isNaN(r[field])) {
        signalAccum[key].sum += r[field] * w;
        signalAccum[key].weight += w;
      }
    }
  }

  const signals = {};
  for (const [key, acc] of Object.entries(signalAccum)) {
    signals[key] = acc.weight > 0 ? Math.round((acc.sum / acc.weight) * 10) / 10 : null;
  }

  // === CONSISTENCY (mathematical, not self-reported) ===
  const composites = window.map(r => r.composite_score).filter(v => v != null);
  let consistencyScore = 50;
  if (composites.length > 1) {
    const mean = composites.reduce((a, b) => a + b, 0) / composites.length;
    const variance = composites.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / composites.length;
    consistencyScore = Math.max(0, 100 - Math.sqrt(variance) * 2);
  }

  // === COMPOSITE SCORE (v2 weights) ===
  let score = behavioralScore * EP_WEIGHTS_V2.behavioral
    + consistencyScore * EP_WEIGHTS_V2.consistency;

  let totalW = EP_WEIGHTS_V2.behavioral + EP_WEIGHTS_V2.consistency;

  if (signals.delivery != null) { score += signals.delivery * EP_WEIGHTS_V2.delivery; totalW += EP_WEIGHTS_V2.delivery; }
  if (signals.product != null) { score += signals.product * EP_WEIGHTS_V2.product; totalW += EP_WEIGHTS_V2.product; }
  if (signals.price != null) { score += signals.price * EP_WEIGHTS_V2.price; totalW += EP_WEIGHTS_V2.price; }
  if (signals.returns != null) { score += signals.returns * EP_WEIGHTS_V2.returns; totalW += EP_WEIGHTS_V2.returns; }

  score = totalW > 0 ? score / totalW : 50;

  // Effective evidence dampening
  if (effectiveEvidence < 5.0) {
    score = 50 + (score - 50) * (effectiveEvidence / 5.0);
  }

  const uniqueSubmitters = new Set(window.map(r => r.submitted_by).filter(Boolean)).size;
  const established = effectiveEvidence >= 5.0 && uniqueSubmitters >= 3;

  score = Math.round(Math.max(0, Math.min(100, score)) * 10) / 10;

  // === ANOMALY DETECTION ===
  const anomaly = detectScoreAnomaly(window, now);

  // === CONFIDENCE ===
  let confidence;
  if (effectiveEvidence === 0) confidence = 'pending';
  else if (effectiveEvidence < 1) confidence = 'insufficient';
  else if (!established) confidence = 'provisional';
  else if (effectiveEvidence < 20) confidence = 'emerging';
  else confidence = 'confident';

  return {
    // The headline score (for backward compat)
    score,
    confidence,
    established,
    effectiveEvidence: Math.round(effectiveEvidence * 100) / 100,
    uniqueSubmitters,
    receiptCount: window.length,

    // THE TRUST PROFILE — this is what makes EP different from "reviews with hashes"
    profile: {
      // Tier 1: Behavioral signals (harder to fake, more aligned)
      behavioral: {
        score: Math.round(behavioralScore * 10) / 10,
        completion_rate: completionRate != null ? Math.round(completionRate * 1000) / 10 : null,
        retry_rate: retryRate != null ? Math.round(retryRate * 1000) / 10 : null,
        abandon_rate: abandonRate != null ? Math.round(abandonRate * 1000) / 10 : null,
        dispute_rate: disputeRate != null ? Math.round(disputeRate * 1000) / 10 : null,
        total_observed: totalBehaviors,
      },

      // Tier 2: Signal scores (self-reported in Phase 1, claims-backed in Phase 2)
      signals: {
        delivery_accuracy: signals.delivery,
        product_accuracy: signals.product,
        price_integrity: signals.price,
        return_processing: signals.returns,
      },

      // Tier 3: Consistency (mathematical)
      consistency: Math.round(consistencyScore * 10) / 10,
    },

    // Score velocity and anomalies
    anomaly,
  };
}

// =============================================================================
// ANOMALY DETECTION — score velocity matters more than absolute score
// =============================================================================

/**
 * Detect anomalous score changes.
 * A 20-point drop in a week is a stronger signal than a static 70.
 *
 * @param {Array} receipts - Recent receipts
 * @param {number} now - Current timestamp in ms
 * @returns {Object|null} Anomaly data or null if none detected
 */
function detectScoreAnomaly(receipts, now) {
  if (receipts.length < 5) return null;

  const sevenDaysAgo = now - 7 * 86400000;
  const thirtyDaysAgo = now - 30 * 86400000;

  const recentReceipts = receipts.filter(r => new Date(r.created_at).getTime() > sevenDaysAgo);
  const olderReceipts = receipts.filter(r => {
    const t = new Date(r.created_at).getTime();
    return t <= sevenDaysAgo && t > thirtyDaysAgo;
  });

  if (recentReceipts.length < 2 || olderReceipts.length < 2) return null;

  const recentAvg = recentReceipts.reduce((s, r) => s + (r.composite_score || 50), 0) / recentReceipts.length;
  const olderAvg = olderReceipts.reduce((s, r) => s + (r.composite_score || 50), 0) / olderReceipts.length;

  const delta = Math.round((recentAvg - olderAvg) * 10) / 10;

  if (Math.abs(delta) < 10) return null;

  return {
    type: delta < 0 ? 'declining' : 'improving',
    delta,
    period: '7d vs 30d',
    recent_avg: Math.round(recentAvg * 10) / 10,
    older_avg: Math.round(olderAvg * 10) / 10,
    alert: Math.abs(delta) >= 20 ? 'severe' : 'moderate',
  };
}

// =============================================================================
// TRUST POLICIES — first-class decision framework
// =============================================================================

/**
 * Evaluate an entity's trust profile against a trust policy.
 * This is how agents CONSUME EP scores — not "score > 70" but a full policy.
 *
 * @param {Object} profile - Trust profile from computeTrustProfile()
 * @param {Object} policy - Trust policy
 * @returns {Object} { pass, failures, warnings }
 */
export function evaluateTrustPolicy(profile, policy) {
  const failures = [];
  const warnings = [];

  if (!profile || profile.confidence === 'pending') {
    return { pass: false, failures: ['no_data'], warnings: [] };
  }

  // Score threshold
  if (policy.min_score != null && profile.score < policy.min_score) {
    failures.push(`score ${profile.score} < min ${policy.min_score}`);
  }

  // Confidence level
  const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];
  if (policy.min_confidence) {
    const required = confLevels.indexOf(policy.min_confidence);
    const actual = confLevels.indexOf(profile.confidence);
    if (actual < required) {
      failures.push(`confidence "${profile.confidence}" < min "${policy.min_confidence}"`);
    }
  }

  // Minimum receipts
  if (policy.min_receipts != null && profile.receiptCount < policy.min_receipts) {
    failures.push(`receipts ${profile.receiptCount} < min ${policy.min_receipts}`);
  }

  // Maximum dispute rate
  if (policy.max_dispute_rate != null && profile.profile?.behavioral?.dispute_rate != null) {
    if (profile.profile.behavioral.dispute_rate / 100 > policy.max_dispute_rate) {
      failures.push(`dispute_rate ${profile.profile.behavioral.dispute_rate}% > max ${policy.max_dispute_rate * 100}%`);
    }
  }

  // Required signal minimums
  if (policy.signal_minimums && profile.profile?.signals) {
    for (const [signal, min] of Object.entries(policy.signal_minimums)) {
      const actual = profile.profile.signals[signal];
      if (actual != null && actual < min) {
        failures.push(`${signal} ${actual} < min ${min}`);
      }
      if (actual == null) {
        warnings.push(`${signal} has no data`);
      }
    }
  }

  // Minimum completion rate
  if (policy.min_completion_rate != null && profile.profile?.behavioral?.completion_rate != null) {
    if (profile.profile.behavioral.completion_rate / 100 < policy.min_completion_rate) {
      failures.push(`completion_rate ${profile.profile.behavioral.completion_rate}% < min ${policy.min_completion_rate * 100}%`);
    }
  }

  // Anomaly check
  if (policy.reject_anomaly && profile.anomaly?.alert === 'severe') {
    failures.push(`severe anomaly detected: ${profile.anomaly.type} ${profile.anomaly.delta} points`);
  }

  // Recency requirement
  if (policy.max_days_since_last_receipt != null && profile.receiptCount > 0) {
    // Would need last_receipt_date — approximation: if entity has receipts, pass
    // Full implementation would check entity.updated_at
  }

  return {
    pass: failures.length === 0,
    failures,
    warnings,
  };
}

// =============================================================================
// EXAMPLE TRUST POLICIES
// =============================================================================

export const TRUST_POLICIES = {
  // Strict: for high-value purchases
  strict: {
    min_score: 75,
    min_confidence: 'confident',
    min_receipts: 20,
    max_dispute_rate: 0.03,
    min_completion_rate: 0.85,
    reject_anomaly: true,
    signal_minimums: {
      delivery_accuracy: 80,
      price_integrity: 90,
    },
  },

  // Standard: for normal commerce
  standard: {
    min_score: 60,
    min_confidence: 'emerging',
    min_receipts: 5,
    max_dispute_rate: 0.10,
    min_completion_rate: 0.70,
    reject_anomaly: false,
  },

  // Permissive: for low-risk interactions
  permissive: {
    min_score: 40,
    min_confidence: 'provisional',
    min_receipts: 1,
    max_dispute_rate: 0.20,
  },

  // Discovery: allow unscored entities (for browsing/exploring)
  discovery: {
    min_score: 0,
    min_confidence: 'pending',
  },
};
