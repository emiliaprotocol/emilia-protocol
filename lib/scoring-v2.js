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
// CONCENTRATION CAP — prevents trust farming by credible actors
// =============================================================================

/**
 * Maximum effective evidence a single submitter can contribute to an entity's score.
 *
 * Without this cap, a high-trust established entity (score 90) submitting 7 bilateral
 * receipts contributes 7 × 0.72 = 5.04 effective evidence — enough to push the target
 * past the dampening threshold entirely on their own. This means one "trusted insider"
 * can manufacture establishment for any entity they choose.
 *
 * With a cap of 2.0, no single submitter can push a target past the 5.0 threshold
 * alone. At least 3 distinct established submitters are required, which matches the
 * uniqueSubmitters ≥ 3 establishment condition and closes the farming loop.
 */
export const MAX_SINGLE_SUBMITTER_CONTRIBUTION = 2.0;

// =============================================================================
// DISPUTE DAMPENING — immune system against gaming via disputes
// =============================================================================

/**
 * Disputed receipts count at 30% weight while under active review.
 * This prevents a bad actor from filing disputes against a competitor's
 * legitimate receipts and tanking their score while the dispute is open.
 * The dampening is temporary and symmetric — the filer's own dispute rate
 * also affects their profile.
 */
export const DISPUTE_DAMPENING_FACTOR = 0.3;

/**
 * Resolved dispute outcomes determine final receipt weight.
 *
 * upheld:    The dispute was valid — receipt is excluded from scoring (0.0x).
 *            Permanent record of the bad event stays in the ledger.
 * dismissed: The dispute was meritless — receipt is fully restored (1.0x).
 *            No permanent score penalty for the subject entity.
 */
export const DISPUTE_RESOLVED_FACTOR = {
  upheld: 0.0,
  dismissed: 1.0,
};

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
// WEIGHT BOUNDS — hard limits for policy-configurable weights
// =============================================================================

/**
 * Enforced bounds on scoring weights. No policy configuration can set a weight
 * outside these ranges. This prevents degenerate configurations that would
 * compromise Sybil resistance or create single-axis gaming vectors.
 *
 * See docs/architecture/ADAPTIVE_SCORING.md §4.3 for rationale.
 */
export const WEIGHT_BOUNDS = {
  behavioral:  { min: 0.20, max: 0.50 },
  consistency: { min: 0.10, max: 0.35 },
  delivery:    { min: 0.05, max: 0.25 },
  product:     { min: 0.03, max: 0.20 },
  price:       { min: 0.03, max: 0.20 },
  returns:     { min: 0.02, max: 0.15 },
};

/**
 * Validate a custom weight configuration against hard bounds.
 * Returns { valid, weights, errors } where weights is the normalized set.
 *
 * Rules enforced:
 *   1. All six dimensions must be present
 *   2. Each dimension must be within its [min, max] bound
 *   3. Weights must sum to 1.0 (tolerance: ±0.001)
 *   4. behavioral + consistency must be >= 0.35 (hard-to-fake signals dominate)
 *
 * @param {Object} weights - { behavioral, consistency, delivery, product, price, returns }
 * @returns {{ valid: boolean, weights: Object|null, errors: string[] }}
 */
export function validateScoringWeights(weights) {
  const errors = [];
  const required = ['behavioral', 'consistency', 'delivery', 'product', 'price', 'returns'];

  // Check all dimensions present
  for (const key of required) {
    if (weights[key] == null || typeof weights[key] !== 'number') {
      errors.push(`missing or non-numeric: ${key}`);
    }
  }
  if (errors.length > 0) return { valid: false, weights: null, errors };

  // Check bounds
  for (const key of required) {
    const { min, max } = WEIGHT_BOUNDS[key];
    if (weights[key] < min || weights[key] > max) {
      errors.push(`${key}: ${weights[key]} outside bounds [${min}, ${max}]`);
    }
  }

  // Check sum = 1.0
  const actualSum = required.reduce((s, k) => s + weights[k], 0);
  if (Math.abs(actualSum - 1.0) > 0.001) {
    errors.push(`weights sum to ${actualSum.toFixed(4)}, must equal 1.0 (±0.001)`);
  }

  // Structural constraint: hard-to-fake signals must dominate
  if (weights.behavioral + weights.consistency < 0.35) {
    errors.push(`behavioral + consistency = ${(weights.behavioral + weights.consistency).toFixed(2)}, must be >= 0.35`);
  }

  if (errors.length > 0) return { valid: false, weights: null, errors };

  // Return cleaned weights (only the six recognized dimensions)
  const cleaned = {};
  for (const k of required) cleaned[k] = weights[k];
  return { valid: true, weights: cleaned, errors: [] };
}

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
 * @param {Set} [disputedReceiptIds] - Set of receipt IDs currently under active dispute.
 *   Receipts in this set receive DISPUTE_DAMPENING_FACTOR (0.3x) weight.
 * @param {Object} [weights] - Custom scoring weights. If null/undefined, uses EP_WEIGHTS_V2
 *   (protocol defaults). Must have keys: behavioral, consistency, delivery, product, price, returns.
 *   Caller is responsible for validation via validateScoringWeights() before passing.
 * @returns {Object} Trust profile
 */
export function computeTrustProfile(receipts, entityMeta = {}, disputedReceiptIds = new Set(), weights = null) {
  const w = weights || EP_WEIGHTS_V2;
  const weightsVersion = weights ? 'policy' : 'ep-v2-default';
  const now = Date.now();

  if (!receipts || receipts.length === 0) {
    // LEGACY: compat_score on 0-100 scale. Used ONLY for sort ordering and backward
    // compatibility. New trust-critical features MUST use policy evaluation, confidence
    // state, or profile dimensions — never raw score. See PROTOCOL-STANDARD.md §20.
    return {
      score: 50, // 0-100 scale (legacy compat_score) — NOT 0-1 normalized
      confidence: 'pending',
      profile: null,
      anomaly: null,
      effectiveEvidence: 0,
      established: false,
      dispute_dampened_count: 0,
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

  // Provenance weight multipliers
  const PROVENANCE_WEIGHTS = {
    self_attested: 0.3,
    identified_signed: 0.5,
    bilateral: 0.8,
    platform_originated: 0.9,
    carrier_verified: 0.95,
    oracle_verified: 1.0,
  };

  // Track established vs unestablished evidence separately (Sybil quality gate)
  let establishedEvidence = 0;
  let disputeDampenedCount = 0;
  // Per-submitter contribution tracker for concentration cap
  const submitterContributions = new Map();

  for (const r of window) {
    const submitterWeight = r.submitter_established ? Math.max(0.1, (r.submitter_score ?? 50) / 100) : 0.1;
    const ageDays = Math.max(0, (now - new Date(r.created_at).getTime()) / 86400000);
    const timeWeight = Math.max(0.05, Math.pow(0.5, ageDays / 90));
    const graphWeight = r.graph_weight ?? 1.0;
    const provenanceWeight = PROVENANCE_WEIGHTS[r.provenance_tier] ?? PROVENANCE_WEIGHTS.self_attested;
    // Four-factor receipt weight: submitter × time × graph × provenance
    let w = submitterWeight * timeWeight * graphWeight * provenanceWeight;

    // Dispute dampening: receipts under active dispute count at 30% weight.
    // This is temporary — resolved disputes restore full weight (dismissed)
    // or remove the receipt entirely (upheld).
    if (r.id != null && disputedReceiptIds.has(r.id)) {
      w *= DISPUTE_DAMPENING_FACTOR;
      disputeDampenedCount++;
    }

    // Concentration cap: a single submitter cannot contribute more than
    // MAX_SINGLE_SUBMITTER_CONTRIBUTION effective evidence units regardless of score.
    // This closes the "trust farming by credible actors" attack vector where one
    // high-trust entity pushes a target past the dampening threshold on its own.
    if (r.submitted_by != null) {
      const alreadyContributed = submitterContributions.get(r.submitted_by) ?? 0;
      const remaining = Math.max(0, MAX_SINGLE_SUBMITTER_CONTRIBUTION - alreadyContributed);
      w = Math.min(w, remaining);
      submitterContributions.set(r.submitted_by, alreadyContributed + w);
    }

    effectiveEvidence += w;

    // Track evidence from established submitters only
    if (r.submitter_established) {
      establishedEvidence += w;
    }

    for (const [field, key] of Object.entries(signalMap)) {
      if (r[field] != null && Number.isFinite(r[field])) {
        // Clamp to [0, 100] — reject out-of-range values that would corrupt score
        const clamped = Math.max(0, Math.min(100, r[field]));
        signalAccum[key].sum += clamped * w;
        signalAccum[key].weight += w;
      }
    }
  }

  const signals = {};
  for (const [key, acc] of Object.entries(signalAccum)) {
    signals[key] = acc.weight > 0 ? Math.round((acc.sum / acc.weight) * 10) / 10 : null;
  }

  // === CONSISTENCY (mathematical, not self-reported) ===
  // Filter to finite values only and clamp to [0, 100] — prevents Infinity/NaN corrupting variance
  const composites = window
    .map(r => r.composite_score)
    .filter(v => v != null && Number.isFinite(v))
    .map(v => Math.max(0, Math.min(100, v)));
  let consistencyScore = 50;
  if (composites.length > 1) {
    const mean = composites.reduce((a, b) => a + b, 0) / composites.length;
    const variance = composites.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / composites.length;
    consistencyScore = Math.max(0, 100 - Math.sqrt(variance) * 2);
  }

  // === COMPOSITE SCORE (policy weights or v2 defaults) ===
  let score = behavioralScore * w.behavioral
    + consistencyScore * w.consistency;

  let totalW = w.behavioral + w.consistency;

  if (signals.delivery != null) { score += signals.delivery * w.delivery; totalW += w.delivery; }
  if (signals.product != null) { score += signals.product * w.product; totalW += w.product; }
  if (signals.price != null) { score += signals.price * w.price; totalW += w.price; }
  if (signals.returns != null) { score += signals.returns * w.returns; totalW += w.returns; }

  score = totalW > 0 ? score / totalW : 50;

  // Effective evidence dampening with Sybil quality gate
  // Pure volume from unestablished submitters cannot overcome dampening.
  // qualityGatedEvidence = established evidence + at most 2.0 from unestablished.
  // This prevents 200 fake identities from crossing the trust barrier.
  const qualityGatedEvidence = Math.min(
    effectiveEvidence,
    establishedEvidence + Math.min(Math.max(0, effectiveEvidence - establishedEvidence), 2.0)
  );
  if (qualityGatedEvidence < 5.0) {
    score = 50 + (score - 50) * (qualityGatedEvidence / 5.0);
  }

  const uniqueSubmitters = new Set(window.map(r => r.submitted_by).filter(Boolean)).size;
  const established = qualityGatedEvidence >= 5.0 && uniqueSubmitters >= 3;

  score = Math.round(Math.max(0, Math.min(100, score)) * 10) / 10;

  // === ANOMALY DETECTION ===
  const anomaly = detectScoreAnomaly(window, now);

  // === CONFIDENCE ===
  // Uses qualityGatedEvidence — pure unestablished volume cannot advance confidence.
  let confidence;
  if (qualityGatedEvidence === 0) confidence = 'pending';
  else if (qualityGatedEvidence < 1) confidence = 'insufficient';
  else if (!established) confidence = 'provisional';
  else if (qualityGatedEvidence < 20) confidence = 'emerging';
  else confidence = 'confident';

  return {
    // The headline score (for backward compat)
    score,
    confidence,
    established,
    effectiveEvidence: Math.round(effectiveEvidence * 100) / 100,
    qualityGatedEvidence: Math.round(qualityGatedEvidence * 100) / 100,
    uniqueSubmitters,
    receiptCount: window.length,
    last_receipt_at: window[0]?.created_at ?? null,
    dispute_dampened_count: disputeDampenedCount,

    // Weight metadata — which weights produced this score
    weights_version: weightsVersion,
    weights_used: { ...w },

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

      // Tier 4: Provenance composition
      provenance: (() => {
        const tiers = {};
        for (const r of window) {
          const tier = r.provenance_tier || 'self_attested';
          tiers[tier] = (tiers[tier] || 0) + 1;
        }
        return {
          breakdown: tiers,
          bilateral_rate: window.length > 0
            ? Math.round((window.filter(r => r.bilateral_status === 'confirmed').length / window.length) * 1000) / 10
            : null,
        };
      })(),
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
 * Uses variance-aware significance testing (simplified t-like statistic) to
 * avoid false positives from high-variance entities or small sample windows.
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

  // Require meaningful sample sizes in both windows before drawing conclusions.
  // 2 receipts is not enough: a single bad receipt out of 2 looks like a 50% crash.
  if (recentReceipts.length < 5 || olderReceipts.length < 5) return null;

  const safeScore = v => (Number.isFinite(v) ? Math.max(0, Math.min(100, v)) : 50);

  // Compute mean, variance, stdDev, and standard error for a set of receipts.
  function windowStats(receipts, scoreGetter) {
    const scores = receipts.map(scoreGetter).filter(Number.isFinite);
    if (scores.length === 0) return null;
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance = scores.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / scores.length;
    const stdDev = Math.sqrt(variance);
    const stderr = stdDev / Math.sqrt(scores.length);
    return { mean, variance, stdDev, stderr, n: scores.length };
  }

  const recent = windowStats(recentReceipts, r => safeScore(r.composite_score));
  const older = windowStats(olderReceipts, r => safeScore(r.composite_score));

  if (!recent || !older) return null;

  const delta = Math.round((recent.mean - older.mean) * 10) / 10;

  // Pooled standard error of the difference between the two window means.
  // This is a simplified (Welch-like) t-statistic denominator.
  const pooledStderr = Math.sqrt(recent.stderr ** 2 + older.stderr ** 2);

  // Significance: how many pooled standard errors does the delta span?
  // Require >= 2.0 (roughly 2σ) so that high-variance entities don't
  // generate alerts from normal fluctuation.
  const significance = pooledStderr > 0 ? Math.abs(delta) / pooledStderr : 0;

  // Both magnitude AND statistical significance must clear their thresholds.
  if (Math.abs(delta) < 10 || significance < 2.0) return null;

  // Alert level combines magnitude, significance, AND sample size so that
  // a 20-point drop across 3 receipts (noise) cannot reach 'severe' —
  // the same drop across 30 receipts (signal) can.
  const minN = Math.min(recent.n, older.n);
  const alert = (Math.abs(delta) >= 20 && significance >= 3.0 && minN >= 10) ? 'severe'
    : (Math.abs(delta) >= 10 && significance >= 2.0) ? 'moderate'
    : null;

  if (!alert) return null;

  return {
    type: delta < 0 ? 'declining' : 'improving',
    delta,
    period: '7d vs 30d',
    recent_avg: Math.round(recent.mean * 10) / 10,
    older_avg: Math.round(older.mean * 10) / 10,
    recent_n: recent.n,
    older_n: older.n,
    recent_stddev: Math.round(recent.stdDev * 10) / 10,
    significance: Math.round(significance * 10) / 10,
    alert,
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
  if (policy.max_days_since_last_receipt != null && profile.last_receipt_at) {
    const daysSince = (Date.now() - new Date(profile.last_receipt_at).getTime()) / 86400000;
    if (daysSince > policy.max_days_since_last_receipt) {
      failures.push(`last_receipt ${Math.round(daysSince)}d ago > max ${policy.max_days_since_last_receipt}d`);
    }
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
    max_days_since_last_receipt: 180,
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

  // === EP-SX: Software Trust Policies ===

  // GitHub: safe for private repos with read-only access
  github_private_repo_safe_v1: {
    min_score: 70,
    min_confidence: 'provisional',
    max_dispute_rate: 0.03,
    software_requirements: {
      publisher_verified: true,
      max_permission_class: 'read_only',
      install_scope: 'selected_repos',
      max_active_disputes: 0,
      min_provenance_score: 80,
      reject_severe_anomaly: true,
    },
  },

  // npm: safe for build-time dependencies
  npm_buildtime_safe_v1: {
    min_score: 60,
    min_confidence: 'provisional',
    software_requirements: {
      trusted_publishing: true,
      provenance_verified: true,
      max_active_disputes: 0,
      max_recent_incidents: 0,
      min_runtime_score: 75,
    },
  },

  // Browser: safe for extensions with limited permissions
  browser_extension_safe_v1: {
    min_score: 65,
    min_confidence: 'provisional',
    software_requirements: {
      listing_review_passed: true,
      max_permission_class: 'limited_content_read',
      max_site_scope: 'declared_sites_only',
      max_active_disputes: 0,
      reject_severe_anomaly: true,
    },
  },

  // MCP: safe for agent tool servers
  mcp_server_safe_v1: {
    min_score: 60,
    min_confidence: 'provisional',
    software_requirements: {
      registry_listed: true,
      server_card_present: true,
      publisher_verified: true,
      max_permission_class: 'bounded_external_access',
      max_active_disputes: 0,
      min_provenance_score: 70,
    },
  },
};
