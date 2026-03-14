/**
 * EMILIA Protocol — Scoring Engine
 * 
 * Entity Measurement Infrastructure for Ledgered Interaction Accountability
 * 
 * This file is OPEN SOURCE. The scoring algorithm is public and auditable.
 * Anyone can verify how EMILIA Scores are computed.
 * 
 * The algorithm computes a 0-100 score from verified transaction receipts.
 * No opinions. No surveys. Just what happened.
 * 
 * @license Apache-2.0
 */

// =============================================================================
// SCORE WEIGHTS — the published formula
// =============================================================================
export const EMILIA_WEIGHTS = {
  delivery_accuracy:  0.30,  // Did it arrive when promised?
  product_accuracy:   0.25,  // Did the listing match reality?
  price_integrity:    0.15,  // Was the price honored?
  return_processing:  0.15,  // Was the return policy followed?
  agent_satisfaction: 0.10,  // Was the purchasing agent satisfied?
  consistency:        0.05,  // Low variance over time?
};

// Minimum receipts before a score is considered "established"
export const MIN_RECEIPTS_ESTABLISHED = 5;

// Rolling window size for score computation
export const RECEIPT_WINDOW = 200;

// Default score for unproven entities
export const DEFAULT_SCORE = 50.0;

// =============================================================================
// COMPOSITE SCORE — for a single receipt
// =============================================================================
/**
 * Compute the composite score for a single receipt.
 * This is the weighted average of all signals present in the receipt.
 * Missing signals are excluded from the calculation (not penalized).
 * 
 * @param {Object} receipt - { delivery_accuracy, product_accuracy, price_integrity, return_processing, agent_satisfaction }
 * @returns {number} 0-100 composite score
 */
export function computeReceiptComposite(receipt) {
  let totalWeight = 0;
  let weightedSum = 0;

  for (const [signal, weight] of Object.entries(EMILIA_WEIGHTS)) {
    if (signal === 'consistency') continue; // consistency is entity-level, not receipt-level
    const value = receipt[signal];
    if (value != null && !isNaN(value)) {
      weightedSum += value * weight;
      totalWeight += weight;
    }
  }

  if (totalWeight === 0) return DEFAULT_SCORE;

  // Normalize by actual weights used (handles missing signals)
  return Math.round((weightedSum / totalWeight) * 10) / 10;
}

// =============================================================================
// ENTITY SCORE — from a set of receipts
// =============================================================================
/**
 * Compute an entity's EMILIA Score from their receipt history.
 * This is the core algorithm. It is deterministic and reproducible.
 * 
 * Phase 1: Simple average of receipt signals
 * Phase 1.5: Submitter-weighted average (receipts from high-scoring entities count more)
 * 
 * @param {Array} receipts - Array of receipt objects, most recent first
 *   Each receipt may include: submitter_score (0-100) for weighting
 * @returns {Object} { score, breakdown, receiptCount, established }
 */
export function computeEmiliaScore(receipts) {
  if (!receipts || receipts.length === 0) {
    return {
      score: DEFAULT_SCORE,
      breakdown: null,
      receiptCount: 0,
      effectiveEvidence: 0,
      established: false,
    };
  }

  // Use rolling window
  const window = receipts.slice(0, RECEIPT_WINDOW);
  const count = window.length;

  // Track effective evidence = sum of all receipt weights
  // This is the REAL measure of how much credible data we have
  let effectiveEvidence = 0;

  const now = Date.now();
  const signals = {};
  for (const signal of Object.keys(EMILIA_WEIGHTS)) {
    if (signal === 'consistency') continue;
    let weightedSum = 0;
    let totalWeight = 0;
    for (const r of window) {
      const value = r[signal];
      if (value != null && !isNaN(value)) {
        const submitterWeight = computeSubmitterWeight(r.submitter_score, r.submitter_established);
        const timeWeight = computeTimeDecay(r.created_at, now);
        const graphWeight = r.graph_weight ?? 1.0;
        const combinedWeight = submitterWeight * timeWeight * graphWeight;
        weightedSum += value * combinedWeight;
        totalWeight += combinedWeight;
      }
    }
    signals[signal] = totalWeight > 0 ? weightedSum / totalWeight : null;
    // Track max effective evidence across signals
    if (totalWeight > effectiveEvidence) effectiveEvidence = totalWeight;
  }

  // Compute consistency (low variance = high score)
  const composites = window.map(r => r.composite_score).filter(v => v != null);
  let consistencyScore = 50;
  if (composites.length > 1) {
    const mean = composites.reduce((a, b) => a + b, 0) / composites.length;
    const variance = composites.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / composites.length;
    const stddev = Math.sqrt(variance);
    consistencyScore = Math.max(0, 100 - stddev * 2);
  }

  // Weighted composite
  let totalWeight = 0;
  let weightedSum = 0;

  for (const [signal, weight] of Object.entries(EMILIA_WEIGHTS)) {
    const value = signal === 'consistency' ? consistencyScore : signals[signal];
    if (value != null) {
      weightedSum += value * weight;
      totalWeight += weight;
    }
  }

  let score = totalWeight > 0 ? weightedSum / totalWeight : DEFAULT_SCORE;

  // CRITICAL: Dampen based on EFFECTIVE EVIDENCE, not raw count.
  // 5 receipts from unestablished entities (0.1x each) = 0.5 effective evidence.
  // That means the score stays near 50. You need REAL credibility to move the needle.
  // This is what makes Sybil attacks worthless.
  const ESTABLISHMENT_THRESHOLD = 5.0;
  if (effectiveEvidence < ESTABLISHMENT_THRESHOLD) {
    score = DEFAULT_SCORE + (score - DEFAULT_SCORE) * (effectiveEvidence / ESTABLISHMENT_THRESHOLD);
  }

  // CANONICAL ESTABLISHMENT: effective evidence >= 5 AND 3+ unique submitters
  const uniqueSubmitters = new Set(window.map(r => r.submitted_by).filter(Boolean)).size;
  const established = effectiveEvidence >= ESTABLISHMENT_THRESHOLD && uniqueSubmitters >= 3;

  score = Math.round(Math.max(0, Math.min(100, score)) * 10) / 10;

  return {
    score,
    breakdown: {
      delivery_accuracy:  signals.delivery_accuracy != null ? Math.round(signals.delivery_accuracy * 10) / 10 : null,
      product_accuracy:   signals.product_accuracy != null ? Math.round(signals.product_accuracy * 10) / 10 : null,
      price_integrity:    signals.price_integrity != null ? Math.round(signals.price_integrity * 10) / 10 : null,
      return_processing:  signals.return_processing != null ? Math.round(signals.return_processing * 10) / 10 : null,
      agent_satisfaction: signals.agent_satisfaction != null ? Math.round(signals.agent_satisfaction * 10) / 10 : null,
      consistency:        Math.round(consistencyScore * 10) / 10,
    },
    receiptCount: count,
    effectiveEvidence: Math.round(effectiveEvidence * 100) / 100,
    uniqueSubmitters,
    established,
  };
}

// =============================================================================
// SUBMITTER WEIGHT — receipts from trusted entities count more
// =============================================================================
/**
 * Compute how much weight a receipt carries based on the submitter's credibility.
 * 
 * TWO FACTORS:
 *   1. Submitter's EMILIA score (0-100)
 *   2. Whether the submitter is established (5+ receipts from 3+ unique submitters)
 * 
 * An ESTABLISHED score-90 entity's receipt counts 0.9x.
 * An ESTABLISHED score-50 entity's receipt counts 0.5x.
 * An UNESTABLISHED entity's receipt counts 0.1x REGARDLESS of score.
 * 
 * This is the Sybil killer. Creating 100 fake entities to boost a score is
 * useless — each fake entity is unestablished, so their receipts carry 0.1x
 * weight. To get meaningful weight, each fake entity would need 5+ receipts
 * from 3+ OTHER established entities. The cost spirals exponentially.
 * 
 * @param {number|null} submitterScore - The submitter's EMILIA score (0-100)
 * @param {boolean} submitterEstablished - Whether submitter has 5+ receipts from 3+ submitters
 * @returns {number} Weight multiplier (0.1 to 1.0)
 */
export function computeSubmitterWeight(submitterScore, submitterEstablished = false) {
  // Unestablished entities get minimum weight — this prevents Sybil attacks
  // where someone creates throwaway entities to inflate scores
  if (!submitterEstablished) return 0.1;
  
  if (submitterScore == null || isNaN(submitterScore)) return 0.5;
  return Math.max(0.1, Math.min(1.0, submitterScore / 100));
}

// =============================================================================
// TIME DECAY — recent receipts matter more, entities can recover
// =============================================================================
/**
 * Compute time-decay weight for a receipt.
 * 
 * Recent receipts carry full weight. Older receipts decay exponentially.
 * This allows entities to recover from bad periods — a merchant who was
 * terrible 6 months ago but has been perfect since will see their score
 * improve as old receipts decay.
 * 
 * Half-life: 90 days. A 90-day-old receipt carries 0.5x weight.
 * A 180-day-old receipt carries 0.25x. A 1-year-old receipt carries ~0.06x.
 * Floor: 0.05 (very old receipts never fully disappear — history matters).
 * 
 * @param {string|Date|null} createdAt - Receipt creation timestamp
 * @param {number} now - Current time in ms (Date.now())
 * @returns {number} Weight multiplier (0.05 to 1.0)
 */
export function computeTimeDecay(createdAt, now) {
  if (!createdAt) return 1.0;
  const receiptTime = new Date(createdAt).getTime();
  if (isNaN(receiptTime)) return 1.0;
  const ageDays = Math.max(0, (now - receiptTime) / (1000 * 60 * 60 * 24));
  const HALF_LIFE_DAYS = 90;
  const decay = Math.pow(0.5, ageDays / HALF_LIFE_DAYS);
  return Math.max(0.05, decay);
}

// =============================================================================
// MATCHING SCORE — for need-to-entity matching
// =============================================================================
/**
 * Compute the match score between a need and an entity.
 * Used by the need feed to rank candidates.
 * 
 * @param {number} cosineSimilarity - 0-1, from pgvector
 * @param {number} emiliaScore - 0-100, entity's EMILIA Score
 * @param {number} minScore - minimum required score (from the need)
 * @returns {number|null} match score (0-1), or null if below minimum
 */
export function computeMatchScore(cosineSimilarity, emiliaScore, minScore = 0) {
  if (emiliaScore < minScore) return null;

  // 60% relevance, 40% reputation
  const matchScore = (cosineSimilarity * 0.6) + ((emiliaScore / 100) * 0.4);
  return Math.round(matchScore * 1000) / 1000;
}

// =============================================================================
// BEHAVIORAL AGENT SATISFACTION — observable actions, not opinions
// =============================================================================
/**
 * Convert an agent's observable behavior into a satisfaction score.
 * This replaces subjective 0-100 ratings with behavioral signals.
 *
 * "FICO doesn't ask borrowers to rate their lender. It watches whether they pay.
 *  EP doesn't ask agents to rate merchants. It watches whether they come back."
 *
 * PRECISE DEFINITIONS:
 *   completed         — Transaction finished successfully, no retry needed.
 *   retried_same      — Same task, same counterparty, new attempt. Indicates a minor
 *                        issue that was resolved (e.g., timeout, partial delivery fixed).
 *   retried_different — Same task category, but agent switched to a different counterparty.
 *                        Indicates lost trust in the original entity.
 *   abandoned         — Agent stopped pursuing this task category entirely within 30 days.
 *                        The task was not completed by any counterparty.
 *   disputed          — Agent filed a formal dispute against the counterparty, triggering
 *                        the conflict receipt process.
 *
 * The submitting agent self-reports its behavior. This is self-enforcing: an agent that
 * lies about completing (to inflate a merchant's score) will route back to that merchant
 * and get burned. You rate what you eat.
 *
 * @param {string} behavior - One of: completed, retried_same, retried_different, abandoned, disputed
 * @returns {number} 0-100 satisfaction score
 */
export function behaviorToSatisfaction(behavior) {
  const BEHAVIOR_SCORES = {
    completed:          95,  // Transaction completed without retry
    retried_same:       75,  // Agent retried with the same entity (minor issue resolved)
    retried_different:  40,  // Agent switched to a different entity
    abandoned:          15,  // Agent abandoned the transaction entirely
    disputed:            5,  // Agent filed a dispute
  };
  return BEHAVIOR_SCORES[behavior] ?? null;
}

// =============================================================================
// EVIDENCE-BASED SCORING — v2 receipts (Phase 1.5)
// =============================================================================
/**
 * Compute signal scores from structured claims + evidence.
 * This is the Phase 2 upgrade: instead of asking agents to rate 0-100,
 * ask them to report WHAT HAPPENED and compute the score from facts.
 *
 * v1 receipts (manual 0-100) continue to work unchanged.
 * v2 receipts (claims object) are computed here and merged in.
 *
 * @param {Object} claims - Structured claims from v2 receipt
 * @returns {Object} Computed signal scores { delivery_accuracy, product_accuracy, ... }
 */
export function computeScoresFromClaims(claims) {
  if (!claims || typeof claims !== 'object') return {};

  const scores = {};

  // Delivery accuracy: delivered + on_time
  if (claims.delivered != null) {
    let deliveryScore = claims.delivered ? 80 : 0;
    if (claims.delivered && claims.on_time != null) {
      if (typeof claims.on_time === 'boolean') {
        deliveryScore = claims.on_time ? 100 : 70;
      } else if (claims.on_time.promised && claims.on_time.actual) {
        const promised = new Date(claims.on_time.promised).getTime();
        const actual = new Date(claims.on_time.actual).getTime();
        const delayHours = Math.max(0, (actual - promised) / (1000 * 60 * 60));
        if (delayHours <= 0) deliveryScore = 100;
        else if (delayHours <= 24) deliveryScore = 85;
        else if (delayHours <= 72) deliveryScore = 65;
        else deliveryScore = 40;
      }
    }
    scores.delivery_accuracy = deliveryScore;
  }

  // Product accuracy: as_described
  if (claims.as_described != null) {
    scores.product_accuracy = claims.as_described ? 100 : 20;
  }

  // Price integrity: price_honored
  if (claims.price_honored != null) {
    if (typeof claims.price_honored === 'boolean') {
      scores.price_integrity = claims.price_honored ? 100 : 10;
    } else {
      // Accept both quoted/charged and quoted_cents/charged_cents
      const quoted = claims.price_honored.quoted ?? claims.price_honored.quoted_cents;
      const charged = claims.price_honored.charged ?? claims.price_honored.charged_cents;
      if (quoted != null && charged != null && quoted > 0) {
        const overcharge = (charged - quoted) / quoted;
        if (overcharge <= 0) scores.price_integrity = 100;
        else if (overcharge <= 0.02) scores.price_integrity = 90;
        else if (overcharge <= 0.05) scores.price_integrity = 70;
        else if (overcharge <= 0.10) scores.price_integrity = 40;
        else scores.price_integrity = 10;
      }
    }
  }

  // Return processing: return_accepted
  if (claims.return_accepted != null) {
    scores.return_processing = claims.return_accepted ? 95 : 15;
  }

  return scores;
}

// =============================================================================
// RECEIPT HASH — for cryptographic integrity
// =============================================================================

/**
 * Canonical JSON serialization with sorted keys.
 * Required for cross-language hash verification (Python/Rust/Go must produce same hash).
 */
function canonicalJSON(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'number' || typeof obj === 'boolean') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
  }
  return JSON.stringify(obj);
}

/**
 * Compute a deterministic hash for a receipt.
 * Includes ALL truth-bearing fields with canonical JSON serialization.
 * 
 * @param {Object} receipt - the receipt data
 * @param {string|null} previousHash - hash of the previous receipt for this entity
 * @returns {string} SHA-256 hex hash
 */
export async function computeReceiptHash(receipt, previousHash = null) {
  const payload = canonicalJSON({
    // Identity
    entity_id: receipt.entity_id,
    submitted_by: receipt.submitted_by,
    transaction_ref: receipt.transaction_ref,
    transaction_type: receipt.transaction_type,
    // Numeric signals
    delivery_accuracy: receipt.delivery_accuracy ?? null,
    product_accuracy: receipt.product_accuracy ?? null,
    price_integrity: receipt.price_integrity ?? null,
    return_processing: receipt.return_processing ?? null,
    agent_satisfaction: receipt.agent_satisfaction ?? null,
    // Behavioral and claims (v2)
    agent_behavior: receipt.agent_behavior ?? null,
    claims: receipt.claims ?? null,
    // Evidence
    evidence: receipt.evidence ?? null,
    // Submitter credibility at time of submission
    submitter_score: receipt.submitter_score ?? null,
    submitter_established: receipt.submitter_established ?? false,
    // Chain link
    previous_hash: previousHash,
    // Version (for future schema changes)
    receipt_version: 1,
  });

  // Works in both Node.js and Edge runtime
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buffer = new TextEncoder().encode(payload);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Node.js fallback
  const { createHash } = await import('crypto');
  return createHash('sha256').update(payload).digest('hex');
}
