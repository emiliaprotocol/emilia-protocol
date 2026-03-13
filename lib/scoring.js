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
 * @param {Array} receipts - Array of receipt objects, most recent first
 * @returns {Object} { score, breakdown, receiptCount, established }
 */
export function computeEmiliaScore(receipts) {
  if (!receipts || receipts.length === 0) {
    return {
      score: DEFAULT_SCORE,
      breakdown: null,
      receiptCount: 0,
      established: false,
    };
  }

  // Use rolling window
  const window = receipts.slice(0, RECEIPT_WINDOW);
  const count = window.length;

  // Compute average for each signal
  const signals = {};
  for (const signal of Object.keys(EMILIA_WEIGHTS)) {
    if (signal === 'consistency') continue;
    const values = window
      .map(r => r[signal])
      .filter(v => v != null && !isNaN(v));
    signals[signal] = values.length > 0
      ? values.reduce((a, b) => a + b, 0) / values.length
      : null;
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

  // Dampen new entities toward 50 (insufficient data)
  const established = count >= MIN_RECEIPTS_ESTABLISHED;
  if (!established) {
    score = DEFAULT_SCORE + (score - DEFAULT_SCORE) * (count / MIN_RECEIPTS_ESTABLISHED);
  }

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
    established,
  };
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
// RECEIPT HASH — for cryptographic integrity
// =============================================================================
/**
 * Compute a deterministic hash for a receipt.
 * This ensures receipts cannot be tampered with after creation.
 * 
 * @param {Object} receipt - the receipt data
 * @param {string|null} previousHash - hash of the previous receipt for this entity
 * @returns {string} SHA-256 hex hash
 */
export async function computeReceiptHash(receipt, previousHash = null) {
  const payload = JSON.stringify({
    entity_id: receipt.entity_id,
    submitted_by: receipt.submitted_by,
    transaction_ref: receipt.transaction_ref,
    transaction_type: receipt.transaction_type,
    delivery_accuracy: receipt.delivery_accuracy,
    product_accuracy: receipt.product_accuracy,
    price_integrity: receipt.price_integrity,
    return_processing: receipt.return_processing,
    agent_satisfaction: receipt.agent_satisfaction,
    evidence: receipt.evidence,
    previous_hash: previousHash,
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
