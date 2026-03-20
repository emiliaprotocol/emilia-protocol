/**
 * Trust Decision Bridge — Maps handshake outcomes to TrustDecision format.
 *
 * Bridges the EP Handshake verification result into the canonical
 * TrustDecision shape used across all EP decision surfaces.
 *
 * @license Apache-2.0
 */

import { buildTrustDecision } from '@/lib/trust-decision';

// ── Outcome-to-Decision Mapping ─────────────────────────────────────────────

const OUTCOME_TO_DECISION = {
  accepted: 'allow',
  rejected: 'deny',
  partial: 'review',
  expired: 'review',
};

// ── Assurance-to-Confidence Score ───────────────────────────────────────────

const ASSURANCE_CONFIDENCE_SCORE = {
  high: 0.95,
  substantial: 0.85,
  medium: 0.70,
  low: 0.50,
};

// ── Confidence Label Mapping ────────────────────────────────────────────────

const SCORE_TO_CONFIDENCE_LABEL = [
  [0.90, 'confident'],
  [0.80, 'emerging'],
  [0.60, 'provisional'],
  [0.0, 'insufficient'],
];

function scoreToLabel(score) {
  for (const [threshold, label] of SCORE_TO_CONFIDENCE_LABEL) {
    if (score >= threshold) return label;
  }
  return 'insufficient';
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Map a handshake verification result to a TrustDecision-compatible object.
 *
 * @param {object} handshakeResult - The result from verifyHandshake()
 * @param {string} handshakeResult.handshake_id
 * @param {string} handshakeResult.outcome - 'accepted' | 'rejected' | 'partial' | 'expired'
 * @param {string[]} handshakeResult.reason_codes
 * @param {string|null} handshakeResult.assurance_achieved
 * @param {string} handshakeResult.policy_version
 * @param {string|null} handshakeResult.commit_ref
 * @returns {object} TrustDecision-compatible object
 */
export function mapHandshakeToTrustDecision(handshakeResult) {
  if (!handshakeResult || !handshakeResult.outcome) {
    throw new Error('handshakeResult with outcome is required');
  }

  const {
    handshake_id,
    outcome,
    reason_codes = [],
    assurance_achieved,
    policy_version,
    commit_ref,
  } = handshakeResult;

  const decision = OUTCOME_TO_DECISION[outcome] || 'deny';
  const confidenceScore = ASSURANCE_CONFIDENCE_SCORE[assurance_achieved] || 0.50;
  const confidenceLabel = scoreToLabel(confidenceScore);

  // Build structured reasons from reason_codes
  const reasons = reason_codes.length > 0
    ? reason_codes.map((code) => `handshake: ${code}`)
    : [`handshake: ${outcome}`];

  // Build warnings for non-blocking outcomes
  const warnings = [];
  if (outcome === 'partial') {
    warnings.push('Handshake partially verified — some assurance checks did not pass');
  }
  if (outcome === 'expired') {
    warnings.push('Handshake binding window has expired');
  }

  // Build evidence extensions
  const evidence = {
    handshake_id: handshake_id || null,
    policy_ref: policy_version || null,
    binding_hash: commit_ref || null,
    assurance_achieved: assurance_achieved || null,
    confidence_score: confidenceScore,
    outcome,
  };

  return buildTrustDecision({
    decision,
    entityId: handshake_id || 'unknown',
    policyUsed: policy_version || 'unknown',
    confidence: confidenceLabel,
    reasons,
    warnings,
    appealPath: '/api/disputes/report',
    contextUsed: {
      source: 'handshake',
      handshake_id,
      assurance_achieved,
    },
    profileSummary: null,
    extensions: { evidence },
  });
}

/**
 * Determine whether a handshake outcome warrants creating a TrustDecision.
 *
 * Only definitive outcomes (accepted, rejected) trigger decisions.
 * Intermediate states (partial, expired) do not — they require
 * further action before a final decision is appropriate.
 *
 * @param {object} handshakeResult
 * @param {string} handshakeResult.outcome
 * @returns {boolean}
 */
export function shouldTriggerDecision(handshakeResult) {
  if (!handshakeResult || !handshakeResult.outcome) return false;
  return handshakeResult.outcome === 'accepted' || handshakeResult.outcome === 'rejected';
}
