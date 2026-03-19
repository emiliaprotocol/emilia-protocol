/**
 * Canonical Trust Decision — EP's primary output object.
 * Every decision surface MUST return this shape.
 *
 * @param {Object} params
 * @returns {Object} TrustDecision
 */
export function buildTrustDecision({
  decision,        // 'allow' | 'review' | 'deny'
  entityId,        // string
  policyUsed,      // string — policy name
  confidence,      // string — 'confident' | 'emerging' | 'provisional' | 'insufficient' | 'pending'
  reasons,         // string[] — why this decision was reached
  warnings,        // string[] — non-blocking concerns
  appealPath,      // string — URL path for disputes/appeals
  contextUsed,     // object — context keys that influenced the decision
  profileSummary,  // object — { confidence, evidenceLevel, behavioralRates, disputeRate }
  extensions,      // object — additional fields specific to the decision surface
}) {
  return {
    decision,
    entity_id: entityId,
    policy_used: policyUsed,
    confidence,
    reasons: reasons || [],
    warnings: warnings || [],
    appeal_path: appealPath || '/api/disputes/report',
    context_used: contextUsed || null,
    profile_summary: profileSummary || null,
    ...(extensions || {}),
  };
}

/**
 * Maps a boolean pass/fail to the canonical decision enum.
 */
export function passToDecision(pass) {
  return pass ? 'allow' : 'deny';
}
