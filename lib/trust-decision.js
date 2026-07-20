/**
 * @typedef {Object} TrustDecisionParams
 * @property {string} decision - 'allow' | 'review' | 'deny'
 * @property {string} entityId
 * @property {string} policyUsed - policy name
 * @property {string} confidence - e.g. 'confident' | 'emerging' | 'provisional' | 'insufficient' | 'pending'
 * @property {string[]} [reasons] - why this decision was reached
 * @property {string[]} [warnings] - non-blocking concerns
 * @property {string} [appealPath] - URL path for disputes/appeals
 * @property {Object|null} [contextUsed] - context keys that influenced the decision
 * @property {Object|null} [profileSummary] - { confidence, evidenceLevel, behavioralRates, disputeRate }
 * @property {Object|null} [extensions] - additional fields specific to the decision surface
 */

/**
 * Canonical Trust Decision — EP's primary output object.
 * @license Apache-2.0
 * Every decision surface MUST return this shape.
 *
 * @param {TrustDecisionParams} params
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
 * Maps a boolean result to the canonical decision enum (allow/deny).
 * @param {*} pass - truthy/falsy value; deliberately untyped (any input type is valid, only truthiness matters)
 */
export function passToDecision(pass) {
  return pass ? 'allow' : 'deny';
}
