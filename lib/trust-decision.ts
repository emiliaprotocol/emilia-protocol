/**
 * Canonical Trust Decision — EP's primary output object.
 * Every decision surface MUST return this shape.
 */
export function buildTrustDecision({
  decision,
  entityId,
  policyUsed,
  confidence,
  reasons,
  warnings,
  appealPath,
  contextUsed,
  profileSummary,
  extensions,
}: {
  decision: 'allow' | 'review' | 'deny';
  entityId: string;
  policyUsed: string;
  confidence: string;
  reasons?: string[];
  warnings?: string[];
  appealPath?: string;
  contextUsed?: Record<string, any>;
  profileSummary?: Record<string, any>;
  extensions?: Record<string, any>;
}): Record<string, any> {
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
 */
export function passToDecision(pass: boolean): 'allow' | 'deny' {
  return pass ? 'allow' : 'deny';
}
