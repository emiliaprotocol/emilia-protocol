/**
 * EP Procedural Justice Layer
 * 
 * Formalizes the human governance side of EP:
 *   - Operator roles and permissions
 *   - Evidence visibility tiers
 *   - Dispute/appeal/continuity state machines
 *   - Abuse detection and throttling
 *   - Operator auditability
 * 
 * Constitutional principle: trust must never be more powerful than appeal.
 * 
 * @license Apache-2.0
 */

import { emitAudit } from '@/lib/ep-ix';

// =============================================================================
// 1. OPERATOR ROLES
// =============================================================================

export const OPERATOR_ROLES = {
  reporter: {
    description: 'Can file reports and human appeals. No auth required.',
    permissions: ['report.file', 'appeal.file'],
    requires_auth: false,
  },
  disputant: {
    description: 'Can file disputes against specific receipts. Requires entity auth.',
    permissions: ['dispute.file', 'dispute.respond', 'evidence.submit'],
    requires_auth: true,
  },
  respondent: {
    description: 'Entity responding to a dispute filed against them.',
    permissions: ['dispute.respond', 'evidence.submit'],
    requires_auth: true,
  },
  reviewer: {
    description: 'Can review disputes, approve/reject continuity. Operator-level.',
    permissions: [
      'dispute.review', 'dispute.resolve',
      'continuity.review', 'continuity.resolve',
      'report.review', 'report.dismiss',
      'evidence.view_restricted',
    ],
    requires_auth: true,
    requires_role: 'reviewer',
  },
  appeal_reviewer: {
    description: 'Can review appeals of dispute resolutions. Senior operator.',
    permissions: [
      'appeal.review', 'appeal.resolve',
      'dispute.override',
      'evidence.view_restricted',
      'redaction.manage',
    ],
    requires_auth: true,
    requires_role: 'appeal_reviewer',
  },
  operator: {
    description: 'Full protocol operator. Can manage all trust-changing actions.',
    permissions: [
      'dispute.review', 'dispute.resolve', 'dispute.override',
      'continuity.review', 'continuity.resolve', 'continuity.freeze',
      'report.review', 'report.dismiss',
      'appeal.review', 'appeal.resolve',
      'entity.suspend', 'entity.unsuspend',
      'evidence.view_all', 'evidence.redact',
      'redaction.manage',
      'audit.view',
    ],
    requires_auth: true,
    requires_role: 'operator',
  },
  host_verifier: {
    description: 'External host that can verify identity bindings.',
    permissions: ['binding.verify', 'binding.revoke'],
    requires_auth: true,
    requires_role: 'host_verifier',
  },
};

/**
 * Check if a role has a specific permission.
 */
export function hasPermission(role, permission) {
  const roleDef = OPERATOR_ROLES[role];
  if (!roleDef) return false;
  return roleDef.permissions.includes(permission);
}

// =============================================================================
// 2. EVIDENCE VISIBILITY TIERS
// =============================================================================

export const VISIBILITY_TIERS = {
  public_summary: {
    level: 0,
    description: 'Visible to anyone. Sanitized summary only.',
    includes: ['entity_id', 'status', 'reason_category', 'outcome', 'created_at'],
    excludes: ['raw_evidence', 'internal_notes', 'operator_reasoning'],
  },
  redacted_public: {
    level: 1,
    description: 'Visible to authenticated entities. Proof types shown, contents redacted.',
    includes: ['entity_id', 'status', 'reason', 'proof_types', 'outcome', 'timeline'],
    excludes: ['raw_evidence', 'internal_notes', 'sensitive_identifiers'],
  },
  restricted: {
    level: 2,
    description: 'Visible to dispute parties and reviewers only.',
    includes: ['full_evidence', 'proof_payloads', 'timeline', 'reasoning'],
    excludes: ['internal_notes', 'operator_private_reasoning'],
  },
  operator_only: {
    level: 3,
    description: 'Visible only to operators and appeal reviewers.',
    includes: ['everything'],
    excludes: [],
  },
};

/**
 * Filter evidence object based on visibility tier.
 */
export function filterByVisibility(evidence, tier, role) {
  const tierDef = VISIBILITY_TIERS[tier];
  if (!tierDef) return {};

  // Operators see everything
  if (role === 'operator' || role === 'appeal_reviewer') {
    return evidence;
  }

  const filtered = {};
  for (const key of tierDef.includes) {
    if (key === 'everything') return evidence;
    if (evidence[key] !== undefined) filtered[key] = evidence[key];
  }
  return filtered;
}

// =============================================================================
// 3. STATE MACHINES
// =============================================================================

/**
 * Dispute state machine.
 * Valid transitions only — invalid transitions are rejected.
 */
export const DISPUTE_STATES = {
  open: {
    description: 'Dispute filed, awaiting response',
    valid_transitions: ['under_review', 'withdrawn'],
    timeout_action: 'escalate_to_under_review',
    timeout_days: 7,
  },
  under_review: {
    description: 'Response received or deadline passed, under operator review',
    valid_transitions: ['upheld', 'reversed', 'dismissed', 'appealed'],
    timeout_action: null,
  },
  upheld: {
    description: 'Dispute upheld — receipt stands, dispute dismissed in favor of receipt',
    valid_transitions: ['appealed'],
    terminal: false,
  },
  reversed: {
    description: 'Receipt reversed — trust recomputed, graph_weight → 0',
    valid_transitions: ['appealed'],
    terminal: false,
  },
  dismissed: {
    description: 'Dispute dismissed — insufficient evidence or invalid claim',
    valid_transitions: ['appealed'],
    terminal: false,
  },
  appealed: {
    description: 'Resolution appealed — escalated to appeal reviewer',
    valid_transitions: ['appeal_upheld', 'appeal_reversed', 'appeal_dismissed'],
    timeout_action: null,
  },
  appeal_upheld: {
    description: 'Appeal upheld — original resolution stands',
    valid_transitions: [],
    terminal: true,
  },
  appeal_reversed: {
    description: 'Appeal reversed — original resolution overturned',
    valid_transitions: [],
    terminal: true,
  },
  appeal_dismissed: {
    description: 'Appeal dismissed',
    valid_transitions: [],
    terminal: true,
  },
  withdrawn: {
    description: 'Dispute withdrawn by the filing party',
    valid_transitions: [],
    terminal: true,
  },
};

/**
 * Continuity state machine.
 */
export const CONTINUITY_STATES = {
  pending: {
    description: 'Claim filed, challenge window open',
    valid_transitions: ['under_challenge', 'approved_full', 'approved_partial', 'rejected', 'frozen_pending_dispute', 'expired'],
    timeout_action: 'auto_approve_if_unchallenged',
    timeout_days: 7,
  },
  under_challenge: {
    description: 'Challenge received, requires operator review',
    valid_transitions: ['approved_full', 'approved_partial', 'rejected', 'expired'],
    timeout_action: null,
  },
  frozen_pending_dispute: {
    description: 'Blocked by active disputes on old entity',
    valid_transitions: ['pending', 'rejected', 'expired'],
    timeout_action: null,
  },
  approved_full: {
    description: 'Full trust transfer approved',
    valid_transitions: [],
    terminal: true,
  },
  approved_partial: {
    description: 'Partial trust transfer — confidence dampened',
    valid_transitions: [],
    terminal: true,
  },
  rejected: {
    description: 'Continuity denied',
    valid_transitions: [],
    terminal: true,
  },
  expired: {
    description: '30-day deadline passed without resolution',
    valid_transitions: [],
    terminal: true,
  },
};

/**
 * Validate a state transition.
 * Returns { valid: true } or { valid: false, reason: '...' }
 */
export function validateTransition(stateMachine, currentState, targetState) {
  const state = stateMachine[currentState];
  if (!state) return { valid: false, reason: `Unknown current state: ${currentState}` };
  if (state.terminal) return { valid: false, reason: `State '${currentState}' is terminal — no transitions allowed` };
  if (!state.valid_transitions.includes(targetState)) {
    return { valid: false, reason: `Invalid transition: '${currentState}' → '${targetState}'. Valid: ${state.valid_transitions.join(', ')}` };
  }
  return { valid: true };
}

// =============================================================================
// 4. ABUSE DETECTION
// =============================================================================

/**
 * Abuse patterns to detect and throttle.
 */
export const ABUSE_PATTERNS = {
  repeated_identical_reports: {
    description: 'Same entity reported multiple times with same reason by same IP',
    detection: 'count reports with matching (entity_id, reason, reporter_ip) in 24h window',
    threshold: 3,
    action: 'rate_limit',
  },
  brigading: {
    description: 'Many reports against same entity from different IPs in short window',
    detection: 'count distinct reporter IPs for same entity_id in 1h window',
    threshold: 10,
    action: 'flag_for_review',
  },
  retaliatory_filing: {
    description: 'Dispute filed against entity that recently filed a dispute against the filer',
    detection: 'check if entity B filed dispute against A within 24h of A filing against B',
    threshold: 1,
    action: 'flag_for_review',
  },
  continuity_challenge_spam: {
    description: 'Multiple challenges against same continuity claim from same source',
    detection: 'count challenges with matching (continuity_id, challenger_id) in 7d window',
    threshold: 2,
    action: 'rate_limit',
  },
  dispute_flooding: {
    description: 'Entity filing many disputes in short window',
    detection: 'count disputes filed by same entity in 24h window',
    threshold: 10,
    action: 'rate_limit',
  },
};

/**
 * Check for abuse patterns on a proposed action.
 * Returns { allowed: true } or { allowed: false, pattern: '...', action: '...' }
 */
export async function checkAbuse(supabase, actionType, params) {
  const now = new Date();

  if (actionType === 'report') {
    // Check repeated identical reports
    const window24h = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    try {
      const { count } = await supabase
        .from('disputes')
        .select('id', { count: 'exact', head: true })
        .eq('entity_id', params.entity_id)
        .eq('reason', params.reason)
        .eq('reporter_ip', params.reporter_ip)
        .gte('created_at', window24h);

      if ((count || 0) >= ABUSE_PATTERNS.repeated_identical_reports.threshold) {
        return { allowed: false, pattern: 'repeated_identical_reports', action: 'rate_limit' };
      }
    } catch { /* table structure may differ */ }

    // Check brigading
    try {
      const window1h = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
      const { data: recentReports } = await supabase
        .from('disputes')
        .select('reporter_ip')
        .eq('entity_id', params.entity_id)
        .gte('created_at', window1h);

      const uniqueIps = new Set((recentReports || []).map(r => r.reporter_ip).filter(Boolean));
      if (uniqueIps.size >= ABUSE_PATTERNS.brigading.threshold) {
        return { allowed: false, pattern: 'brigading', action: 'flag_for_review' };
      }
    } catch { /* graceful */ }
  }

  if (actionType === 'dispute') {
    // Check retaliatory filing
    const window24h = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    try {
      const { count } = await supabase
        .from('disputes')
        .select('id', { count: 'exact', head: true })
        .eq('entity_id', params.filer_entity_id)
        .eq('filed_by', params.target_entity_id)
        .gte('created_at', window24h);

      if ((count || 0) >= ABUSE_PATTERNS.retaliatory_filing.threshold) {
        return { allowed: false, pattern: 'retaliatory_filing', action: 'flag_for_review' };
      }
    } catch { /* graceful */ }

    // Check dispute flooding
    try {
      const { count } = await supabase
        .from('disputes')
        .select('id', { count: 'exact', head: true })
        .eq('filed_by', params.filer_entity_id)
        .gte('created_at', new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString());

      if ((count || 0) >= ABUSE_PATTERNS.dispute_flooding.threshold) {
        return { allowed: false, pattern: 'dispute_flooding', action: 'rate_limit' };
      }
    } catch { /* graceful */ }
  }

  return { allowed: true };
}

// =============================================================================
// 5. OPERATOR AUDIT TRAIL
// =============================================================================

/**
 * Record an operator action with full before/after state.
 */
export async function recordOperatorAction(supabase, params) {
  const { operatorId, operatorRole, targetType, targetId, action, beforeState, afterState, reasoning } = params;

  await emitAudit(
    `operator.${action}`,
    operatorId,
    'operator',
    targetType,
    targetId,
    action,
    beforeState,
    { ...afterState, reasoning, operator_role: operatorRole }
  );

  return { recorded: true };
}
