/**
 * EP Protocol-Level Enumeration Constants
 *
 * Canonical source of truth for all hardcoded string constants used across
 * the Emilia Protocol codebase. Any status value, tier, or categorical
 * label that appears in database queries, conditional checks, or record
 * creation should be defined here.
 *
 * ALREADY CENTRALIZED ELSEWHERE (do NOT duplicate here):
 *   - OPERATOR_ROLES, DISPUTE_STATES, CONTINUITY_STATES,
 *     VISIBILITY_TIERS, ABUSE_PATTERNS, DUAL_CONTROL_ACTIONS
 *       → lib/procedural-justice.js
 *   - HANDSHAKE_MODES, HANDSHAKE_STATUSES, ASSURANCE_LEVELS,
 *     ASSURANCE_RANK, VALID_PARTY_ROLES, VALID_DISCLOSURE_MODES,
 *     CANONICAL_BINDING_FIELDS, BINDING_MATERIAL_VERSION
 *       → lib/handshake/invariants.js
 *   - SIGNOFF_STATUS_ORDER, SIGNOFF_TERMINAL_STATES,
 *     SIGNOFF_ALLOWED_METHODS, SIGNOFF_ASSURANCE_LEVELS,
 *     SIGNOFF_ASSURANCE_RANK
 *       → lib/signoff/invariants.js
 *   - SIGNOFF_EVENT_TYPES
 *       → lib/signoff/events.js
 *
 * @license Apache-2.0
 */

// =============================================================================
// 1. ENTITY STATUS
// =============================================================================

/**
 * Top-level entity lifecycle statuses.
 * Used in: lib/commit.js, lib/supabase.js, lib/canonical-evaluator.js,
 *          lib/zk-proofs.js, lib/delegation.js, lib/dispute-adjudication.js,
 *          lib/cloud/auth.js, lib/cloud/tenant-manager.js, lib/ep-ix.js,
 *          app/api/entities/search/route.js, app/api/score/[entityId]/route.js,
 *          app/api/stats/route.js, app/api/leaderboard/route.js,
 *          app/entity/[entityId]/page.js
 */
export const ENTITY_STATUS = Object.freeze({
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  SUSPENDED: 'suspended',
});

// =============================================================================
// 2. COMMIT STATUS
// =============================================================================

/**
 * Commit lifecycle statuses.
 * Used in: lib/commit.js (TERMINAL_STATUSES, status checks, DB updates)
 */
export const COMMIT_STATUS = Object.freeze({
  ACTIVE: 'active',
  FULFILLED: 'fulfilled',
  REVOKED: 'revoked',
  EXPIRED: 'expired',
});

/**
 * Terminal commit statuses — once a commit reaches one of these,
 * no further state transitions are permitted.
 */
export const COMMIT_TERMINAL_STATUSES = Object.freeze([
  COMMIT_STATUS.FULFILLED,
  COMMIT_STATUS.REVOKED,
  COMMIT_STATUS.EXPIRED,
]);

// =============================================================================
// 3. COMMIT ACTIONS & DECISIONS
// =============================================================================

/**
 * Valid commit action types.
 * Used in: lib/commit.js (VALID_ACTIONS)
 */
export const COMMIT_ACTIONS = Object.freeze({
  INSTALL: 'install',
  CONNECT: 'connect',
  DELEGATE: 'delegate',
  TRANSACT: 'transact',
});

/**
 * Valid commit trust decisions.
 * Used in: lib/commit.js (VALID_DECISIONS)
 */
export const COMMIT_DECISIONS = Object.freeze({
  ALLOW: 'allow',
  REVIEW: 'review',
  DENY: 'deny',
});

// =============================================================================
// 4. RECEIPT / BILATERAL STATUS
// =============================================================================

/**
 * Bilateral confirmation statuses for receipts.
 * Used in: lib/canonical-writer.js, lib/create-receipt.js,
 *          lib/protocol-write.js
 */
export const BILATERAL_STATUS = Object.freeze({
  PENDING_CONFIRMATION: 'pending_confirmation',
  CONFIRMED: 'confirmed',
  DISPUTED: 'disputed',
  EXPIRED: 'expired',
});

// =============================================================================
// 5. AGENT BEHAVIOR
// =============================================================================

/**
 * Agent behavior outcomes recorded on receipts.
 * Used in: lib/canonical-writer.js, lib/attribution.js,
 *          lib/dispute-adjudication.js, lib/domain-scoring.js,
 *          app/api/receipts/submit/route.js
 */
export const AGENT_BEHAVIOR = Object.freeze({
  COMPLETED: 'completed',
  RETRIED_SAME: 'retried_same',
  RETRIED_DIFFERENT: 'retried_different',
  ABANDONED: 'abandoned',
  DISPUTED: 'disputed',
});

// =============================================================================
// 6. PROVENANCE TIER
// =============================================================================

/**
 * Receipt provenance tiers — how the receipt's authenticity was established.
 * Used in: lib/signatures.js, lib/canonical-writer.js, lib/create-receipt.js,
 *          lib/scoring-v2.js, lib/domain-scoring.js, lib/ep-ix.js
 */
export const PROVENANCE_TIER = Object.freeze({
  SELF_ATTESTED: 'self_attested',
  IDENTIFIED_SIGNED: 'identified_signed',
  BILATERAL: 'bilateral',
  PLATFORM_ORIGINATED: 'platform_originated',
  CARRIER_VERIFIED: 'carrier_verified',
  ORACLE_VERIFIED: 'oracle_verified',
});

// =============================================================================
// 7. CONFIDENCE LEVELS
// =============================================================================

/**
 * Trust-profile confidence levels, ordered from lowest to highest.
 * Used in: lib/scoring-v2.js, lib/domain-scoring.js,
 *          lib/trust-decision.js, lib/dispute-adjudication.js,
 *          app/api/entities/search/route.js, app/api/feed/route.js,
 *          app/api/leaderboard/route.js, app/api/trust/gate/route.js,
 *          app/api/needs/broadcast/route.js, app/api/entities/register/route.js
 */
export const CONFIDENCE_LEVEL = Object.freeze({
  PENDING: 'pending',
  INSUFFICIENT: 'insufficient',
  PROVISIONAL: 'provisional',
  EMERGING: 'emerging',
  CONFIDENT: 'confident',
});

/**
 * Ordered array for rank comparisons (index = rank).
 */
export const CONFIDENCE_LEVEL_ORDER = Object.freeze([
  CONFIDENCE_LEVEL.PENDING,
  CONFIDENCE_LEVEL.INSUFFICIENT,
  CONFIDENCE_LEVEL.PROVISIONAL,
  CONFIDENCE_LEVEL.EMERGING,
  CONFIDENCE_LEVEL.CONFIDENT,
]);

// =============================================================================
// 8. DELEGATION STATUS
// =============================================================================

/**
 * Delegation lifecycle statuses.
 * Used in: lib/delegation.js
 */
export const DELEGATION_STATUS = Object.freeze({
  ACTIVE: 'active',
  REVOKED: 'revoked',
  EXPIRED: 'expired',
});

// =============================================================================
// 9. AUTHORITY STATUS
// =============================================================================

/**
 * Authority / key status values.
 * Used in: lib/handshake/invariants.js (checkAuthorityNotRevoked),
 *          lib/handshake/present.js, lib/handshake/verify.js,
 *          lib/handshake/policy.js
 */
export const AUTHORITY_STATUS = Object.freeze({
  ACTIVE: 'active',
  REVOKED: 'revoked',
  RETIRED: 'retired',
});

// =============================================================================
// 10. HANDSHAKE OUTCOME
// =============================================================================

/**
 * Verification outcome values for handshake results.
 * Used in: lib/handshake/verify.js, lib/handshake/invariants.js,
 *          lib/handshake/trust-decision-bridge.js
 */
export const HANDSHAKE_OUTCOME = Object.freeze({
  ACCEPTED: 'accepted',
  REJECTED: 'rejected',
  EXPIRED: 'expired',
});

// =============================================================================
// 11. RECEIPT DISPUTE STATUS
// =============================================================================

/**
 * Dispute status on individual receipts (not the full dispute state machine,
 * which lives in procedural-justice.js DISPUTE_STATES).
 * Used in: lib/canonical-writer.js
 */
export const RECEIPT_DISPUTE_STATUS = Object.freeze({
  CHALLENGED: 'challenged',
});

// =============================================================================
// 12. CONTINUITY CLAIM STATUS
// =============================================================================

/**
 * Continuity claim statuses used in EP-IX.
 * The full state machine with transitions lives in
 * procedural-justice.js CONTINUITY_STATES — these are the raw values.
 * Used in: lib/ep-ix.js
 */
export const CONTINUITY_STATUS = Object.freeze({
  PENDING: 'pending',
  UNDER_CHALLENGE: 'under_challenge',
  APPROVED_FULL: 'approved_full',
  APPROVED_PARTIAL: 'approved_partial',
  REJECTED: 'rejected',
  EXPIRED: 'expired',
});

// =============================================================================
// 13. NEEDS STATUS
// =============================================================================

/**
 * Need lifecycle statuses.
 * Used in: app/api/needs/[id]/complete/route.js,
 *          app/api/needs/[id]/claim/route.js,
 *          app/api/needs/[id]/rate/route.js
 */
export const NEED_STATUS = Object.freeze({
  COMPLETED: 'completed',
  EXPIRED: 'expired',
});

// =============================================================================
// 14. OPERATOR APPLICATION STATUS
// =============================================================================

/**
 * Operator application statuses.
 * Used in: app/api/operators/apply/route.js
 */
export const OPERATOR_APPLICATION_STATUS = Object.freeze({
  PENDING: 'pending',
});
