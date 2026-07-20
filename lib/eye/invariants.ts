/**
 * EP Eye — Pure invariant constants.
 *
 * Canonical statuses, policy actions, severity hints, observation types,
 * scope binding fields, TTLs, and confidence classes for the Emilia Eye
 * trust-signal observation subsystem.
 *
 * @license Apache-2.0
 */

// ── Statuses ────────────────────────────────────────────────────────────────

export const EYE_STATUSES = Object.freeze([
  'clear',
  'caution',
  'elevated',
  'review_required',
]);

// ── Policy Actions ──────────────────────────────────────────────────────────

export const EYE_POLICY_ACTIONS = Object.freeze([
  'allow_normal_flow',
  'require_ep_handshake',
  'require_strict_ep_handshake',
  'require_accountable_signoff',
  'hold_for_manual_review',
]);

// ── Severity Hints ──────────────────────────────────────────────────────────

export const EYE_SEVERITY_HINTS = Object.freeze([
  'low',
  'medium',
  'high',
  'critical',
]);

// ── Observation Types ───────────────────────────────────────────────────────
// All ~25 signal classes from GOD FILE Section 9
// (government, financial, enterprise, AI/agent, issuer)

export const EYE_OBSERVATION_TYPES = Object.freeze([
  // Government / Regulatory
  'sanctions_match',
  'pep_match',
  'adverse_media',
  'watchlist_match',
  'regulatory_action',
  // Financial
  'unusual_transaction_pattern',
  'velocity_anomaly',
  'high_value_transfer',
  'cross_border_risk',
  'structuring_indicator',
  // Enterprise
  'privilege_escalation',
  'anomalous_access_pattern',
  'data_exfiltration_signal',
  'insider_threat_indicator',
  'policy_violation',
  // AI / Agent
  'agent_drift',
  'model_hallucination',
  'prompt_injection_attempt',
  'autonomous_action_anomaly',
  'delegation_chain_break',
  // Issuer / Credential
  'credential_compromise',
  'issuer_trust_degradation',
  'revocation_cascade',
  'stale_attestation',
  'binding_mismatch',
]);

// ── Scope Binding Fields ────────────────────────────────────────────────────

export const EYE_SCOPE_BINDING_FIELDS = Object.freeze([
  'actor_ref',
  'subject_ref',
  'action_type',
  'target_ref',
  'issuer_ref',
  'context_hash',
  'issued_at',
  'expires_at',
]);

// ── Default TTLs (seconds) ──────────────────────────────────────────────────

export const EYE_DEFAULT_TTL = Object.freeze({
  clear: 300,
  caution: 300,
  elevated: 180,
  review_required: 120,
});

// ── Confidence Classes ──────────────────────────────────────────────────────

export const EYE_CONFIDENCE_CLASSES = Object.freeze([
  'deterministic',
  'trusted',
  'heuristic',
]);

// ── Valid Sets (for O(1) membership checks) ─────────────────────────────────

export const VALID_EYE_STATUSES = new Set(EYE_STATUSES);
export const VALID_EYE_POLICY_ACTIONS = new Set(EYE_POLICY_ACTIONS);
export const VALID_EYE_SEVERITY_HINTS = new Set(EYE_SEVERITY_HINTS);
export const VALID_EYE_OBSERVATION_TYPES = new Set(EYE_OBSERVATION_TYPES);
export const VALID_EYE_CONFIDENCE_CLASSES = new Set(EYE_CONFIDENCE_CLASSES);
