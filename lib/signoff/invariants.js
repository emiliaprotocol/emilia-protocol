/**
 * EP Signoff — Pure invariant constants.
 *
 * Canonical status ordering, terminal states, allowed authentication
 * methods, and assurance levels for the accountable signoff subsystem.
 *
 * @license Apache-2.0
 */

// ── Status Ordering ─────────────────────────────────────────────────────────
// Ordered array of valid statuses in the signoff lifecycle.
// A signoff progresses forward through this list; backward transitions
// are never permitted.

export const SIGNOFF_STATUS_ORDER = Object.freeze([
  'challenge_issued',
  'challenge_viewed',
  'approved',
  'denied',
  'consumed',
  'expired',
  'revoked',
]);

// ── Terminal States ─────────────────────────────────────────────────────────
// Once a signoff reaches a terminal state, no further transitions are allowed.

export const SIGNOFF_TERMINAL_STATES = Object.freeze([
  'denied',
  'consumed',
  'expired',
  'revoked',
]);

// ── Allowed Authentication Methods ──────────────────────────────────────────

export const SIGNOFF_ALLOWED_METHODS = Object.freeze([
  'passkey',
  'secure_app',
  'platform_authenticator',
  'out_of_band',
  'dual_signoff',
]);

// ── Assurance Levels ────────────────────────────────────────────────────────

export const SIGNOFF_ASSURANCE_LEVELS = Object.freeze([
  'low',
  'substantial',
  'high',
]);

export const SIGNOFF_ASSURANCE_RANK = Object.freeze({
  low: 1,
  substantial: 2,
  high: 3,
});

// ── Valid Sets (for O(1) membership checks) ─────────────────────────────────

export const VALID_SIGNOFF_STATUSES = new Set(SIGNOFF_STATUS_ORDER);
export const VALID_TERMINAL_STATES = new Set(SIGNOFF_TERMINAL_STATES);
export const VALID_ALLOWED_METHODS = new Set(SIGNOFF_ALLOWED_METHODS);
export const VALID_ASSURANCE_LEVELS = new Set(SIGNOFF_ASSURANCE_LEVELS);
