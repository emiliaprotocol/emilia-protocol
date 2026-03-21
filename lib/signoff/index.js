/**
 * EP Signoff — Barrel export for all accountable signoff operations.
 *
 * @license Apache-2.0
 */

// ── Challenge ───────────────────────────────────────────────────────────────
export { issueChallenge } from './challenge.js';

// ── Attestation ─────────────────────────────────────────────────────────────
export { createAttestation } from './attest.js';

// ── Consumption ─────────────────────────────────────────────────────────────
export { consumeSignoff, isSignoffConsumed } from './consume.js';

// ── Revocation ──────────────────────────────────────────────────────────────
export { revokeChallenge, revokeAttestation } from './revoke.js';

// ── Events ──────────────────────────────────────────────────────────────────
export {
  emitSignoffEvent,
  requireSignoffEvent,
  getSignoffEvents,
  SIGNOFF_EVENT_TYPES,
} from './events.js';

// ── Invariants ──────────────────────────────────────────────────────────────
export {
  SIGNOFF_STATUS_ORDER,
  SIGNOFF_TERMINAL_STATES,
  SIGNOFF_ALLOWED_METHODS,
  SIGNOFF_ASSURANCE_LEVELS,
  SIGNOFF_ASSURANCE_RANK,
} from './invariants.js';

// ── Errors ──────────────────────────────────────────────────────────────────
export { SignoffError } from './errors.js';
