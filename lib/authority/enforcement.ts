// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-REGISTRY-v1 — staged enforcement.
 *
 * Authority enforcement rolls out on its OWN axis, server-pinned and never
 * caller-selectable (the guard enforcement mode IS caller-selectable and can
 * downgrade a block to observe; authority must not inherit that hole):
 *
 *   shadow  ─▶  warn  ─▶  enforce_critical  ─▶  enforce_default
 *
 *   shadow            resolve, bind into the receipt, LOG what would have been
 *                     denied. Never blocks. Behavior identical to today — this
 *                     is the safe default while the registry is populated.
 *   warn              same, but the decision is surfaced to the caller as a
 *                     warning. Still never blocks.
 *   enforce_critical  CRITICAL actions (money movement, payee change, the
 *                     Class-A set) FAIL CLOSED when authority is not `authorized`.
 *                     Non-critical actions still only warn.
 *   enforce_default   every action fails closed when authority is not authorized.
 *
 * The non-negotiable invariant: a non-`authorized` verdict on a blocked path
 * yields `not_admissible`, never "unknown but allow." Unresolved authority
 * (registry unavailable / no record) is the umbrella code `authority_unresolved`.
 */

export const AUTHORITY_ENFORCEMENT_MODES = Object.freeze({
  SHADOW: 'shadow',
  WARN: 'warn',
  ENFORCE_CRITICAL: 'enforce_critical',
  ENFORCE_DEFAULT: 'enforce_default',
});

const ORDER = Object.freeze(['shadow', 'warn', 'enforce_critical', 'enforce_default']);

/** Verdicts where authority truly could not be established (vs. a definite deny). */
const UNRESOLVED = new Set(['registry_unavailable', 'unknown_authority']);

export function isAuthorityEnforcementMode(mode) {
  return ORDER.includes(mode);
}

/** Map a resolver verdict to a stable admissibility code. */
export function authorityAdmissibilityCode(verdict) {
  if (verdict === 'authorized') return 'admissible';
  if (UNRESOLVED.has(verdict)) return 'authority_unresolved';
  return `authority_${verdict}`;
}

/**
 * Decide what a resolver verdict means under a given rollout mode.
 *
 * @param {object} p
 * @param {string} p.verdict     one of AUTHORITY_VERDICTS
 * @param {boolean} p.isCritical whether the action is critical (fail-closed set)
 * @param {string} p.mode        one of AUTHORITY_ENFORCEMENT_MODES
 * @returns {{ mode, verdict, block:boolean, admissibility:'admissible'|'observed'|'not_admissible',
 *            code:string, warn:boolean, reason:string }}
 */
export function applyAuthorityEnforcement({ verdict, isCritical, mode }) {
  const m = isAuthorityEnforcementMode(mode) ? mode : AUTHORITY_ENFORCEMENT_MODES.SHADOW;
  const code = authorityAdmissibilityCode(verdict);

  if (verdict === 'authorized') {
    return { mode: m, verdict, block: false, admissibility: 'admissible', code, warn: false, reason: 'authorized' };
  }

  // Not authorized. Decide by mode.
  const willBlock = m === AUTHORITY_ENFORCEMENT_MODES.ENFORCE_DEFAULT
    || (m === AUTHORITY_ENFORCEMENT_MODES.ENFORCE_CRITICAL && isCritical);

  if (willBlock) {
    return {
      mode: m, verdict, block: true, admissibility: 'not_admissible', code, warn: false,
      reason: UNRESOLVED.has(verdict) ? 'authority_unresolved' : verdict,
    };
  }

  const warn = m === AUTHORITY_ENFORCEMENT_MODES.WARN
    || (m === AUTHORITY_ENFORCEMENT_MODES.ENFORCE_CRITICAL && !isCritical);
  return {
    mode: m, verdict, block: false, admissibility: 'observed', code, warn,
    reason: warn ? `warn:${verdict}` : `would_block:${verdict}`,
  };
}

const enforcementApi = {
  AUTHORITY_ENFORCEMENT_MODES,
  isAuthorityEnforcementMode,
  authorityAdmissibilityCode,
  applyAuthorityEnforcement,
};
export default enforcementApi;
