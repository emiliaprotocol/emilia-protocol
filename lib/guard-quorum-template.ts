// SPDX-License-Identifier: Apache-2.0
// EP-QUORUM-v1 — organization-pinned quorum policy templates.
//
// THE GAP THIS CLOSES. packages/verify/quorum.js proves a quorum document is
// internally consistent (threshold met, distinct humans, roster admitted,
// window, signatures) against WHATEVER policy it is handed. That policy, today,
// is chosen by the receipt CREATOR at issuance (route.js:
// `quorum_policy: body.quorum_policy`). Nothing binds it to organization intent.
// So a creator can declare `required: 1` (or a hand-picked roster) for their own
// receipt where the org's rule is 2-of-3. Separation-of-duties still holds and
// no enrolled key can be forged — this is NOT a signature bypass — but the
// "two-person rule" guarantee is only as strong as a per-receipt, creator-set
// field. That is a policy-AUTHENTICITY / assurance-DOWNGRADE gap.
//
// THE CONTROL. Source the *expected* quorum policy out-of-band from an
// org-pinned template keyed by (organization_id, action_type), exactly as the
// federation module sources its trust anchor out-of-band (verified ≠ accepted).
// A submitted/stored quorum_policy is only honored when it MEETS OR EXCEEDS the
// org template: threshold >= floor, window <= ceiling, distinct_humans not
// disabled, and every declared approver inside the allowed roster. A creator can
// make a quorum STRONGER than the org floor, never weaker.
//
// FAIL-CLOSED, with one deliberate availability carve-out. A real policy-store
// fault on the quorum path fails closed (refuse the high-stakes action rather
// than accept an unverified quorum). The ONE exception is a MISSING TABLE
// (migration not yet applied in this environment): that is treated as "no
// template configured" and logged, so an un-migrated deployment behaves exactly
// as it did before this control existed instead of bricking all creation. The
// meet-or-exceed enforcement is fully active the moment the table + a row exist.

import { logger } from './logger.js';

/** Postgres SQLSTATE for "relation does not exist". */
const UNDEFINED_TABLE = '42P01';

/** JSON array encoding keeps the composite key textual and unambiguous. */
function slotKey(role, approver) {
  return JSON.stringify([role ?? '', approver ?? '']);
}

/**
 * The effective quorum parameters a submitted policy resolves to — computed the
 * SAME way packages/verify/quorum.js computes them, so template comparison and
 * runtime verification agree on what the policy means. Ordered mode requires
 * every listed approver, so its effective threshold is the roster size.
 *
 * @param {object} policy  an EP-QUORUM-v1 `policy` object
 * @returns {{ mode:string, required:number, windowSec:number, distinctHumans:boolean,
 *             approvers:Array<{role,approver}> }}
 */
export function effectiveQuorumParams(policy) {
  const mode = policy?.mode === 'ordered' ? 'ordered' : 'threshold';
  const approvers = Array.isArray(policy?.approvers) ? policy.approvers : [];
  const distinctHumans = policy?.distinct_humans !== false; // default true
  const windowSec = Number.isFinite(policy?.window_sec) ? policy.window_sec : 900;
  const required = mode === 'ordered'
    ? approvers.length
    : (Number.isInteger(policy?.required) && policy.required > 0 ? policy.required : NaN);
  return { mode, required, windowSec, distinctHumans, approvers };
}

/**
 * Normalize a raw org_quorum_policies row into a template object with defaults.
 * Returns null for a null/absent row.
 */
export function normalizeQuorumTemplate(row) {
  if (!row || typeof row !== 'object') return null;
  const allowed = Array.isArray(row.allowed_approvers) ? row.allowed_approvers : null;
  const modes = Array.isArray(row.allowed_modes) && row.allowed_modes.length > 0
    ? row.allowed_modes
    : null;
  return {
    organization_id: row.organization_id ?? null,
    action_type: row.action_type ?? null,
    // Minimum threshold M the org requires (null = no floor).
    min_required: Number.isInteger(row.min_required) ? row.min_required : null,
    // Ceiling on the approval window in seconds (null = no ceiling).
    max_window_sec: Number.isInteger(row.max_window_sec) ? row.max_window_sec : null,
    // Distinct-humans floor. Defaults TRUE (separation of duties is the norm);
    // only an explicit `false` in the row relaxes it.
    require_distinct_humans: row.require_distinct_humans !== false,
    // When true, a receipt for this action_type MUST carry a quorum_policy.
    quorum_required: row.quorum_required === true,
    // Allowed roster: submitted approvers must be a subset. null/empty = unrestricted.
    allowed_approvers: allowed && allowed.length > 0 ? allowed : null,
    // Optional allowed modes (e.g. ['ordered']); null = any mode.
    allowed_modes: modes,
  };
}

/**
 * Is a submitted/stored quorum policy AT LEAST as strong as the org template?
 * Pure — no I/O. The decisive control: a creator may exceed the org floor, never
 * fall below it.
 *
 * @param {object} policy    the EP-QUORUM-v1 `policy` being validated
 * @param {object} template  a normalized template (see normalizeQuorumTemplate)
 * @returns {{ ok: boolean, violations: string[] }}
 */
export function evaluateQuorumAgainstTemplate(policy, template) {
  const violations: string[] = [];
  if (!template) {
    // No org intent expressed → nothing to enforce here. (Whether a template is
    // REQUIRED is a separate, caller-side decision — see resolve + route logic.)
    return { ok: true, violations };
  }
  if (!policy || typeof policy !== 'object') {
    return { ok: false, violations: ['invalid_quorum_policy'] };
  }

  const { mode, required, windowSec, distinctHumans, approvers } = effectiveQuorumParams(policy);

  // 1. Threshold floor. A non-integer / non-positive effective threshold is
  //    itself a violation when the org set a floor (fail closed).
  if (template.min_required != null) {
    if (!Number.isInteger(required) || required < template.min_required) {
      violations.push('threshold_below_min');
    }
  }

  // 2. Window ceiling. A longer window widens the collusion/coercion horizon.
  if (template.max_window_sec != null && windowSec > template.max_window_sec) {
    violations.push('window_exceeds_max');
  }

  // 3. Distinct-humans floor (separation of duties). The org floor cannot be
  //    disabled by a per-receipt policy.
  if (template.require_distinct_humans && distinctHumans === false) {
    violations.push('distinct_humans_disabled');
  }

  // 4. Roster subset. Every declared approver slot must be one the org allows —
  //    blocks a hand-picked colluding roster that would still pass verifyQuorum.
  if (template.allowed_approvers) {
    const allowedSet = new Set(template.allowed_approvers.map((e) => slotKey(e?.role, e?.approver)));
    const outOfRoster = approvers.some((a) => !allowedSet.has(slotKey(a?.role, a?.approver)));
    if (outOfRoster) violations.push('approver_out_of_roster');
  }

  // 5. Mode allowlist (optional). e.g. an org may require ordered co-sign.
  if (template.allowed_modes && !template.allowed_modes.includes(mode)) {
    violations.push('mode_not_allowed');
  }

  return { ok: violations.length === 0, violations };
}

/**
 * Resolve the org-pinned quorum template for (organization_id, action_type).
 *
 * Distinguishes three outcomes so callers can fail closed correctly WITHOUT
 * bricking un-migrated deployments:
 *   - { template } present  → enforce meet-or-exceed / quorum_required.
 *   - { template: null }     → no row configured for this action (or table not
 *                              yet migrated: tableMissing=true, logged).
 *   - { error }              → a real store fault; the quorum path must fail
 *                              closed on it.
 *
 * @param {object} supabase  a query client (getGuardedClient()/getServiceClient())
 * @param {{ organizationId?: string, actionType?: string }} [ctx] - both required at
 *   runtime; missing either short-circuits to `{ template: null }` below
 * @returns {Promise<{ template?: object|null, error?: string, tableMissing?: boolean }>}
 */
export async function resolveOrgQuorumTemplate(supabase, { organizationId, actionType }: { organizationId?: string; actionType?: string } = {}) {
  if (!organizationId || !actionType) {
    // Missing subject can't be matched to org intent — caller decides. Treat as
    // "no template" so it doesn't hard-fail unrelated creation.
    return { template: null };
  }
  try {
    const { data, error } = await supabase
      .from('org_quorum_policies')
      .select('organization_id, action_type, min_required, max_window_sec, require_distinct_humans, quorum_required, allowed_approvers, allowed_modes')
      .eq('organization_id', organizationId)
      .eq('action_type', actionType)
      .limit(1);
    if (error) {
      if (error.code === UNDEFINED_TABLE) {
        // Migration 124 not applied in this environment. Behave as pre-control:
        // no template, but make the gap visible in logs.
        logger.warn('[guard] org_quorum_policies table missing — quorum template enforcement inactive until migration 124 is applied');
        return { template: null, tableMissing: true };
      }
      logger.error('[guard] org quorum template lookup failed:', error?.message);
      return { error: error.message || 'quorum_template_lookup_failed' };
    }
    return { template: normalizeQuorumTemplate((data || [])[0] || null) };
  } catch (e) {
    logger.error('[guard] org quorum template lookup threw:', e?.message);
    return { error: e?.message || 'quorum_template_lookup_failed' };
  }
}
