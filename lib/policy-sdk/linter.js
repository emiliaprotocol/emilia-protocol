/**
 * EP Policy Linter
 *
 * Catches common authoring mistakes in handshake policies BEFORE they reach
 * production. The handshake-layer validator (lib/handshake/policy.js) checks
 * structural conformance. This linter checks semantic smells: policies that
 * pass schema validation but are dangerously weak, unreachable, inconsistent,
 * or contradictory.
 *
 * Every finding has a severity:
 *   - 'error':   policy must not ship (structural or clear security gap)
 *   - 'warning': policy likely wrong (ship-blocking for high-risk actions)
 *   - 'info':    authoring smell (hygiene, not a defect)
 *
 * The linter is pure: no I/O, no DB. Call with a policy rules object; get a
 * report. Integrate into CI gates, pre-commit hooks, and the policy editor.
 *
 * @license Apache-2.0
 */

import { validatePolicyRules } from '@/lib/handshake/policy.js';

const ASSURANCE_RANK = { low: 1, medium: 2, substantial: 3, high: 4 };

// Severity levels, ranked so filterBySeverity can compare.
const SEVERITY_RANK = { info: 1, warning: 2, error: 3 };

/**
 * Lint a policy rules object.
 *
 * @param {object} rules - The policy.rules object (not the whole policy row).
 * @param {object} [options]
 * @param {string} [options.action_class] - Action risk class: 'low' | 'medium' | 'high' | 'critical'.
 *   Higher classes raise the assurance floor and tighten expiry/nonce checks.
 *   Default 'high' — most EP policies gate high-risk actions.
 * @returns {{ findings: Array<{ rule: string, severity: string, path: string, message: string, suggestion?: string }>, ok: boolean }}
 */
export function lintPolicy(rules, options = {}) {
  const action_class = options.action_class || 'high';
  const findings = [];

  // Step 1: structural validation. If it fails, surface as errors and stop —
  // semantic lints on a malformed policy produce noise.
  const structural = validatePolicyRules(rules);
  if (!structural.valid) {
    for (const msg of structural.errors) {
      findings.push({ rule: 'EP-STRUCT', severity: 'error', path: '$', message: msg });
    }
    return { findings, ok: false };
  }

  // Step 2: semantic lints.
  lintAssuranceFloor(rules, action_class, findings);
  lintBindingStrength(rules, action_class, findings);
  lintRequiredParties(rules, findings);
  lintStorageConsistency(rules, findings);
  lintExpiryBounds(rules, action_class, findings);
  lintDuplicateClaims(rules, findings);
  lintUnreachableRoles(rules, findings);
  lintSignoffConsistency(rules, action_class, findings);

  const hasError = findings.some(f => f.severity === 'error');
  return { findings, ok: !hasError };
}

/**
 * Filter a report to findings at or above a given severity.
 *
 * @param {{ findings: Array }} report
 * @param {'info'|'warning'|'error'} minSeverity
 */
export function filterBySeverity(report, minSeverity) {
  const min = SEVERITY_RANK[minSeverity];
  if (min === undefined) throw new Error(`Unknown severity: ${minSeverity}`);
  return {
    ...report,
    findings: report.findings.filter(f => SEVERITY_RANK[f.severity] >= min),
  };
}

// ── Individual lint rules ──────────────────────────────────────────────────

/**
 * EP-L001: required assurance floor for the action class.
 *
 * A 'critical' action accepting 'low' assurance is almost always a mistake;
 * a 'high' action accepting 'medium' raises a warning. This prevents the
 * classic copy-paste defect where a stub policy is left on a critical path.
 */
function lintAssuranceFloor(rules, action_class, findings) {
  const floors = { low: 1, medium: 2, high: 3, critical: 4 };
  const floor = floors[action_class] ?? 3;
  if (!rules.required_parties) return;

  for (const [role, def] of Object.entries(rules.required_parties)) {
    const rank = ASSURANCE_RANK[def.minimum_assurance];
    if (rank === undefined) continue; // caught by structural validator
    if (rank < floor) {
      findings.push({
        rule: 'EP-L001',
        severity: rank < floor - 1 ? 'error' : 'warning',
        path: `$.required_parties.${role}.minimum_assurance`,
        message: `Assurance "${def.minimum_assurance}" is below the floor for action_class "${action_class}".`,
        suggestion: `Raise to "${Object.entries(ASSURANCE_RANK).find(([, v]) => v === floor)?.[0]}" or reclassify the action.`,
      });
    }
  }
}

/**
 * EP-L002: binding must require nonce AND payload_hash for non-trivial actions.
 *
 * Without nonce_required = true, two concurrent bindings cannot be distinguished
 * at the hash level and replay attacks are possible. Without payload_hash_required,
 * the exact action content is not bound — classic bait-and-switch.
 */
function lintBindingStrength(rules, action_class, findings) {
  if (!rules.binding) return;
  if (rules.binding.nonce_required !== true) {
    findings.push({
      rule: 'EP-L002',
      severity: action_class === 'low' ? 'warning' : 'error',
      path: '$.binding.nonce_required',
      message: 'nonce_required must be true — without a nonce, replay resistance is not enforced.',
      suggestion: 'Set binding.nonce_required = true. Required for all EP conformance tiers ≥ basic.',
    });
  }
  if (rules.binding.payload_hash_required !== true && action_class !== 'low') {
    findings.push({
      rule: 'EP-L002',
      severity: 'warning',
      path: '$.binding.payload_hash_required',
      message: 'payload_hash_required is false — the exact action content is not bound into the handshake.',
      suggestion: 'Set binding.payload_hash_required = true for any action_class above "low".',
    });
  }
}

/**
 * EP-L003: required_parties must be non-empty.
 *
 * A policy with zero required parties is a no-op — every request passes the
 * party check vacuously. Almost always an authoring error.
 */
function lintRequiredParties(rules, findings) {
  if (!rules.required_parties || typeof rules.required_parties !== 'object') return;
  const roles = Object.keys(rules.required_parties);
  if (roles.length === 0) {
    findings.push({
      rule: 'EP-L003',
      severity: 'error',
      path: '$.required_parties',
      message: 'required_parties is empty — policy vacuously accepts any party configuration.',
      suggestion: 'Declare at least one required role (e.g., initiator, responder).',
    });
  }
  // Spot-check for the classic "only initiator required" on a critical path.
  if (roles.length === 1 && roles[0] === 'initiator') {
    findings.push({
      rule: 'EP-L003',
      severity: 'info',
      path: '$.required_parties',
      message: 'Only the initiator is required — no counter-party or verifier is involved.',
      suggestion: 'Confirm this is intentional. Single-party handshakes are unusual for high-risk flows.',
    });
  }
}

/**
 * EP-L004: storage flags must be consistent with binding requirements.
 *
 * If payload_hash_required = true but store_raw_payload = false, audit replay
 * will be impossible. Warn the author to choose explicitly.
 */
function lintStorageConsistency(rules, findings) {
  if (!rules.binding || !rules.storage) return;
  if (rules.binding.payload_hash_required === true && rules.storage.store_raw_payload === false) {
    findings.push({
      rule: 'EP-L004',
      severity: 'info',
      path: '$.storage.store_raw_payload',
      message: 'Payload hash is required but raw payload is not stored — audit replay will require re-fetching the payload externally.',
      suggestion: 'If you need to reconstruct the binding later (e.g., for dispute resolution), set storage.store_raw_payload = true.',
    });
  }
}

/**
 * EP-L005: expiry must be within a safe operational window.
 *
 * Too short → legitimate users fail. Too long → replay window widens.
 * Defaults: high-risk = 5–60 min; critical = 1–15 min.
 */
function lintExpiryBounds(rules, action_class, findings) {
  if (!rules.binding) return;
  const mins = rules.binding.expiry_minutes;
  if (typeof mins !== 'number') return;

  const bounds = {
    low:      { min: 1,  max: 1440 },
    medium:   { min: 1,  max: 240 },
    high:     { min: 1,  max: 60 },
    critical: { min: 1,  max: 15 },
  };
  const b = bounds[action_class] || bounds.high;
  if (mins < b.min) {
    findings.push({
      rule: 'EP-L005',
      severity: 'warning',
      path: '$.binding.expiry_minutes',
      message: `Expiry ${mins}m is shorter than the minimum recommended (${b.min}m) — legitimate users may fail before completing the ceremony.`,
      suggestion: `Consider at least ${b.min}m for action_class "${action_class}".`,
    });
  }
  if (mins > b.max) {
    findings.push({
      rule: 'EP-L005',
      severity: action_class === 'critical' ? 'error' : 'warning',
      path: '$.binding.expiry_minutes',
      message: `Expiry ${mins}m is longer than the maximum recommended (${b.max}m) for action_class "${action_class}" — widens the replay window.`,
      suggestion: `Tighten to ≤ ${b.max}m or reclassify the action.`,
    });
  }
}

/**
 * EP-L006: duplicate required_claims within a role.
 */
function lintDuplicateClaims(rules, findings) {
  if (!rules.required_parties) return;
  for (const [role, def] of Object.entries(rules.required_parties)) {
    if (!Array.isArray(def.required_claims)) continue;
    const seen = new Set();
    const dups = [];
    for (const c of def.required_claims) {
      if (seen.has(c)) dups.push(c);
      seen.add(c);
    }
    if (dups.length) {
      findings.push({
        rule: 'EP-L006',
        severity: 'info',
        path: `$.required_parties.${role}.required_claims`,
        message: `Duplicate claims in role "${role}": ${[...new Set(dups)].join(', ')}.`,
        suggestion: 'Remove duplicates for clarity. Duplicates are tolerated at runtime but signal authoring drift.',
      });
    }
  }
}

/**
 * EP-L007: role names must match EP's canonical role set.
 *
 * Reaches flag unknown roles — these will never bind because handshake_parties
 * only accepts initiator/responder/verifier/delegate.
 */
function lintUnreachableRoles(rules, findings) {
  if (!rules.required_parties) return;
  const CANONICAL = new Set(['initiator', 'responder', 'verifier', 'delegate']);
  for (const role of Object.keys(rules.required_parties)) {
    if (!CANONICAL.has(role)) {
      findings.push({
        rule: 'EP-L007',
        severity: 'error',
        path: `$.required_parties.${role}`,
        message: `Role "${role}" is not in the canonical role set (${[...CANONICAL].join(', ')}). Handshake presentations will never match.`,
        suggestion: 'Use a canonical role or extend VALID_PARTY_ROLES in invariants.js (requires protocol version bump).',
      });
    }
  }
}

/**
 * EP-L008: accountable signoff policy consistency.
 *
 * If the policy opts into signoff (rules.signoff.required = true), ensure
 * the party and binding settings are consistent — signoff requires a specific
 * human identity bound, which means medium+ assurance.
 */
function lintSignoffConsistency(rules, action_class, findings) {
  if (!rules.signoff || rules.signoff.required !== true) return;
  if (!rules.required_parties) return;

  // Signoff requires at least one party with assurance >= substantial.
  const haveHighAssurance = Object.values(rules.required_parties).some(
    def => ASSURANCE_RANK[def.minimum_assurance] >= ASSURANCE_RANK.substantial,
  );
  if (!haveHighAssurance) {
    findings.push({
      rule: 'EP-L008',
      severity: 'error',
      path: '$.signoff.required',
      message: 'Accountable signoff is required but no party has minimum_assurance >= "substantial". Signoff cannot legally attribute ownership without substantial-grade authentication.',
      suggestion: 'Raise minimum_assurance for the signing role to "substantial" or "high".',
    });
  }

  // If signoff is required for a critical action, it must also require re-auth.
  if (action_class === 'critical' && rules.signoff.re_auth_required !== true) {
    findings.push({
      rule: 'EP-L008',
      severity: 'warning',
      path: '$.signoff.re_auth_required',
      message: 'Critical action with signoff should require fresh re-authentication at the signoff step (defense against session takeover).',
      suggestion: 'Set signoff.re_auth_required = true.',
    });
  }
}

/**
 * Format a lint report as a human-readable string.
 *
 * @param {{ findings: Array, ok: boolean }} report
 * @returns {string}
 */
export function formatReport(report) {
  if (report.findings.length === 0) {
    return 'Policy lint: OK (0 findings).';
  }
  const lines = [`Policy lint: ${report.ok ? 'OK' : 'FAIL'} (${report.findings.length} finding${report.findings.length > 1 ? 's' : ''}).`];
  for (const f of report.findings) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.rule} at ${f.path}: ${f.message}`);
    if (f.suggestion) lines.push(`    → ${f.suggestion}`);
  }
  return lines.join('\n');
}
