// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — usage metering (the value metric, EP-GATE-USAGE-v1).
 *
 * Pricing scales with what the gate actually protects: PROTECTED IRREVERSIBLE
 * ACTIONS (guarded decisions — allows AND denies both consume enforcement) plus
 * RECEIPT-YEARS under retention (one receipt kept one year = one receipt-year;
 * horizons follow retention.js, default 6y = 2190 days). NEVER seats.
 *
 * Pure functions over evidence-log entries (`evidence.all()`); no clock, no
 * network. The billing period is an explicit [periodStart, periodEnd) window —
 * INCLUSIVE start, EXCLUSIVE end — so adjacent periods never double-count an
 * entry sitting exactly on a boundary.
 *
 * Fail-closed posture for billing: an unbounded or reversed period is refused
 * (thrown); malformed entries are surfaced in `integrity_warnings` rather than
 * silently dropped; an entry whose allow flag is not literally `true` is
 * counted as a deny; a statement over foreign or malformed usage is refused.
 * `buildUsageStatement` output is deterministic (sorted keys + content hash)
 * and UNSIGNED — the deployer signs it; the content hash binds that signature
 * to exactly these numbers for billing reconciliation.
 */
import crypto from 'node:crypto';

export const USAGE_VERSION = 'EP-GATE-USAGE-v1';

const DAYS_PER_YEAR = 365;
// Mirrors retention.js's cold-horizon default (coldDays = 2190 = 6y): a receipt
// is presumed retained for the full audit horizon unless the entry states its own.
const DEFAULT_RETENTION_YEARS = 2190 / DAYS_PER_YEAR;

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/** Canonical JSON (recursive sorted keys) — matches evidence.js / @emilia-protocol/verify. */
function canonical(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

function toMs(t) {
  if (t == null) return null;
  const ms = typeof t === 'number' ? t : Date.parse(t);
  return Number.isFinite(ms) ? ms : null;
}

/** Key-sorted copy so output is byte-stable regardless of entry order. */
function sortedCounts(map) {
  const out = {};
  for (const k of Object.keys(map).sort()) out[k] = map[k];
  return out;
}

/** Entry-level day resolution (1/365y ≈ 0.00274) without float noise. */
function round6(x) {
  return Math.round(x * 1e6) / 1e6;
}

/**
 * The retention this entry STATES for itself, in years.
 * @returns {number|null|NaN} years, `null` when unstated (default applies),
 *   `NaN` when stated but invalid (default applies + integrity warning — a
 *   malformed stated value must never silently shrink the metered total).
 */
function statedRetentionYears(e) {
  if (e.retention_years != null) {
    const y = Number(e.retention_years);
    return Number.isFinite(y) && y >= 0 ? y : NaN;
  }
  if (e.retention_days != null) {
    const d = Number(e.retention_days);
    return Number.isFinite(d) && d >= 0 ? d / DAYS_PER_YEAR : NaN;
  }
  return null;
}

/**
 * Meter a billing period over evidence entries.
 *
 * Billable = `kind: 'decision'` entries on GUARDED actions (`not_guarded`
 * pass-throughs are free; execution records are provenance, not enforcement).
 * Window is [periodStart, periodEnd): inclusive start, exclusive end.
 *
 * @param {Array<object>} entries  evidence.all()
 * @param {object} [o]
 * @param {string|number} [o.periodStart]  ISO or ms — required
 * @param {string|number} [o.periodEnd]    ISO or ms — required, >= periodStart
 * @param {number} [o.retentionYearsDefault=6]  applied when an entry states no retention
 * @returns {{'@version':string, protected_actions:number, allows:number, denies:number,
 *   replays_blocked:number, by_action_type:object, by_tier:object,
 *   receipt_years:number, retention_years_default:number, period:object, integrity_warnings:object[]}}
 */
export function meterUsage(entries: any[] = [], {
  periodStart,
  periodEnd,
  retentionYearsDefault = DEFAULT_RETENTION_YEARS,
}: {
  periodStart?: string | number;
  periodEnd?: string | number;
  retentionYearsDefault?: number;
} = {}) {
  const startMs = toMs(periodStart);
  const endMs = toMs(periodEnd);
  // An unbounded or reversed period is not meterable — refuse rather than emit
  // a statement whose window cannot be reconciled.
  if (startMs == null || endMs == null) {
    throw new Error('meterUsage: periodStart and periodEnd are required (ISO string or ms)');
  }
  if (endMs < startMs) throw new Error('meterUsage: periodEnd must be >= periodStart');
  if (!Number.isFinite(retentionYearsDefault) || retentionYearsDefault < 0) {
    throw new Error('meterUsage: retentionYearsDefault must be a finite number >= 0');
  }

  const warnings: { index: number; reason: string }[] = [];
  const byAction = Object.create(null);
  const byTier = Object.create(null);
  let protectedActions = 0;
  let allows = 0;
  let denies = 0;
  let replaysBlocked = 0;
  let receiptYears = 0;

  entries.forEach((e, index) => {
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      warnings.push({ index, reason: 'not_an_object' });
      return;
    }
    const t = toMs(e.at);
    if (t == null) {
      // Unplaceable in ANY period — surfaced, never silently dropped.
      warnings.push({ index, reason: 'unparseable_at' });
      return;
    }
    if (t < startMs || t >= endMs) return; // outside [start, end)
    if (typeof e.kind !== 'string' || e.kind.length === 0) {
      warnings.push({ index, reason: 'missing_kind' });
      return;
    }
    if (e.kind !== 'decision') return; // execution/other records are not billable
    if (e.reason === 'not_guarded') return; // pass-throughs are free by design

    protectedActions += 1;
    // Fail closed: only a literal `true` counts as an allow.
    if (e.allow === true) allows += 1; else denies += 1;
    if (e.reason === 'replay_refused') replaysBlocked += 1;

    const action = typeof e.action === 'string' && e.action ? e.action : 'unknown';
    byAction[action] = (byAction[action] || 0) + 1;
    const tier = typeof e.required_tier === 'string' && e.required_tier ? e.required_tier : 'unknown';
    byTier[tier] = (byTier[tier] || 0) + 1;

    const stated = statedRetentionYears(e);
    if (Number.isNaN(stated)) {
      warnings.push({ index, reason: 'invalid_stated_retention' });
      receiptYears += retentionYearsDefault;
    } else {
      receiptYears += stated ?? retentionYearsDefault;
    }
  });

  return {
    '@version': USAGE_VERSION,
    period: {
      start: new Date(startMs).toISOString(),
      end: new Date(endMs).toISOString(),
      bounds: 'inclusive_start_exclusive_end',
    },
    protected_actions: protectedActions,
    allows,
    denies,
    replays_blocked: replaysBlocked,
    by_action_type: sortedCounts(byAction),
    by_tier: sortedCounts(byTier),
    receipt_years: round6(receiptYears),
    retention_years_default: retentionYearsDefault,
    integrity_warnings: warnings,
  };
}

/**
 * Build the signed-ready usage statement handed to billing reconciliation.
 * UNSIGNED — the deployer signs it; `content_hash` (sha256 over the canonical
 * JSON of everything else) binds that signature to exactly these numbers.
 * Deterministic: same usage + org → byte-identical statement, regardless of
 * the entry order the usage was metered from.
 * @param {object} usage  a USAGE_VERSION object from meterUsage
 * @param {{ org?: string }} [o]
 */
export function buildUsageStatement(usage, { org }: { org?: string } = {}) {
  // Never emit a statement over an artifact of a different or unknown format,
  // and never one that fails to name who it bills.
  if (!usage || usage['@version'] !== USAGE_VERSION) {
    throw new Error(`buildUsageStatement: usage must be a ${USAGE_VERSION} object from meterUsage`);
  }
  if (!org || typeof org !== 'string') {
    throw new Error('buildUsageStatement: org is required — a statement must name the billed party');
  }
  if (!usage.period || !usage.period.start || !usage.period.end) {
    throw new Error('buildUsageStatement: usage.period is missing');
  }
  for (const k of ['protected_actions', 'allows', 'denies', 'replays_blocked', 'receipt_years']) {
    if (!Number.isFinite(usage[k]) || usage[k] < 0) {
      throw new Error(`buildUsageStatement: usage.${k} must be a finite number >= 0`);
    }
  }
  const warningCount = Array.isArray(usage.integrity_warnings) ? usage.integrity_warnings.length : 0;
  const body = {
    '@version': USAGE_VERSION,
    kind: 'usage_statement',
    org,
    period: {
      start: usage.period.start,
      end: usage.period.end,
      bounds: 'inclusive_start_exclusive_end',
    },
    protected_actions: usage.protected_actions,
    allows: usage.allows,
    denies: usage.denies,
    replays_blocked: usage.replays_blocked,
    by_action_type: sortedCounts(usage.by_action_type || {}),
    by_tier: sortedCounts(usage.by_tier || {}),
    receipt_years: usage.receipt_years,
    retention_years_default: usage.retention_years_default ?? DEFAULT_RETENTION_YEARS,
    // Data-quality signal for the reconciler: a statement metered over a log
    // with integrity warnings is flagged incomplete, never silently clean.
    integrity_warning_count: warningCount,
    complete: warningCount === 0,
  };
  return { ...body, content_hash: sha256hex(canonical(body)) };
}

export default { meterUsage, buildUsageStatement, USAGE_VERSION };
