// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — evidence retention policy (production audit custody).
 *
 * The evidence log is the compliance/insurance artifact. Production custody adds
 * a retention POLICY over it: classify each decision/execution record as HOT
 * (recent, fast access), COLD (older, archival), or EXPIRED (past the retention
 * horizon, eligible for deletion) — and honor a LEGAL HOLD that pins records so
 * they are never expired. `EP_AUDIT_HOT_DAYS` / `EP_AUDIT_COLD_DAYS` set the
 * horizons; legal hold is a set of evidence hashes.
 *
 * Pure functions over the evidence entries (each has `.at` ISO and `.hash`); the
 * gate never deletes anything itself — it tells the operator what is eligible.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

type EvidenceEntry = { at: string; hash?: string; kind?: string };
type TaggedEntry = { hash: string | null; at: string | null; kind: string | null };
type RetentionOptions = {
  hotDays?: number;
  coldDays?: number;
  now?: number;
  legalHold?: Set<string> | string[];
};

function ageDays(atISO, nowMs) {
  const t = Date.parse(atISO);
  if (!Number.isFinite(t)) return null;
  return (nowMs - t) / DAY_MS;
}

/**
 * Classify evidence entries into retention buckets.
 * @param {Array<{at:string, hash?:string, kind?:string}>} entries  evidence.all()
 * @param {object} o
 * @param {number} [o.hotDays=365]
 * @param {number} [o.coldDays=2190]   (6y)
 * @param {number} [o.now=Date.now()]
 * @param {Set<string>|string[]} [o.legalHold]  hashes pinned indefinitely
 * @returns {{hot:object[], cold:object[], expired:object[], legal_hold:object[], unknown:object[], summary:object}}
 */
export function classifyRetention(entries: EvidenceEntry[] = [], {
  hotDays = 365, coldDays = 2190, now = Date.now(), legalHold,
}: RetentionOptions = {}) {
  const held = legalHold instanceof Set ? legalHold : new Set(legalHold || []);
  const buckets: {
    hot: TaggedEntry[];
    cold: TaggedEntry[];
    expired: TaggedEntry[];
    legal_hold: TaggedEntry[];
    unknown: TaggedEntry[];
  } = { hot: [], cold: [], expired: [], legal_hold: [], unknown: [] };
  for (const e of entries) {
    const tagged = { hash: e.hash ?? null, at: e.at ?? null, kind: e.kind ?? null };
    if (e.hash && held.has(e.hash)) { buckets.legal_hold.push(tagged); continue; }
    const age = ageDays(e.at, now);
    if (age == null) { buckets.unknown.push(tagged); continue; }
    if (age <= hotDays) buckets.hot.push(tagged);
    else if (age <= coldDays) buckets.cold.push(tagged);
    else buckets.expired.push(tagged);
  }
  return {
    ...buckets,
    summary: {
      total: entries.length,
      hot: buckets.hot.length,
      cold: buckets.cold.length,
      expired: buckets.expired.length,
      legal_hold: buckets.legal_hold.length,
      unknown: buckets.unknown.length,
      hot_days: hotDays,
      cold_days: coldDays,
    },
  };
}

/**
 * Build an export manifest (the artifact handed to an auditor / SIEM). Includes
 * the evidence head so the export is verifiably tied to a chain state.
 */
export function buildRetentionExport(entries: EvidenceEntry[] = [], opts: RetentionOptions = {}) {
  const cls = classifyRetention(entries, opts);
  const last = entries[entries.length - 1] || null;
  return {
    '@version': 'EP-GATE-RETENTION-EXPORT-v1',
    generated_at: new Date(opts.now || Date.now()).toISOString(),
    hot_days: cls.summary.hot_days,
    cold_days: cls.summary.cold_days,
    evidence_head: last?.hash ?? null,
    counts: {
      total: cls.summary.total, hot: cls.summary.hot, cold: cls.summary.cold,
      expired: cls.summary.expired, legal_hold: cls.summary.legal_hold, unknown: cls.summary.unknown,
    },
    entries: entries.map((e) => ({ hash: e.hash ?? null, at: e.at ?? null, kind: e.kind ?? null })),
  };
}

export const RETENTION_EXPORT_VERSION = 'EP-GATE-RETENTION-EXPORT-v1';
export default { classifyRetention, buildRetentionExport, RETENTION_EXPORT_VERSION };
