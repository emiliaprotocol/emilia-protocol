// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — SIEM export of the evidence log (EP-GATE-SIEM-EXPORT-v1).
 *
 * Gate decisions must land where the SOC already looks: Splunk, Sentinel,
 * Datadog. Two static, offline mappings over evidence-log entries:
 *   - OCSF (JSON object) for OCSF-native pipelines (Amazon Security Lake,
 *     Splunk CIM-OCSF, Sentinel ASIM ingestion);
 *   - CEF (single line) as the lowest-common-denominator syslog fallback.
 * Pure functions: entry in, event out — no network, no wall clock. Every
 * timestamp in the output comes from the entry itself, so a fixed entry maps
 * to a byte-identical event on every call and every host.
 *
 * OCSF class choice — class_uid 6003 (API Activity, category 6 Application
 * Activity). The gate is a policy-enforcement point in front of a tool/API
 * call: each evidence entry is one attempted API operation with an
 * allow/deny (or executed/failed) disposition, which is exactly what 6003
 * models via status_id. The IAM alternatives fit worse: 3003 Authorize
 * Session models session-privilege grants (no deny activity), and 6004 Web
 * Resource Access Activity is deprecated in current OCSF.
 *
 * Mapping table (evidence entry → OCSF 6003):
 *   entry.at (ISO)          → time (epoch ms; 0 sentinel if unparseable)
 *   entry.kind              → activity_name ('decision'|'execution'), activity_id 99 (Other)
 *   entry.action            → api.operation
 *   entry.allow / outcome   → status_id 1 Success / 2 Failure (+ status)
 *   entry.reason / outcome  → status_detail
 *   entry.subject           → actor.user.uid
 *   entry.receipt_id        → metadata.correlation_uid
 *   entry.hash              → metadata.uid (ties the event to the evidence chain)
 *   allow                   → severity_id 1 Informational; refuse/fail → 3 Medium
 *   required_tier, selector, seq, prev_hash → unmapped.* (no OCSF slot)
 *
 * A malformed entry NEVER throws out of the mappers: it becomes a structured
 * error event (status Failure, status_detail 'malformed_evidence_entry') so
 * the corruption itself is visible in the SIEM instead of silently dropped.
 */

export const SIEM_EXPORT_VERSION = 'EP-GATE-SIEM-EXPORT-v1';
export const SIEM_OCSF_CLASS_UID = 6003; // API Activity
const OCSF_SCHEMA_VERSION = '1.1.0';
const CATEGORY_UID = 6; // Application Activity
const PRODUCT = { name: 'EMILIA Gate', vendor_name: 'Emilia Protocol' };
const PREVIEW_MAX = 256;

/**
 * Shape-check an evidence entry and derive the disposition. An entry is
 * mappable only if it carries a parseable timestamp AND a verdict (a decision's
 * `allow` boolean or an execution's `outcome` string) — anything else is
 * treated as malformed and surfaced as an error event, never a throw.
 */
function classifyEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return { valid: false };
  const timeMs = typeof entry.at === 'string' ? Date.parse(entry.at) : NaN;
  const hasVerdict = typeof entry.allow === 'boolean' || typeof entry.outcome === 'string';
  if (!Number.isFinite(timeMs) || !hasVerdict) return { valid: false };
  const kind = entry.kind === 'execution' ? 'execution' : 'decision';
  const success = typeof entry.allow === 'boolean' ? entry.allow === true : entry.outcome === 'executed';
  return { valid: true, kind, success, timeMs };
}

/** Bounded, throw-proof rendering of an unmappable entry for the error event. */
function safePreview(entry) {
  let s;
  try {
    s = typeof entry === 'string' ? entry : JSON.stringify(entry);
  } catch {
    s = '[unserializable]';
  }
  if (s == null) s = String(entry);
  return s.replace(/[\r\n]+/g, ' ').slice(0, PREVIEW_MAX);
}

/**
 * Map an evidence-log entry to an OCSF API Activity (6003) event object.
 * Static and deterministic: same entry, same object, always. Malformed input
 * yields a structured error event rather than throwing (see module doc).
 * @param {object} entry  one record from evidence.all()
 * @returns {object} OCSF-shaped event
 */
export function toOCSF(entry) {
  const c = classifyEntry(entry);
  if (!c.valid) {
    return {
      activity_id: 0,
      activity_name: 'Unknown',
      category_uid: CATEGORY_UID,
      category_name: 'Application Activity',
      class_uid: SIEM_OCSF_CLASS_UID,
      class_name: 'API Activity',
      type_uid: SIEM_OCSF_CLASS_UID * 100 + 0,
      // No trustworthy timestamp inside the entry; 0 sentinel, never the wall
      // clock — the mapping stays pure and the bad entry stays evident.
      time: 0,
      severity_id: 3,
      severity: 'Medium',
      status_id: 2,
      status: 'Failure',
      status_detail: 'malformed_evidence_entry',
      metadata: { version: OCSF_SCHEMA_VERSION, log_name: SIEM_EXPORT_VERSION, product: PRODUCT, uid: null, correlation_uid: null },
      actor: { user: { uid: null } },
      api: { operation: null },
      unmapped: { error: 'malformed_evidence_entry', entry_preview: safePreview(entry) },
    };
  }
  return {
    activity_id: 99,
    activity_name: c.kind,
    category_uid: CATEGORY_UID,
    category_name: 'Application Activity',
    class_uid: SIEM_OCSF_CLASS_UID,
    class_name: 'API Activity',
    type_uid: SIEM_OCSF_CLASS_UID * 100 + 99,
    time: c.timeMs,
    severity_id: c.success ? 1 : 3,
    severity: c.success ? 'Informational' : 'Medium',
    status_id: c.success ? 1 : 2,
    status: c.success ? 'Success' : 'Failure',
    status_detail: entry.reason ?? entry.outcome ?? null,
    metadata: {
      version: OCSF_SCHEMA_VERSION,
      log_name: SIEM_EXPORT_VERSION,
      product: PRODUCT,
      uid: entry.hash ?? null,
      correlation_uid: entry.receipt_id ?? null,
    },
    actor: { user: { uid: entry.subject ?? null } },
    api: { operation: entry.action ?? null },
    unmapped: {
      kind: c.kind,
      required_tier: entry.required_tier ?? null,
      selector: entry.selector ?? null,
      evidence_seq: Number.isFinite(entry.seq) ? entry.seq : null,
      prev_hash: entry.prev_hash ?? null,
    },
  };
}

// CEF escaping per the ArcSight CEF spec: prefix fields escape backslash and
// pipe; extension values escape backslash and equals. Newlines are collapsed
// in both — a CEF record is one line, always.
function escPrefix(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}
function escExt(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/[\r\n]+/g, ' ');
}

/**
 * Map an evidence-log entry to a one-line CEF string (syslog fallback for
 * SIEMs without OCSF ingestion). Same determinism and malformed-input
 * contract as toOCSF.
 * @param {object} entry  one record from evidence.all()
 * @returns {string} `CEF:0|...` single line
 */
export function toCEF(entry) {
  const c = classifyEntry(entry);
  if (!c.valid) {
    const ext = [
      'act=error',
      'outcome=malformed_evidence_entry',
      `msg=${escExt(safePreview(entry))}`,
      `cs4=${escExt(SIEM_EXPORT_VERSION)}`, 'cs4Label=export_version',
    ].join(' ');
    return `CEF:0|EmiliaProtocol|Gate|1|gate.malformed|malformed evidence entry|5|${ext}`;
  }
  const verdictWord = c.kind === 'execution'
    ? (c.success ? 'executed' : 'failed')
    : (c.success ? 'allowed' : 'refused');
  const signatureId = `gate.${c.kind}.${c.success ? 'allow' : 'deny'}`;
  const name = `${entry.action ?? 'unknown_action'} ${verdictWord}`;
  const severity = c.success ? 3 : 7;
  const ext = [`end=${c.timeMs}`, `act=${c.success ? 'allow' : 'deny'}`];
  const reason = entry.reason ?? entry.outcome;
  if (reason != null) ext.push(`outcome=${escExt(reason)}`);
  if (entry.subject != null) ext.push(`suser=${escExt(entry.subject)}`);
  if (entry.receipt_id != null) ext.push(`cs1=${escExt(entry.receipt_id)}`, 'cs1Label=receipt_id');
  if (entry.hash != null) ext.push(`cs2=${escExt(entry.hash)}`, 'cs2Label=evidence_hash');
  if (entry.required_tier != null) ext.push(`cs3=${escExt(entry.required_tier)}`, 'cs3Label=required_tier');
  ext.push(`cs4=${escExt(SIEM_EXPORT_VERSION)}`, 'cs4Label=export_version');
  if (Number.isFinite(entry.seq)) ext.push(`cn1=${entry.seq}`, 'cn1Label=evidence_seq');
  return `CEF:0|EmiliaProtocol|Gate|1|${escPrefix(signatureId)}|${escPrefix(name)}|${severity}|${ext.join(' ')}`;
}

/**
 * Create a forwarder that ships evidence entries to a SIEM sink.
 *
 * INVARIANT: SIEM export must NEVER block or crash enforcement. The gate path
 * calls forward() fire-and-forget; a sink that throws, rejects, or is down is
 * recorded on the internal `dropped` counter (exposed via stats()) and NOTHING
 * propagates back to the caller — forward() always resolves, never rejects.
 * This is the inverse of the evidence log's strict mode: the evidence log is
 * the authoritative record and fails closed; the SIEM copy is telemetry and
 * fails open, silently, with an auditable drop count.
 *
 * Configuration errors (unknown format, missing sink) DO throw — at
 * construction time, before anything is on the gate path.
 *
 * @param {object} [o]
 * @param {'ocsf'|'cef'} [o.format='ocsf']
 * @param {function} [o.sink]  receives the mapped event (object for ocsf, string for cef); may be async
 * @returns {{ forward(entry): Promise<{delivered:boolean, event:object|string|null}>, stats(): object }}
 */
export function createSiemForwarder({ format = 'ocsf', sink } = {}) {
  if (format !== 'ocsf' && format !== 'cef') {
    throw new Error(`EMILIA Gate SIEM: unknown format "${format}" (expected 'ocsf' or 'cef')`);
  }
  if (typeof sink !== 'function') {
    throw new Error('EMILIA Gate SIEM: a sink function is required');
  }
  const counts = { forwarded: 0, dropped: 0, malformed: 0 };

  async function forward(entry) {
    let event = null;
    try {
      if (!classifyEntry(entry).valid) counts.malformed += 1;
      event = format === 'cef' ? toCEF(entry) : toOCSF(entry);
      await sink(event);
      counts.forwarded += 1;
      return { delivered: true, event };
    } catch {
      // Sink failure (or any unexpected mapper failure): counted, never
      // propagated — enforcement must not depend on SIEM availability.
      counts.dropped += 1;
      return { delivered: false, event };
    }
  }

  function stats() {
    return { format, forwarded: counts.forwarded, dropped: counts.dropped, malformed: counts.malformed };
  }

  return { forward, stats };
}

export default { SIEM_EXPORT_VERSION, SIEM_OCSF_CLASS_UID, toOCSF, toCEF, createSiemForwarder };
