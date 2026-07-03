// SPDX-License-Identifier: Apache-2.0
/**
 * GRACE — proof-of-curtailment settlement layer (grid.curtailment profile).
 *
 * WHAT THIS IS
 * ------------
 * The evidence side of demand response for AI-scale loads: a utility or ISO
 * grants faster interconnection to a facility that promises to curtail, and
 * the promise is only bankable if the CLAIM is verifiable — who authorized
 * participation, what a given event ordered, whether the facility complied,
 * and what should be paid. EP does not turn the power down (the facility's
 * BMS/DCIM does); EP makes turning it down AUTHORIZED, PROVABLE, and PAYABLE.
 *
 * Pieces, all riding the existing stack (no new cryptography):
 *  - FLEX ENVELOPE: a human-authorized participation commitment with hard
 *    bounds (max MW, allowed windows, notice floor). Authorized once, per
 *    season — the honest scale story: the human authorized the ENVELOPE.
 *  - ORDER CONTAINMENT: every curtailment order must fit inside the
 *    envelope (Order ⊆ Envelope), checked fail-closed BEFORE execution.
 *  - SETTLEMENT POLICY: the relying-party evidence policy a settlement
 *    (or interconnection) authority replays over the event's evidence
 *    graph: order + authorization + execution attestation + meter
 *    statement, each byte-bound to the same event.
 *  - COMPLIANCE: delivered-vs-ordered MW from the METER leg (never from
 *    the facility's own attestation alone) — a settlement computation,
 *    separate from evidence sufficiency by design.
 */

export const FLEX_ENVELOPE_VERSION = 'EP-FLEX-ENVELOPE-v1';

/**
 * The settlement authority's evidence policy for one curtailment event.
 * Relying-party-supplied, like every evidence policy; this is the GRACE
 * default a utility adopts and then owns (pin issuers, tune freshness).
 */
export const CURTAILMENT_SETTLEMENT_POLICY = Object.freeze({
  policy_id: 'ep:grace:curtailment-settlement:v1',
  reliance_purpose: 'settlement',
  action_family: 'urn:ep:action:grid.curtailment',
  requirement: 'curtailment_order AND authorization_receipt AND execution_attestation AND meter_statement',
  freshness_sec: { curtailment_order: 86400, execution_attestation: 86400, meter_statement: 172800 },
  revocation_required: ['authorization_receipt'],
  required_edges: [
    // the facility acted UNDER its authorization…
    { from_type: 'execution_attestation', rel: 'executes', to_type: 'authorization_receipt' },
    // …and the meter (independent telemetry) recorded THAT execution.
    { from_type: 'meter_statement', rel: 'records', to_type: 'execution_attestation' },
  ],
  trust_anchor_slots: ['curtailment_order', 'authorization_receipt', 'meter_statement'],
});

/**
 * Order ⊆ Envelope — the fail-closed pre-execution check a facility runs
 * before its enforcement point lets a curtailment command through. Every
 * violation is reported; an out-of-bounds order MUST NOT execute, however
 * validly it is signed.
 *
 * @param {object} [opts] {spent_mw} — aggregate already-settled MW under this
 *   envelope this period. The order's mw MUST NOT exceed the envelope's
 *   UNSPENT balance (max_mw - spent_mw), not merely max_mw: the envelope, not
 *   any single order, is the ceiling, so a compromised dispatcher key can
 *   never spend more than the human authorized across the whole period.
 */
export function checkOrderWithinEnvelope(order, envelope, opts = {}) {
  const violations = [];
  if (envelope?.['@version'] !== FLEX_ENVELOPE_VERSION) violations.push('envelope: unknown version');
  const mw = Number(order?.mw), maxMw = Number(envelope?.bounds?.max_mw);
  const spent = Number.isFinite(Number(opts.spent_mw)) ? Number(opts.spent_mw) : 0;
  const remaining = Number.isFinite(maxMw) ? maxMw - spent : NaN;
  if (!Number.isFinite(mw) || mw <= 0) violations.push('order: mw missing or non-positive');
  else if (!Number.isFinite(remaining) || mw > remaining) {
    violations.push(`order: ${mw} MW exceeds envelope unspent balance ${Number.isFinite(remaining) ? remaining : 'unknown'} MW (max ${maxMw}, spent ${spent})`);
  }
  const noticeMin = Number(order?.notice_minutes), floor = Number(envelope?.bounds?.min_notice_minutes);
  if (Number.isFinite(floor) && (!Number.isFinite(noticeMin) || noticeMin < floor)) {
    violations.push(`order: ${noticeMin} min notice below envelope floor ${floor} min`);
  }
  const start = Date.parse(order?.window?.start), end = Date.parse(order?.window?.end);
  const eStart = Date.parse(envelope?.bounds?.window?.start), eEnd = Date.parse(envelope?.bounds?.window?.end);
  if (!(start < end)) violations.push('order: invalid window');
  else if (Number.isFinite(eStart) && Number.isFinite(eEnd) && (start < eStart || end > eEnd)) {
    violations.push('order: window outside envelope participation window');
  }
  const maxH = Number(envelope?.bounds?.max_event_hours);
  if (Number.isFinite(maxH) && (end - start) / 3600000 > maxH) violations.push(`order: event longer than envelope max ${maxH}h`);
  return { within: violations.length === 0, violations };
}

/**
 * Delivered-vs-ordered compliance, computed from the METER statement's
 * interval data (independent telemetry), never from the facility's own
 * attestation. Returns the settlement-relevant numbers plus a compliance
 * ratio; what ratio earns what payment is the program's tariff, not EP's.
 */
export function computeCompliance(order, meterStatement) {
  const baseline = Number(meterStatement?.baseline_mw);
  const intervals = meterStatement?.intervals_mw;
  if (!Number.isFinite(baseline) || !Array.isArray(intervals) || intervals.length === 0) {
    return { computable: false, reason: 'meter statement lacks baseline or interval data' };
  }
  const avgLoad = intervals.reduce((a, b) => a + Number(b), 0) / intervals.length;
  const delivered = baseline - avgLoad;
  const ordered = Number(order?.mw);
  if (!Number.isFinite(ordered) || ordered <= 0) return { computable: false, reason: 'order lacks mw' };
  const ratio = delivered / ordered;
  return {
    computable: true,
    ordered_mw: ordered,
    delivered_mw: Math.round(delivered * 1000) / 1000,
    compliance_ratio: Math.round(ratio * 1000) / 1000,
    compliant: ratio >= 0.95, // program default; tariffs may override
  };
}

/**
 * A refused order is evidence, not silence: on any gate-predicate failure or
 * protected-lane conflict the controller emits a signed REFUSAL statement over
 * the refused order's digest, the failing predicate(s), and the time — so the
 * dispatcher gets a verifiable "no, and here is why," offline-checkable by the
 * same parties that verify an authorization. Signing is delegated to the
 * caller's key material (kept out of this pure builder).
 */
export function buildRefusalStatement(orderDigest, violations, atISO) {
  return {
    typ: 'ep-curtailment-refusal',
    action_type: 'grid.curtailment',
    refused_order_digest: orderDigest,
    failing_predicates: Array.isArray(violations) ? violations : [String(violations)],
    refused_at: atISO,
  };
}
