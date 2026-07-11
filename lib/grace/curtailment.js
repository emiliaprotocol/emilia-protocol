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
 *    bounds, DIMENSIONED so no check ever compares mixed units:
 *    max_event_mw (per-event instantaneous power cap, MW), max_period_mwh
 *    (cumulative energy budget for the period, MWh), max_events (event
 *    count budget), max_event_hours (cumulative event-hours budget),
 *    plus the participation window and notice floor. Authorized once, per
 *    season — the honest scale story: the human authorized the ENVELOPE.
 *  - ORDER CONTAINMENT: every curtailment order must fit inside the
 *    envelope (Order ⊆ Envelope), checked fail-closed BEFORE execution.
 *  - SETTLEMENT POLICY: the relying-party evidence policy a settlement
 *    (or interconnection) authority replays over the event's evidence
 *    graph: order + authorization + execution attestation + meter
 *    statement, each byte-bound to the same event.
 *  - COMPLIANCE: delivered-vs-ordered MW from the METER leg (never from
 *    the facility's own attestation alone) — a settlement computation,
 *    separate from evidence sufficiency by design. The meter is a
 *    physical witness: a meter statement that carries market rules
 *    (baseline_method_hash) is refused, never quietly accepted.
 *  - ONE-TIME SETTLEMENT: a settlement CONSUMES a unique entitlement
 *    keyed by {entitlement_id, event_id, meter_window_digest}; a second
 *    settlement over the same key is refused with a typed reason, so the
 *    same curtailment event can never be sold twice.
 */

export const FLEX_ENVELOPE_VERSION = 'EP-FLEX-ENVELOPE-v2';

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

const round3 = (n) => Math.round(n * 1000) / 1000;

/**
 * Order ⊆ Envelope — the fail-closed pre-execution check a facility runs
 * before its enforcement point lets a curtailment command through. Every
 * violation is reported; an out-of-bounds order MUST NOT execute, however
 * validly it is signed.
 *
 * Every comparison is dimensioned — power against power, energy against
 * energy, counts against counts, hours against hours (per-event MW are
 * never summed against an instantaneous ceiling):
 *   - order.mw                      <= bounds.max_event_mw        (MW)
 *   - order.mw * window duration    <= max_period_mwh - spent_mwh (MWh)
 *   - spent_events + 1              <= bounds.max_events          (count)
 *   - window duration               <= max_event_hours - spent_event_hours (h)
 *
 * @param {object} [opts] {spent_mwh, spent_events, spent_event_hours} —
 *   the aggregate already SETTLED under this envelope this period. Omitting
 *   a spent value asserts nothing has settled yet (0); a spent value that is
 *   PRESENT but unparseable or negative is a violation, never coerced to
 *   zero — a garbage ledger must not read as a fresh one. Any dimension
 *   bound the check needs that is missing or unparseable is likewise a
 *   violation, never an unlimited default. The envelope, not any single
 *   order, is the ceiling: a compromised dispatcher key can never spend
 *   more than the human authorized across the whole period.
 */
export function checkOrderWithinEnvelope(order, envelope, opts = {}) {
  const violations = [];
  if (envelope?.['@version'] !== FLEX_ENVELOPE_VERSION) violations.push('envelope: unknown version');
  const bounds = envelope?.bounds;

  // A dimension bound the check needs must be present and parseable —
  // a missing budget is a refusal, never an unlimited default (fail closed).
  const requiredBound = (name) => {
    const v = Number(bounds?.[name]);
    if (!Number.isFinite(v) || v <= 0) { violations.push(`envelope: ${name} missing or unparseable (fail closed)`); return null; }
    return v;
  };
  // Spent accounting: omitted means "nothing settled under this envelope yet".
  const spentOf = (name) => {
    const raw = opts?.[name];
    if (raw === undefined || raw === null) return 0;
    const v = Number(raw);
    if (!Number.isFinite(v) || v < 0) { violations.push(`opts: ${name} unparseable (fail closed)`); return null; }
    return v;
  };

  const maxEventMw = requiredBound('max_event_mw');
  const maxPeriodMwh = requiredBound('max_period_mwh');
  const maxEvents = requiredBound('max_events');
  const maxEventHours = requiredBound('max_event_hours');
  const spentMwh = spentOf('spent_mwh');
  const spentEvents = spentOf('spent_events');
  const spentEventHours = spentOf('spent_event_hours');

  // Per-event instantaneous cap: MW against MW.
  const mw = Number(order?.mw);
  if (!Number.isFinite(mw) || mw <= 0) violations.push('order: mw missing or non-positive');
  else if (maxEventMw !== null && mw > maxEventMw) {
    violations.push(`order: ${mw} MW exceeds envelope per-event cap ${maxEventMw} MW`);
  }

  const noticeMin = Number(order?.notice_minutes), floor = Number(bounds?.min_notice_minutes);
  if (Number.isFinite(floor) && (!Number.isFinite(noticeMin) || noticeMin < floor)) {
    violations.push(`order: ${noticeMin} min notice below envelope floor ${floor} min`);
  }

  const start = Date.parse(order?.window?.start), end = Date.parse(order?.window?.end);
  const eStart = Date.parse(bounds?.window?.start), eEnd = Date.parse(bounds?.window?.end);
  let durationHours = null; // an invalid window is already a refusal; no budget math without it
  if (!(start < end)) violations.push('order: invalid window');
  else {
    durationHours = (end - start) / 3600000;
    if (Number.isFinite(eStart) && Number.isFinite(eEnd) && (start < eStart || end > eEnd)) {
      violations.push('order: window outside envelope participation window');
    }
  }

  // Cumulative energy budget: the projected energy of THIS event (MW × h)
  // against the period MWh budget net of what is already settled.
  if (Number.isFinite(mw) && mw > 0 && durationHours !== null && maxPeriodMwh !== null && spentMwh !== null) {
    const projectedMwh = mw * durationHours;
    const remainingMwh = maxPeriodMwh - spentMwh;
    if (projectedMwh > remainingMwh) {
      violations.push(`order: projected ${round3(projectedMwh)} MWh exceeds envelope remaining energy budget ${round3(remainingMwh)} MWh (max ${maxPeriodMwh}, spent ${spentMwh})`);
    }
  }

  // Event-count budget: this event must still fit.
  if (maxEvents !== null && spentEvents !== null && spentEvents + 1 > maxEvents) {
    violations.push(`order: event count budget exhausted (${spentEvents} of ${maxEvents} events already settled)`);
  }

  // Cumulative event-hours budget.
  if (durationHours !== null && maxEventHours !== null && spentEventHours !== null) {
    const remainingHours = maxEventHours - spentEventHours;
    if (durationHours > remainingHours) {
      violations.push(`order: ${round3(durationHours)}h event exceeds envelope remaining event-hours budget ${round3(remainingHours)}h (max ${maxEventHours}, spent ${spentEventHours})`);
    }
  }

  return { within: violations.length === 0, violations };
}

/**
 * Delivered-vs-ordered compliance, computed from the METER statement's
 * interval data (independent telemetry), never from the facility's own
 * attestation. Returns the settlement-relevant numbers plus a compliance
 * ratio; what ratio earns what payment is the program's tariff, not EP's.
 *
 * The meter is a PHYSICAL WITNESS: its statement carries measurement data
 * only. A meter statement that smuggles market rules (baseline_method_hash)
 * is refused fail-closed — the baseline method is bound at the BUNDLE level
 * against the order, so changing a program's method never requires
 * re-provisioning meters.
 */
export function computeCompliance(order, meterStatement) {
  if (meterStatement && typeof meterStatement === 'object' && 'baseline_method_hash' in meterStatement) {
    return {
      computable: false,
      reason: 'meter statement carries baseline_method_hash: the meter is a physical witness and must not carry market rules (bind the method at the bundle level, against the order)',
    };
  }
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

// ─── One-time settlement consumption ─────────────────────────────────────────

export const SETTLEMENT_CONSUMPTION_PROFILE = 'EP-GRACE-SETTLE-v1';

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/i;

/**
 * The unique one-time entitlement key a settlement CONSUMES:
 * {entitlement_id (the envelope/contract being drawn against), event_id
 * (the order's event), meter_window_digest (digest of the signed meter
 * payload for the settled window)}. Serialized as a JSON array so the
 * mapping is injective — no delimiter ambiguity between parts.
 *
 * This key is exactly the NONCE for EP's existing one-time-consumption
 * discipline (EP-SMT-CONSUME-v1, packages/verify/consumption-proof.js): a
 * settlement authority operating a witnessed sparse-Merkle consumption log
 * inserts this key at settlement time, making a double settlement
 * offline-detectable by any third party holding two log heads, the same
 * way receipt-nonce double-spend is.
 *
 * Fail-closed: any missing or malformed part yields no key, with a typed
 * reason — an incomplete claim can never settle.
 *
 * @returns {{key: (string|null), reason: (string|null)}}
 */
export function settlementEntitlementKey(claim) {
  const entitlement = claim?.entitlement_id, event = claim?.event_id, windowDigest = claim?.meter_window_digest;
  if (typeof entitlement !== 'string' || entitlement.length === 0) return { key: null, reason: 'entitlement_id_missing' };
  if (typeof event !== 'string' || event.length === 0) return { key: null, reason: 'event_id_missing' };
  if (typeof windowDigest !== 'string' || !SHA256_DIGEST.test(windowDigest)) return { key: null, reason: 'meter_window_digest_malformed' };
  return { key: `${SETTLEMENT_CONSUMPTION_PROFILE}:${JSON.stringify([entitlement, event, windowDigest.toLowerCase()])}`, reason: null };
}

/**
 * One-time settlement consumption, fail-closed: the same curtailment event
 * can never settle twice. Mirrors the consumedNonces discipline the
 * evidence-challenge loop already enforces (lib/negotiate/
 * evidence-challenge.js): the registry is an explicit Set the settlement
 * authority owns; no registry, no settlement. A second settlement
 * presenting the same {entitlement_id, event_id, meter_window_digest} is
 * refused with the typed reason 'settlement_already_consumed'.
 *
 * Scope, stated on purpose: this checks the settling authority's OWN
 * ledger. Third-party offline detection of double settlement is the
 * EP-SMT-CONSUME-v1 consumption proof over the same key (see
 * settlementEntitlementKey above); this function is the authority-side
 * gate that consumes the entitlement in the first place.
 *
 * @param {object} claim {entitlement_id, event_id, meter_window_digest}
 * @param {Set<string>} consumedKeys the authority's consumption registry
 * @returns {{settled: boolean, key: (string|null), reason: (string|null)}}
 */
export function checkSettlementConsumption(claim, consumedKeys) {
  if (!claim || typeof claim !== 'object') return { settled: false, key: null, reason: 'claim_missing' };
  if (!(consumedKeys instanceof Set)) return { settled: false, key: null, reason: 'consumption_registry_missing' };
  const { key, reason } = settlementEntitlementKey(claim);
  if (key === null) return { settled: false, key: null, reason };
  if (consumedKeys.has(key)) return { settled: false, key, reason: 'settlement_already_consumed' };
  consumedKeys.add(key); // consumed exactly once, at first successful settlement
  return { settled: true, key, reason: null };
}
