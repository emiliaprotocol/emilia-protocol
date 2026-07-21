// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Prometheus metrics exposition (EP-GATE-METRICS-v1).
 *
 * Zero-dependency operational metrics over gate decisions, rendered in the
 * Prometheus text exposition format 0.0.4 (HELP/TYPE lines, escaped label
 * values, stable sorted output). Feed it the gate's decision entries — either
 * the evidence-log entry ({ allow, action, reason, have_tier/required_tier,
 * at }) or the `check()` output — via `onDecision`; scrape via `render()` or
 * mount `handler()` on any framework.
 *
 * CONSTRAINT (enforced): metrics must NEVER throw into the enforcement path.
 * `onDecision` sits on the gate's decision hot path; observability is never
 * allowed to break enforcement. Any entry it cannot interpret — wrong type,
 * underivable outcome, even a poisoned object whose property getters throw —
 * increments ep_gate_metrics_malformed_total and returns. No exception
 * escapes `onDecision`, ever.
 *
 * CARDINALITY GUARD: the action_type label is capped to a bounded set via the
 * `maxSeries` option (default 64 distinct values). Once the cap is reached,
 * new action types bucket to action_type="_other" so a hostile or buggy
 * caller cannot blow up the time-series database. All label values are also
 * length-capped. outcome and reason_class are bounded by construction.
 *
 * Deterministic and pure: time is injected (`now`), used only when an entry
 * carries no usable timestamp. Same entries in, same exposition text out.
 */
export const METRICS_VERSION = 'EP-GATE-METRICS-v1';
/** Prometheus text exposition format 0.0.4 content type. */
export const METRICS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';
/** Bounded denial reason classes — every gate refusal maps into exactly one. */
export const REASON_CLASSES = [
    'replay', // replay_refused — one-time consumption caught a reuse
    'receipt_missing', // receipt_required — guarded action arrived with no receipt
    'receipt_invalid', // receipt_rejected:* — signature/freshness/scope/id failures
    'assurance', // assurance_too_low | unknown_required_tier
    'execution_binding', // execution_binding_failed — claim != observed mutation
    'infrastructure', // evidence_log_failed | consumption_store_lacks_reserve
    'other', // anything this version does not model
];
/** Longest label value we will expose; longer values are truncated (bounded exposition size). */
const MAX_LABEL_VALUE_LEN = 128;
/** Overflow bucket for the action_type cardinality guard. */
const OTHER_BUCKET = '_other';
/**
 * Classify a gate denial reason string into one of REASON_CLASSES. Bounded by
 * construction: unknown reasons land in 'other', never in a fresh label value.
 * @param {string} reason e.g. 'replay_refused', 'receipt_rejected:bad_signature'
 * @returns {string} one of REASON_CLASSES
 */
export function classifyDenialReason(reason) {
    if (typeof reason !== 'string')
        return 'other';
    if (reason === 'replay_refused' || reason.includes('replay'))
        return 'replay';
    if (reason === 'receipt_required')
        return 'receipt_missing';
    if (reason.startsWith('receipt_rejected'))
        return 'receipt_invalid';
    if (reason === 'assurance_too_low' || reason === 'unknown_required_tier')
        return 'assurance';
    if (reason === 'execution_binding_failed')
        return 'execution_binding';
    if (reason === 'evidence_log_failed' || reason === 'consumption_store_lacks_reserve')
        return 'infrastructure';
    return 'other';
}
/** Escape a label value per the exposition format: backslash, quote, newline. */
function escapeLabelValue(v) {
    return String(v)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n');
}
/** Escape HELP text per the exposition format: backslash and newline only. */
function escapeHelp(v) {
    return String(v).replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}
/** Normalize a raw value into a safe, length-capped label value. */
function normLabel(raw, fallback) {
    if (typeof raw !== 'string' || raw.length === 0)
        return fallback;
    return raw.length > MAX_LABEL_VALUE_LEN ? raw.slice(0, MAX_LABEL_VALUE_LEN) : raw;
}
/** Render a sorted, escaped label set: {a="x",b="y"} — stable key order. */
function renderLabels(obj) {
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${k}="${escapeLabelValue(obj[k])}"`).join(',')}}`;
}
const METRICS = [
    { name: 'ep_gate_decisions_total', type: 'counter', help: 'Gate decisions by outcome, action type, and credited assurance tier.' },
    { name: 'ep_gate_denials_total', type: 'counter', help: 'Denied gate decisions by bounded denial reason class.' },
    { name: 'ep_gate_evidence_entries_total', type: 'counter', help: 'Evidence-log entries recorded for gate decisions.' },
    { name: 'ep_gate_last_decision_timestamp_seconds', type: 'gauge', help: 'Unix timestamp (seconds) of the most recent gate decision.' },
    { name: 'ep_gate_metrics_malformed_total', type: 'counter', help: 'Decision entries the metrics layer could not interpret (dropped, never thrown).' },
    { name: 'ep_gate_replays_blocked_total', type: 'counter', help: 'Receipt replays refused by one-time consumption.' },
];
/**
 * Create a metrics registry for one gate.
 * @param {object} [o]
 * @param {number} [o.maxSeries=64] cap on distinct action_type label values; overflow buckets to "_other"
 * @param {number|function} [o.now=Date.now] injected clock (ms or () => ms) — used only when an entry has no usable timestamp
 * @returns {{ onDecision: (entry: object) => void, render: () => string, handler: () => { status: number, headers: object, body: string } }}
 */
export function createMetrics({ maxSeries = 64, now = Date.now } = {}) {
    // Config is clamped, not thrown: a bad option must not brick metrics either.
    const cap = (Number.isInteger(maxSeries) && maxSeries > 0) ? maxSeries : 64;
    const decisions = new Map(); // rendered label set -> count
    const denials = new Map(); // rendered label set -> count
    let replaysBlocked = 0;
    let evidenceEntries = 0;
    let malformed = 0;
    let lastDecisionSeconds = null; // gauge; no sample until the first decision
    const actionTypes = new Set(); // cardinality guard for action_type
    function boundedActionType(raw) {
        const v = normLabel(raw, 'unknown');
        if (actionTypes.has(v))
            return v;
        if (actionTypes.size < cap) {
            actionTypes.add(v);
            return v;
        }
        return OTHER_BUCKET;
    }
    function inc(map, key) {
        map.set(key, (map.get(key) || 0) + 1);
    }
    /**
     * Observe one gate decision. NEVER throws — see the module constraint. A
     * malformed entry (non-object, underivable outcome, throwing getters, ...)
     * increments ep_gate_metrics_malformed_total and returns.
     */
    function onDecision(entry) {
        try {
            if (!entry || typeof entry !== 'object') {
                malformed += 1;
                return;
            }
            // Outcome: the authoritative field is the boolean `allow` (evidence
            // entry and check() output both carry it). A string outcome is accepted
            // only if it is exactly 'allow'/'deny'. Anything else is malformed.
            let outcome;
            if (entry.allow === true)
                outcome = 'allow';
            else if (entry.allow === false)
                outcome = 'deny';
            else if (entry.outcome === 'allow' || entry.outcome === 'deny')
                outcome = entry.outcome;
            else {
                malformed += 1;
                return;
            }
            const actionType = boundedActionType(entry.action_type ?? entry.action);
            const tier = normLabel(entry.tier ?? entry.have_tier ?? entry.required_tier, 'unknown');
            inc(decisions, renderLabels({ outcome, action_type: actionType, tier }));
            if (outcome === 'deny') {
                const reasonClass = classifyDenialReason(entry.reason);
                inc(denials, renderLabels({ reason_class: reasonClass }));
                if (reasonClass === 'replay')
                    replaysBlocked += 1;
            }
            // Each decision appends one evidence record — unless the entry says the
            // write failed outright (check() output carries evidence: null then).
            if (entry.evidence !== null)
                evidenceEntries += 1;
            // Gauge: prefer the entry's own timestamp (`at` ISO/ms), else the
            // injected clock. An unusable clock skips the gauge — never throws.
            const at = entry.at ?? entry.created_at ?? null;
            let ms = null;
            if (typeof at === 'number' && Number.isFinite(at))
                ms = at;
            else if (typeof at === 'string') {
                const p = Date.parse(at);
                if (Number.isFinite(p))
                    ms = p;
            }
            if (ms == null) {
                try {
                    const n = typeof now === 'function' ? now() : now;
                    if (typeof n === 'number' && Number.isFinite(n))
                        ms = n;
                }
                catch { /* unusable injected clock: skip the gauge update */ }
            }
            if (ms != null)
                lastDecisionSeconds = ms / 1000;
        }
        catch {
            // The never-throw guarantee: a poisoned entry (throwing getter, hostile
            // proxy) lands here. Count it, drop it, return. Enforcement continues.
            malformed += 1;
        }
    }
    /** Render Prometheus text format 0.0.4. Deterministic: metrics in fixed order, series sorted. */
    function render() {
        const lines = [];
        for (const m of METRICS) {
            lines.push(`# HELP ${m.name} ${escapeHelp(m.help)}`);
            lines.push(`# TYPE ${m.name} ${m.type}`);
            switch (m.name) {
                case 'ep_gate_decisions_total':
                    for (const k of [...decisions.keys()].sort())
                        lines.push(`${m.name}${k} ${decisions.get(k)}`);
                    break;
                case 'ep_gate_denials_total':
                    for (const k of [...denials.keys()].sort())
                        lines.push(`${m.name}${k} ${denials.get(k)}`);
                    break;
                case 'ep_gate_evidence_entries_total':
                    lines.push(`${m.name} ${evidenceEntries}`);
                    break;
                case 'ep_gate_last_decision_timestamp_seconds':
                    // No sample until the first decision — a fabricated 0 would read as 1970.
                    if (lastDecisionSeconds != null)
                        lines.push(`${m.name} ${lastDecisionSeconds}`);
                    break;
                case 'ep_gate_metrics_malformed_total':
                    lines.push(`${m.name} ${malformed}`);
                    break;
                case 'ep_gate_replays_blocked_total':
                    lines.push(`${m.name} ${replaysBlocked}`);
                    break;
                /* c8 ignore next 2 -- METRICS is a module constant; no other names exist */
                default:
                    break;
            }
        }
        return lines.join('\n') + '\n';
    }
    /** Framework-agnostic scrape response: mount on any router/handler. */
    function handler() {
        return {
            status: 200,
            headers: { 'content-type': METRICS_CONTENT_TYPE },
            body: render(),
        };
    }
    return { onDecision, render, handler };
}
export default { createMetrics, classifyDenialReason, METRICS_VERSION, METRICS_CONTENT_TYPE, REASON_CLASSES };
//# sourceMappingURL=metrics.js.map