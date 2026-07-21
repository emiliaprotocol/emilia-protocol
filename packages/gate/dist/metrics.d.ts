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
export declare const METRICS_VERSION = "EP-GATE-METRICS-v1";
/** Prometheus text exposition format 0.0.4 content type. */
export declare const METRICS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
/** Bounded denial reason classes — every gate refusal maps into exactly one. */
export declare const REASON_CLASSES: string[];
/**
 * Classify a gate denial reason string into one of REASON_CLASSES. Bounded by
 * construction: unknown reasons land in 'other', never in a fresh label value.
 * @param {string} reason e.g. 'replay_refused', 'receipt_rejected:bad_signature'
 * @returns {string} one of REASON_CLASSES
 */
export declare function classifyDenialReason(reason: any): "replay" | "receipt_missing" | "receipt_invalid" | "assurance" | "execution_binding" | "infrastructure" | "other";
/**
 * Create a metrics registry for one gate.
 * @param {object} [o]
 * @param {number} [o.maxSeries=64] cap on distinct action_type label values; overflow buckets to "_other"
 * @param {number|function} [o.now=Date.now] injected clock (ms or () => ms) — used only when an entry has no usable timestamp
 * @returns {{ onDecision: (entry: object) => void, render: () => string, handler: () => { status: number, headers: object, body: string } }}
 */
export declare function createMetrics({ maxSeries, now }?: {
    maxSeries?: number | undefined;
    now?: (() => number) | undefined;
}): {
    onDecision: (entry: any) => void;
    render: () => string;
    handler: () => {
        status: number;
        headers: {
            'content-type': string;
        };
        body: string;
    };
};
declare const _default: {
    createMetrics: typeof createMetrics;
    classifyDenialReason: typeof classifyDenialReason;
    METRICS_VERSION: string;
    METRICS_CONTENT_TYPE: string;
    REASON_CLASSES: string[];
};
export default _default;
//# sourceMappingURL=metrics.d.ts.map