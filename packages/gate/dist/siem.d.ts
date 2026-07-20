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
export declare const SIEM_EXPORT_VERSION = "EP-GATE-SIEM-EXPORT-v1";
export declare const SIEM_OCSF_CLASS_UID = 6003;
/**
 * Map an evidence-log entry to an OCSF API Activity (6003) event object.
 * Static and deterministic: same entry, same object, always. Malformed input
 * yields a structured error event rather than throwing (see module doc).
 * @param {object} entry  one record from evidence.all()
 * @returns {object} OCSF-shaped event
 */
export declare function toOCSF(entry: any): {
    activity_id: number;
    activity_name: string;
    category_uid: number;
    category_name: string;
    class_uid: number;
    class_name: string;
    type_uid: number;
    time: number;
    severity_id: number;
    severity: string;
    status_id: number;
    status: string;
    status_detail: string;
    metadata: {
        version: string;
        log_name: string;
        product: {
            name: string;
            vendor_name: string;
        };
        uid: null;
        correlation_uid: null;
    };
    actor: {
        user: {
            uid: null;
        };
    };
    api: {
        operation: null;
    };
    unmapped: {
        error: string;
        entry_preview: any;
        kind?: undefined;
        required_tier?: undefined;
        selector?: undefined;
        evidence_seq?: undefined;
        prev_hash?: undefined;
    };
} | {
    activity_id: number;
    activity_name: string | undefined;
    category_uid: number;
    category_name: string;
    class_uid: number;
    class_name: string;
    type_uid: number;
    time: number | undefined;
    severity_id: number;
    severity: string;
    status_id: number;
    status: string;
    status_detail: any;
    metadata: {
        version: string;
        log_name: string;
        product: {
            name: string;
            vendor_name: string;
        };
        uid: any;
        correlation_uid: any;
    };
    actor: {
        user: {
            uid: any;
        };
    };
    api: {
        operation: any;
    };
    unmapped: {
        kind: string | undefined;
        required_tier: any;
        selector: any;
        evidence_seq: any;
        prev_hash: any;
        error?: undefined;
        entry_preview?: undefined;
    };
};
/**
 * Map an evidence-log entry to a one-line CEF string (syslog fallback for
 * SIEMs without OCSF ingestion). Same determinism and malformed-input
 * contract as toOCSF.
 * @param {object} entry  one record from evidence.all()
 * @returns {string} `CEF:0|...` single line
 */
export declare function toCEF(entry: any): string;
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
export declare function createSiemForwarder({ format, sink }?: {
    format?: 'ocsf' | 'cef';
    sink?: (event: any) => any;
}): {
    forward: (entry: any) => Promise<{
        delivered: boolean;
        event: string | {
            activity_id: number;
            activity_name: string;
            category_uid: number;
            category_name: string;
            class_uid: number;
            class_name: string;
            type_uid: number;
            time: number;
            severity_id: number;
            severity: string;
            status_id: number;
            status: string;
            status_detail: string;
            metadata: {
                version: string;
                log_name: string;
                product: {
                    name: string;
                    vendor_name: string;
                };
                uid: null;
                correlation_uid: null;
            };
            actor: {
                user: {
                    uid: null;
                };
            };
            api: {
                operation: null;
            };
            unmapped: {
                error: string;
                entry_preview: any;
                kind?: undefined;
                required_tier?: undefined;
                selector?: undefined;
                evidence_seq?: undefined;
                prev_hash?: undefined;
            };
        } | {
            activity_id: number;
            activity_name: string | undefined;
            category_uid: number;
            category_name: string;
            class_uid: number;
            class_name: string;
            type_uid: number;
            time: number | undefined;
            severity_id: number;
            severity: string;
            status_id: number;
            status: string;
            status_detail: any;
            metadata: {
                version: string;
                log_name: string;
                product: {
                    name: string;
                    vendor_name: string;
                };
                uid: any;
                correlation_uid: any;
            };
            actor: {
                user: {
                    uid: any;
                };
            };
            api: {
                operation: any;
            };
            unmapped: {
                kind: string | undefined;
                required_tier: any;
                selector: any;
                evidence_seq: any;
                prev_hash: any;
                error?: undefined;
                entry_preview?: undefined;
            };
        } | null;
    }>;
    stats: () => {
        format: "ocsf" | "cef";
        forwarded: number;
        dropped: number;
        malformed: number;
    };
};
declare const _default: {
    SIEM_EXPORT_VERSION: string;
    SIEM_OCSF_CLASS_UID: number;
    toOCSF: typeof toOCSF;
    toCEF: typeof toCEF;
    createSiemForwarder: typeof createSiemForwarder;
};
export default _default;
//# sourceMappingURL=siem.d.ts.map