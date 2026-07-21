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
type EvidenceEntry = {
    at: string;
    hash?: string;
    kind?: string;
};
type TaggedEntry = {
    hash: string | null;
    at: string | null;
    kind: string | null;
};
type RetentionOptions = {
    hotDays?: number;
    coldDays?: number;
    now?: number;
    legalHold?: Set<string> | string[];
};
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
export declare function classifyRetention(entries?: EvidenceEntry[], { hotDays, coldDays, now, legalHold, }?: RetentionOptions): {
    summary: {
        total: number;
        hot: number;
        cold: number;
        expired: number;
        legal_hold: number;
        unknown: number;
        hot_days: number;
        cold_days: number;
    };
    hot: TaggedEntry[];
    cold: TaggedEntry[];
    expired: TaggedEntry[];
    legal_hold: TaggedEntry[];
    unknown: TaggedEntry[];
};
/**
 * Build an export manifest (the artifact handed to an auditor / SIEM). Includes
 * the evidence head so the export is verifiably tied to a chain state.
 */
export declare function buildRetentionExport(entries?: EvidenceEntry[], opts?: RetentionOptions): {
    '@version': string;
    generated_at: string;
    hot_days: number;
    cold_days: number;
    evidence_head: string | null;
    counts: {
        total: number;
        hot: number;
        cold: number;
        expired: number;
        legal_hold: number;
        unknown: number;
    };
    entries: {
        hash: string | null;
        at: string;
        kind: string | null;
    }[];
};
export declare const RETENTION_EXPORT_VERSION = "EP-GATE-RETENTION-EXPORT-v1";
declare const _default: {
    classifyRetention: typeof classifyRetention;
    buildRetentionExport: typeof buildRetentionExport;
    RETENTION_EXPORT_VERSION: string;
};
export default _default;
//# sourceMappingURL=retention.d.ts.map