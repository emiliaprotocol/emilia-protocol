import { type TimeAttestation } from './time-attestation.js';
export declare const EVIDENCE_RECORD_VERSION = "EP-EVIDENCE-RECORD-v1";
interface ArchiveTimestamp {
    time_attestation?: TimeAttestation | null;
    [key: string]: unknown;
}
interface EvidenceRecord {
    '@version'?: unknown;
    protected_hash?: unknown;
    archive_timestamps?: ArchiveTimestamp[];
    [key: string]: unknown;
}
interface EvidenceRecordOptions {
    tsaKeys?: Record<string, {
        public_key: string;
    }>;
    protectedHash?: string;
}
/**
 * @param {object} record  the EP-EVIDENCE-RECORD-v1 document.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.protectedHash]  the hash of the artifact the relying party HOLDS; binds the record to it.
 * @returns {{valid:boolean, checks:object, errors:string[], protected_since?:string, last_renewed?:string}}
 */
export declare function verifyEvidenceRecord(record: EvidenceRecord | null | undefined, opts?: EvidenceRecordOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    protected_since?: undefined;
    last_renewed?: undefined;
} | {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    protected_since: string | null;
    last_renewed: unknown;
};
export {};
//# sourceMappingURL=evidence-record.d.ts.map