import { type TimeAttestation } from './time-attestation.js';
import { type AgileSigningKey, type AgilityOptions } from './pq-signature-agility.js';
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
export declare const REATTESTATION_VERSION = "EP-EVIDENCE-REATTESTATION-v1";
export interface ReattestationSignature {
    alg: string;
    key_id: string;
    sig: string;
}
export interface ReattestationEntry {
    '@version': typeof REATTESTATION_VERSION;
    prior_record_digest: string;
    digest_alg: string;
    reattested_at: string;
    new_signature: ReattestationSignature;
}
export interface ReattestationLinkReport {
    index: number;
    alg: string | null;
    key_id: string | null;
    reattested_at: string | null;
    digest_valid: boolean | null;
    signature_valid: boolean | null;
    reason: string | null;
}
export interface ReattestationChainResult {
    verified: boolean;
    reason: string | null;
    links: ReattestationLinkReport[];
    first_reattested_at: string | null;
    last_reattested_at: string | null;
}
export interface ReattestationKeys {
    [key_id: string]: {
        alg: string;
        public_key: string | Uint8Array;
    };
}
/**
 * Issue one re-attestation link (issuer side; throws on misuse).
 *
 * @param prior  the protected record bytes (first link) or the previous
 *               ReattestationEntry (subsequent links).
 * @param opts.key         EP-SIG-AGILITY-v1 signing key ({ alg, private_key, key_id }).
 * @param opts.digestAlg   'sha256' (default) | 'sha384' | 'sha512'.
 * @param opts.reattestedAt RFC 3339 instant; defaults to now.
 */
export declare function createReattestation(prior: Uint8Array | ReattestationEntry, opts: {
    key: AgileSigningKey;
    digestAlg?: string;
    reattestedAt?: string;
} & AgilityOptions): Promise<ReattestationEntry>;
/**
 * Verify a re-attestation chain over the protected record bytes the relying
 * party HOLDS. Walks NEWEST-TO-OLDEST; reports per-link algorithm and
 * validity; a broken link refuses naming the link index and reason.
 *
 * verified:true means: every link's signature verifies under its pinned key,
 * every link's digest commits to the full prior link (link 0 to the record
 * bytes), and re-attestation times strictly increase. It does NOT mean the
 * original artifact was correct, nor that any re-anchor happened before its
 * predecessor algorithm actually broke (see the boundary note above).
 */
export declare function verifyReattestationChain(recordBytes: Uint8Array, entries: unknown, keys: ReattestationKeys | null | undefined, opts?: AgilityOptions): Promise<ReattestationChainResult>;
export {};
//# sourceMappingURL=evidence-record.d.ts.map