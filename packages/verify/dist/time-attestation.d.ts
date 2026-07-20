export declare const TIME_ATTESTATION_VERSION = "EP-TIME-ATTESTATION-v1";
export interface TimeAttestation {
    '@version'?: unknown;
    ts_authority_id?: unknown;
    hashed?: unknown;
    time?: unknown;
    proof?: {
        public_key?: unknown;
        signature_b64u?: unknown;
        [key: string]: unknown;
    } | null;
    [key: string]: unknown;
}
export interface TimeAttestationOptions {
    tsaKeys?: Record<string, {
        public_key: string;
    }>;
    expectedHash?: string;
    notBefore?: string | number | Date;
    notAfter?: string | number | Date;
    [key: string]: unknown;
}
export interface TimeAttestationResult {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
/**
 * @param {object} att  the EP-TIME-ATTESTATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.expectedHash]  the artifact hash this attestation MUST cover.
 * @param {string|number|Date} [opts.notBefore]  attested time must be >= this.
 * @param {string|number|Date} [opts.notAfter]   attested time must be <= this.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export declare function verifyTimeAttestation(att: TimeAttestation | null | undefined, opts?: TimeAttestationOptions): TimeAttestationResult;
//# sourceMappingURL=time-attestation.d.ts.map