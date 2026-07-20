export declare const AUTHORITY_PROOF_VERSION = "EP-AUTHORITY-PROOF-v1";
export declare const AUTHORITY_PROOF_DOMAIN = "EP-AUTHORITY-PROOF-v1\0";
export interface AuthorityProof {
    '@type'?: unknown;
    authority_id?: unknown;
    registry_head?: unknown;
    registry_epoch?: unknown;
    signature?: {
        algorithm?: unknown;
        public_key?: unknown;
        signature_b64u?: unknown;
        key_id?: unknown;
        proof_digest?: unknown;
        [key: string]: unknown;
    } | null;
    [key: string]: unknown;
}
export interface PinnedRegistryKey {
    issuer_id: string;
    key_id?: string;
    public_key: string;
}
export interface AuthorityProofOptions {
    pinnedRegistryKeys?: PinnedRegistryKey[];
    expectRegistryHead?: string;
    expectMinEpoch?: number;
}
/** Digest of the signed proof body, excluding the signature envelope. */
export declare function authorityProofDigest(proof: AuthorityProof): string;
/**
 * Verify an EP-AUTHORITY-PROOF-v1 against pinned registry issuer keys.
 * @param {object} proof
 * @param {object} opts
 * @param {Array<{issuer_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectRegistryHead]  proof.registry_head must equal this (equivocation)
 * @param {number} [opts.expectMinEpoch]      proof.registry_epoch must be >= this (staleness)
 * @returns {{verified:boolean, accepted:boolean, checks:object, reason?:string, proof_digest?:string, key_id?:string}}
 */
export declare function verifyAuthorityProof(proof: AuthorityProof | null | undefined, opts?: AuthorityProofOptions): {
    proof_digest?: string | undefined;
    verified: boolean;
    accepted: boolean;
    checks: {
        [x: string]: boolean;
    };
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    checks: Record<string, boolean>;
    key_id: string;
    proof_digest: string;
};
//# sourceMappingURL=authority-proof.d.ts.map