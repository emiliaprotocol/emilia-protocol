export declare const ZK_RANGE_RECEIPT_VERSION = "EP-ZK-RANGE-RECEIPT-v1";
export declare const ZK_RANGE_SCHEME = "Bulletproofs-Ristretto255-range-v1";
export declare const ZK_RANGE_BACKEND_PACKAGE = "@aptos-labs/confidential-asset-bindings@1.1.2";
/** Derive independent, deterministic Pedersen bases for this proof domain. */
export declare function deriveZkRangeBases(domain?: string): {
    valBase: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    randBase: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
/** Lazy-load the audited/pinned optional Bulletproof WASM binding. */
export declare function loadBulletproofBackend(): Promise<any>;
/**
 * Mint a hidden-amount Bulletproof range receipt.
 * @param {{ value?: any, max?: any, blindingFactor?: any, policyHash?: any, actionPredicate?: any, baseReceiptDigest?: any, issuerPublicKey?: any, nonce?: string, domain?: string, backend?: any }} [options]
 */
export declare function mintZkRangeReceipt({ value, max, blindingFactor, policyHash, actionPredicate, baseReceiptDigest, issuerPublicKey, nonce, domain, backend, }?: {
    value?: number;
    max?: number;
    blindingFactor?: Uint8Array | string;
    policyHash?: string;
    actionPredicate?: string;
    baseReceiptDigest?: string;
    issuerPublicKey?: string;
    nonce?: string;
    domain?: string;
    backend?: {
        batchRangeProof?: Function;
        batchVerifyProof?: Function;
    } | null;
}): Promise<{
    '@version': string;
    scheme: string;
    domain: string;
    nonce: string;
    statement: {
        policy_hash: string;
        action_predicate: any;
        max: any;
        base_receipt_digest: string;
        issuer_public_key: any;
        num_bits: any;
    };
    commitments: any;
    proof: string;
    binding: string;
}>;
/** Verify the range proof and its public commitment relation. */
export declare function verifyZkRangeReceipt(receipt: any, { backend }?: {
    backend?: null | undefined;
}): Promise<{
    ok: boolean;
    reason: string;
    scheme?: undefined;
    statement?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    scheme: string;
    statement: any;
    reason?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    detail: string;
    scheme?: undefined;
    statement?: undefined;
}>;
declare const _default: {
    ZK_RANGE_RECEIPT_VERSION: string;
    ZK_RANGE_SCHEME: string;
    ZK_RANGE_BACKEND_PACKAGE: string;
    deriveZkRangeBases: typeof deriveZkRangeBases;
    loadBulletproofBackend: typeof loadBulletproofBackend;
    mintZkRangeReceipt: typeof mintZkRangeReceipt;
    verifyZkRangeReceipt: typeof verifyZkRangeReceipt;
};
export default _default;
//# sourceMappingURL=zk-range-proof.d.ts.map