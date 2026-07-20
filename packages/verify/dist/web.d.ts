/**
 * @emilia-protocol/verify/web — Zero-Dependency Trust Verification (Web Crypto)
 *
 * The browser/edge/Deno counterpart to index.js. Identical verification
 * semantics, but built on the W3C Web Crypto API (globalThis.crypto.subtle)
 * instead of Node's `crypto` module — so a receipt can be verified entirely
 * inside the relying party's own browser tab, with nothing uploaded and no
 * server trusted. Same input, same `{ valid, checks }` output as index.js
 * (proven byte-for-byte in web.test.js).
 *
 * Pure ESM, zero dependencies. Functions are async because Web Crypto is.
 *
 * @license Apache-2.0
 */
type JsonObject = Record<string, any>;
interface WebOptions {
    allowLegacyMerkle?: boolean;
    v2?: boolean;
    allowedOrigins?: string[];
    rpId?: string;
    allowUnsigned?: boolean;
}
export declare function canonicalize(value: unknown): string;
export declare const MERKLE_V2_ALG = "EP-MERKLE-v2";
/**
 * Verify an EP receipt document in the browser. Mirrors index.js verifyReceipt.
 * @param {object} doc
 * @param {string} publicKeyBase64url - Ed25519 public key (SPKI DER, base64url)
 * @returns {Promise<{valid:boolean, checks:{version:boolean,signature:boolean,anchor:boolean|null}, error?:string}>}
 */
export declare function verifyReceipt(doc: JsonObject, publicKeyBase64url: string, opts?: WebOptions): Promise<{
    valid: boolean;
    checks: {
        version: boolean;
        signature: boolean;
        anchor: boolean | null;
    };
    error: string;
} | {
    valid: boolean;
    checks: {
        version: boolean;
        signature: boolean;
        anchor: boolean | null;
    };
    error?: undefined;
}>;
/** @returns {Promise<boolean>} */
export declare function verifyMerkleAnchor(leafHash: unknown, proof: unknown, expectedRoot: unknown, opts?: WebOptions): Promise<boolean>;
/**
 * Verify a Class A (approver-held key) signoff fully offline, in the browser.
 * Mirrors index.js verifyWebAuthnSignoff.
 * @returns {Promise<{valid:boolean, checks:object, error?:string}>}
 */
export declare function verifyWebAuthnSignoff(signoff: JsonObject, approverPublicKeySpkiB64u: string, opts?: WebOptions): Promise<{
    valid: boolean;
    checks: {
        challenge_binding: boolean;
        client_data_type: boolean;
        user_present: boolean;
        user_verified: boolean;
        rp_id_hash: boolean | null;
        signature: boolean;
    };
    error: string;
} | {
    valid: boolean;
    checks: {
        challenge_binding: boolean;
        client_data_type: boolean;
        user_present: boolean;
        user_verified: boolean;
        rp_id_hash: boolean | null;
        signature: boolean;
    };
    error?: undefined;
}>;
/** @returns {Promise<{valid:boolean, claim:object|null, error?:string}>} */
export declare function verifyCommitmentProof(proof: JsonObject, publicKeyBase64url: string, options?: WebOptions): Promise<{
    valid: boolean;
    claim: any;
    error: string;
} | {
    valid: boolean;
    claim: any;
    error?: undefined;
}>;
/** @returns {Promise<{valid:boolean, total:number, verified:number, failed:string[]}>} */
export declare function verifyReceiptBundle(bundle: JsonObject, publicKeyBase64url: string): Promise<{
    valid: boolean;
    total: any;
    verified: number;
    failed: string[];
}>;
/** True if Web Crypto with the algorithms EP needs is available in this runtime. */
export declare function isSupported(): boolean;
export {};
//# sourceMappingURL=web.d.ts.map