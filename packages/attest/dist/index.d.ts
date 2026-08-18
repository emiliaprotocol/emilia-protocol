/**
 * @emilia-protocol/attest — match identity bytes to a relying-party pin, then
 * sign a work-product binding as an EP-RECEIPT-v1.
 *
 * This is the standardized, drop-in version of the "Identity Manager" pattern
 * (hash an identity → compare to a known-good → sign the work): the same idea,
 * but the thing it signs is an EP receipt anyone can re-derive offline with
 * @emilia-protocol/verify — re-hash the identity file, re-hash the work file,
 * check the Ed25519 signature, and check the EP-MERKLE-v2 inclusion structure.
 * Acceptance still requires an out-of-band pinned signer key and identity pin.
 *
 * Two calls:
 *   verifyIdentity()  — SHA-256 an agent's identity bytes, constant-time compare
 *                       to a known-good hash (e.g. from a Keeper vault).
 *   signWorkReceipt() — bind the verified identity + the work-product hash into a
 *                       receipt. Fail-closed: refuses to sign if identity != known-good.
 *
 * Zero runtime deps beyond node:crypto and the sibling issuer/verifier packages.
 *
 * @license Apache-2.0
 */
import type { KeyObject } from 'node:crypto';
export declare const ATTEST_VERSION = "EP-ATTEST-v2";
export type AttestInput = Buffer | Uint8Array | string;
export interface IdentityCheck {
    verified: boolean;
    computedHash: string | null;
}
export interface SignWorkReceiptArgs {
    identity?: AttestInput;
    knownGoodHash?: string;
    knownGoodSubject?: string;
    work?: AttestInput;
    signerPrivateKey?: KeyObject | string;
    subject?: string;
    issuedAt?: string;
    workName?: string | null;
    receiptId?: string;
    anchor?: boolean;
    priorLeaves?: string[];
}
export interface AttestDocument {
    '@version': 'EP-RECEIPT-v1';
    payload: Record<string, unknown>;
    signature: {
        algorithm: 'Ed25519';
        value: string;
    };
    anchor?: Record<string, unknown>;
}
export interface SignWorkReceiptResult {
    document: AttestDocument;
    public_key: string;
}
/** SHA-256 of arbitrary bytes (Buffer | Uint8Array | string) -> hex. */
export declare function sha256Hex(input: AttestInput): string;
/**
 * Verify an agent identity against a known-good SHA-256.
 * @param {{ identity?: Buffer|Uint8Array|string, knownGoodHash?: string }} args
 * @returns {{ verified: boolean, computedHash: string | null }}
 */
export declare function verifyIdentity({ identity, knownGoodHash }?: {
    identity?: AttestInput;
    knownGoodHash?: string;
}): IdentityCheck;
/**
 * Sign a work product as an EP-RECEIPT-v1, bound to a verified identity.
 * Fail-closed: throws if the identity does not match knownGoodHash.
 *
 * @param {object} args
 * @param {Buffer|Uint8Array|string} [args.identity]        identity-file bytes
 * @param {string} [args.knownGoodHash]                     SHA-256 hex (e.g. from Keeper)
 * @param {string} [args.knownGoodSubject]                  identity id pinned with that hash
 * @param {Buffer|Uint8Array|string} [args.work]            the work-product bytes
 * @param {crypto.KeyObject|string} [args.signerPrivateKey] Ed25519 key (KeyObject or b64u PKCS#8)
 * @param {string} [args.subject]                           identity id (e.g. ep:approver:cfo)
 * @param {string} [args.issuedAt]                          ISO-8601 (caller-supplied — no Date.now lock-in)
 * @param {string|null} [args.workName]
 * @param {string} [args.receiptId]
 * @param {boolean} [args.anchor=false]                   attach an EP-MERKLE-v2 anchor
 * @param {string[]} [args.priorLeaves]                   existing v2 leaves for a real inclusion proof
 * @returns {{ document: object, public_key: string }}   EP-RECEIPT-v1 + the signer SPKI (b64u)
 */
export declare function signWorkReceipt({ identity, knownGoodHash, knownGoodSubject, work, signerPrivateKey, subject, issuedAt, workName, receiptId, anchor, priorLeaves, }?: SignWorkReceiptArgs): SignWorkReceiptResult;
import { type HybridReceiptDocument, type HybridVerificationKeys, type HybridOptions } from '../../issue/dist/hybrid-issuance.js';
/** The attestation profile marker carried INSIDE a hybrid attestation payload. */
export declare const ATTEST_HYBRID_VERSION = "EP-ATTEST-HYBRID-v1";
/** The envelope profile a hybrid attestation is wrapped in. Re-exported so a
 *  relying party can pin the marker without depending on @emilia-protocol/issue. */
export declare const ATTEST_HYBRID_ENVELOPE = "EP-RECEIPT-HYBRID-v1";
export interface SignWorkReceiptHybridArgs extends Omit<SignWorkReceiptArgs, 'signerPrivateKey' | 'anchor' | 'priorLeaves'> {
    /**
     * An EP-HYBRID-ISSUER-KEYS-v1 bundle (generateHybridIssuerKeyBundle in
     * @emilia-protocol/issue), carrying BOTH private halves and BOTH public
     * halves.
     *
     * A bundle rather than loose keys, for one substantive reason: the ML-DSA-65
     * PUBLIC key is not derivable from its secret key (FIPS 204's secret key
     * carries rho, K, tr, s1, s2, t0 — not t1), so a hybrid issuer that holds
     * only secret keys cannot tell a relying party what to pin. The bundle is
     * where both halves already live together.
     */
    keyBundle?: Record<string, any>;
}
export interface SignWorkReceiptHybridResult {
    document: HybridReceiptDocument;
    /** The public halves a relying party pins to verify the document. */
    verification_keys: HybridVerificationKeys;
}
/**
 * Sign a work product as an EP-RECEIPT-HYBRID-v1 (Ed25519 AND ML-DSA-65), bound
 * to a verified identity. Fail-closed in both directions: it refuses to sign
 * when the identity does not match the pin, and it refuses to sign when no
 * ML-DSA backend is available rather than emit a receipt missing the PQ leg.
 *
 * Verify the result with verifyHybridReceipt() from @emilia-protocol/verify
 * (packages/verify/src/receipt-hybrid.ts), passing `verification_keys`.
 *
 * @throws on any pin mismatch, malformed key material, or unavailable ML-DSA
 *   backend. Issuer-side misuse is a programming error, not attacker input.
 */
export declare function signWorkReceiptHybrid({ identity, knownGoodHash, knownGoodSubject, work, keyBundle, subject, issuedAt, workName, receiptId, ...options }?: SignWorkReceiptHybridArgs & HybridOptions): Promise<SignWorkReceiptHybridResult>;
//# sourceMappingURL=index.d.ts.map