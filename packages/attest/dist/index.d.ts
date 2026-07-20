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
//# sourceMappingURL=index.d.ts.map