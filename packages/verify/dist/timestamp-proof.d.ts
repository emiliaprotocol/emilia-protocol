type TimestampResult = {
    verified: false;
    tsa_key_id: null;
    gen_time: null;
    reason: string;
} | {
    verified: true;
    tsa_key_id: string;
    gen_time: string;
};
export declare const TIMESTAMP_PROOF_ALG = "RFC3161";
/**
 * Parse + verify an RFC 3161 TimeStampToken against a PINNED TSA key.
 *
 * @param {string|Buffer} timestampProof  DER TimeStampToken, base64/base64url (or a Buffer).
 * @param {string|Buffer} expectedDigest  the digest the token MUST timestamp
 *   (the receipt's checkpoint root or action digest — CALLER decides which).
 *   Accepts "sha256:<hex>", bare hex, or a Buffer of raw digest bytes.
 * @param {string|string[]|object} pinnedTsaKeys  the caller-supplied trust set.
 *   Each entry is an SPKI DER public key (base64/base64url) or a PEM string. May
 *   be a single key, an array of keys, or an object map { id: key }. The token
 *   REFUSES unless its signature verifies under one of these pinned keys.
 * @returns {{verified:boolean, tsa_key_id:(string|null), gen_time:(string|null), reason?:string}}
 *   FAIL-CLOSED. `verified:false` always carries a distinct `reason`. On success
 *   `tsa_key_id` is the SHA-256 fingerprint of the pinned SPKI that verified it,
 *   and `gen_time` is the TSA-asserted RFC 3339 UTC instant. The honest meaning:
 *   this TSA asserted `expectedDigest` existed at `gen_time` (the bytes predate
 *   gen_time). It does NOT prove the action was correct.
 */
export declare function verifyTimestampProof(timestampProof: unknown, expectedDigest: unknown, pinnedTsaKeys: unknown): TimestampResult;
export {};
//# sourceMappingURL=timestamp-proof.d.ts.map