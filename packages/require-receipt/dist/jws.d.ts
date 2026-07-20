type AnyRecord = Record<string, any>;
export declare const JWS_PROFILE_VERSION = "EP-RECEIPT-JWS-PROFILE-v1";
export declare const JWS_ALG = "EdDSA";
export declare const JWS_TYP = "application/ep-receipt+jws";
declare function canonicalize(v: any): string;
/**
 * Deterministic key id for an issuer Ed25519 public key: the first 16 bytes of
 * SHA-256 over the base64url SPKI-DER key, hex-encoded. EP receipts do not carry
 * a native `kid`; this gives JOSE consumers a stable, reproducible identifier
 * derived from the key itself (a JWK thumbprint-style fingerprint). Purely
 * advisory — verification trusts the supplied key, never the `kid`.
 *
 * @param {string} publicKeyBase64url base64url SPKI-DER Ed25519 public key
 * @returns {string} hex key id
 */
export declare function deriveKid(publicKeyBase64url: string): string;
/**
 * Serialize an EP-RECEIPT-v1 document as a COMPACT JWS (RFC 7515 §3.1, §7.1).
 *
 * The JWS payload is the canonical (JCS) bytes of `doc.payload` — the exact same
 * bytes the native EP signature covers — so a JWS verifier and an EP verifier
 * authenticate identical receipt material.
 *
 * @param {object} doc EP-RECEIPT-v1 document ({ '@version', payload, signature?, public_key? })
 * @param {crypto.KeyObject|string|Buffer} privateKey issuer Ed25519 private key
 *   (KeyObject, PEM, base64url PKCS8 DER, or DER Buffer)
 * @param {object} [opts]
 * @param {string} [opts.kid] explicit JWS `kid`; otherwise derived from
 *   opts.publicKey or doc.public_key when available (else omitted)
 * @param {string} [opts.publicKey] issuer base64url SPKI key, used only to derive `kid`
 * @returns {string} compact JWS: b64u(protected).b64u(payload).b64u(signature)
 */
export declare function serializeReceiptJws(doc: AnyRecord, privateKey: any, opts?: {
    kid?: string;
    publicKey?: string;
}): string;
/**
 * Verify an EP-RECEIPT-JWS-PROFILE-v1 compact JWS and reconstruct the receipt.
 *
 * Steps (RFC 7515 §5.2 + the EP profile):
 *   1. Parse the three compact segments and the protected header.
 *   2. Enforce the profile header: alg === "EdDSA", typ === "application/ep-receipt+jws".
 *   3. Verify the Ed25519 signature over ASCII(b64u(header) "." b64u(payload)).
 *   4. Parse the payload bytes back to the receipt payload object.
 *   5. Round-trip check: canonicalize(parsedPayload) MUST equal the verified
 *      payload bytes byte-for-byte. This rejects any non-canonical re-encoding
 *      and guarantees the JWS authenticated the EP canonical form.
 *
 * Fails closed: any structural, header, signature, or round-trip mismatch
 * returns { valid: false, ... } and never throws on attacker-controlled input.
 *
 * @param {string} jws compact JWS string
 * @param {crypto.KeyObject|string|Buffer} publicKey issuer Ed25519 public key
 *   (KeyObject, PEM, or base64url SPKI DER)
 * @returns {{ valid: boolean, checks: { structure: boolean, header: boolean, signature: boolean, roundtrip: boolean }, payload?: object, header?: object, error?: string }}
 */
export declare function verifyReceiptJws(jws: string, publicKey: any): {
    valid: boolean;
    checks: {
        structure: boolean;
        header: boolean;
        signature: boolean;
        roundtrip: boolean;
    };
    error: string;
    header?: undefined;
    payload?: undefined;
} | {
    valid: boolean;
    checks: {
        structure: boolean;
        header: boolean;
        signature: boolean;
        roundtrip: boolean;
    };
    header: AnyRecord;
    error: string;
    payload?: undefined;
} | {
    valid: boolean;
    checks: {
        structure: boolean;
        header: boolean;
        signature: boolean;
        roundtrip: boolean;
    };
    header: AnyRecord;
    payload: AnyRecord;
    error: string;
} | {
    valid: boolean;
    checks: {
        structure: boolean;
        header: boolean;
        signature: boolean;
        roundtrip: boolean;
    };
    header: AnyRecord;
    payload: AnyRecord;
    error?: undefined;
};
export { canonicalize as canonicalizeReceiptPayload };
//# sourceMappingURL=jws.d.ts.map