/**
 * EP-COSE-ENCODING-v0.1 - encoding-equivalence profile for EP receipts.
 *
 * Proves that the CAID join survives re-encoding. Two legs:
 *
 *  1. A total value mapping between the EP strict-JSON receipt domain and a
 *     deterministically encoded CBOR subset (RFC 8949 Section 4.2.1). The
 *     mapping uses TEXT map keys: the EP receipt payload is an OPEN strict-JSON
 *     document domain, so a closed integer-key table cannot be total over it
 *     without freezing the payload schema. Text keys keep the mapping total,
 *     bijective on the domain, and auditable byte-for-byte.
 *
 *  2. A COSE_Sign1 (RFC 9052, tag 18) TRANSPORT/REGISTRATION envelope whose
 *     payload is the original receipt's canonical JSON bytes (RFC 8785 profile,
 *     the same bytes the receipt's own Ed25519 signature covers). Protected
 *     headers carry the content type and the receipt action's CAID string.
 *
 * TRUST SEMANTICS (the load-bearing statement):
 *   The COSE_Sign1 signature is a NEW attestation, made by whoever holds the
 *   envelope key, over the carried bytes. It is a transport/registration
 *   signature ONLY. It is NOT the approval signature and confers NO approval,
 *   authorization, or trust semantics. Approval is proven exclusively by the
 *   receipt's own signature inside the payload, verified under the relying
 *   party's pinned issuer key over exactly the payload bytes. Because the
 *   payload is the canonical JSON receipt itself, wrapping and unwrapping the
 *   envelope changes nothing the original signature covers. The alternative
 *   profile (re-signing a CBOR-mapped receipt as a first-class COSE receipt)
 *   would mint a second first-class attestation and is deliberately NOT
 *   implemented here; it is documented as future work in the profile README.
 *
 * DETERMINISTIC ENCODING (verified by experiment, recorded in the README):
 *   RFC 8949 Section 4.2.1 - shortest-form arguments, no indefinite lengths,
 *   and map keys sorted in the bytewise lexicographic order of their
 *   deterministic encodings (NOT the older RFC 7049 length-first ordering).
 *   The strict decoder REFUSES any non-deterministic encoding with the named
 *   reason `non_deterministic_encoding` instead of accepting semantically
 *   equal bytes. Both installed CBOR libraries failed this bar by experiment
 *   (`cbor` v10 truncates output on Node 26; `cbor-x` emits non-shortest map
 *   length headers), so the encoder and strict decoder are implemented here
 *   inline, keeping this package zero-dependency. The sibling McGraw adapter's
 *   `encodeDeterministicCbor` now implements the SAME RFC 8949 Section 4.2.1
 *   bytewise-encoded-key ordering (it was historically RFC 7049 length-first;
 *   that divergence lives on only as a regression test in the McGraw suite).
 *   This module still ships its own codec under distinct names because it is a
 *   Result-typed API (refusal reasons instead of throws) with its own strict
 *   decoder, not because the orderings differ.
 *
 * NOTE ON KEY ORDER ACROSS ENCODINGS: JCS sorts object keys by UTF-16 code
 * units; CBOR deterministic order sorts by the bytes of the UTF-8 encoded key.
 * These orders can differ for keys mixing U+E000..U+FFFF with supplementary
 * characters. Equivalence in this profile is at the VALUE level: each encoding
 * applies its own deterministic order, and decoding recovers the identical
 * value, so re-canonicalizing yields identical JCS bytes and an identical CAID.
 *
 * Fail-closed: malformed or hostile input returns a refusal with a reason.
 * Nothing here throws on untrusted input.
 */
import crypto from 'node:crypto';
export declare const COSE_ENCODING_PROFILE = "EP-COSE-ENCODING-v0.1";
/** The map-key ordering this profile ships (see module doc + README). */
export declare const CBOR_DETERMINISTIC_ORDER = "rfc8949-4.2.1-bytewise-encoded-key";
export declare const COSE_RECEIPT_CONTENT_TYPE = "application/emilia-receipt+json";
/** COSE alg value for EdDSA (RFC 9053 Section 2.2). */
export declare const COSE_ALG_EDDSA = -8;
/** Private (non-IANA-registered) protected-header label carrying the CAID. */
export declare const COSE_HEADER_EP_CAID = "ep.caid";
export interface CborOk<T> {
    ok: true;
    value: T;
}
export interface CborRefusal {
    ok: false;
    reason: string;
}
export type CborResult<T> = CborOk<T> | CborRefusal;
/**
 * Deterministically encode a value from the profile domain.
 * Never throws; refuses out-of-domain values with `unsupported_item`.
 */
export declare function encodeDeterministicCbor8949(value: unknown): CborResult<Uint8Array>;
/**
 * Strictly decode one deterministically encoded CBOR item.
 *
 * With `textKeysOnly: true` (the receipt mapping) maps become plain objects
 * and any non-text map key refuses. With `textKeysOnly: false` (COSE header
 * maps) maps decode to Map instances preserving integer labels.
 */
export declare function decodeDeterministicCbor8949(bytes: Uint8Array, opts?: {
    textKeysOnly?: boolean;
}): CborResult<unknown>;
/**
 * Map an EP receipt document (or any strict-JSON value) to deterministic
 * CBOR map bytes with text keys. Total over the EP canonicalization domain.
 */
export declare function receiptToCborBytes(receipt: unknown): CborResult<Uint8Array>;
/**
 * Recover the receipt value from deterministic CBOR bytes. Refuses
 * non-deterministic encodings rather than accepting semantically equal bytes.
 */
export declare function receiptFromCborBytes(bytes: Uint8Array): CborResult<unknown>;
/**
 * Compute the jcs-sha256 CAID string for a receipt action object.
 *
 * SCOPE LIMIT: this helper exists to prove ENCODING INVARIANCE of the CAID -
 * the identifier is a digest of the action's canonical JCS bytes, so it is
 * identical no matter which envelope encoding carried the receipt. It checks
 * the action_type grammar and the canonicalization domain only. Material-field
 * validation against a pinned type definition is the CAID core's job
 * (caid/impl); a caller minting production identifiers must use that.
 */
export declare function receiptActionCaid(action: unknown): CborResult<{
    caid: string;
    digest: string;
}>;
export interface BuildCoseOptions {
    /** Ed25519 private key of the ENVELOPE signer (transport leg only). */
    envelopePrivateKey: crypto.KeyObject;
    /** Key identifier placed in the protected headers (COSE label 4, bstr). */
    kid: string;
}
/**
 * Wrap an EP receipt in a deterministically encoded COSE_Sign1 (tag 18)
 * transport/registration envelope.
 *
 * payload           = UTF-8 bytes of the receipt's canonical JSON (the exact
 *                     bytes the receipt's own signature already travels with)
 * protected headers = { 1: -8 (EdDSA), 3: content type, 4: kid,
 *                       "ep.caid": jcs-sha256 CAID of receipt.payload.action }
 * signature         = Ed25519 by the ENVELOPE key over Sig_structure.
 *                     A new transport attestation; NOT the approval signature.
 */
export declare function buildReceiptCoseSign1(receipt: unknown, opts: BuildCoseOptions): CborResult<{
    cose: Uint8Array;
    payload: Uint8Array;
    protectedHeaderBytes: Uint8Array;
    caid: string;
}>;
export interface VerifyCoseOptions {
    /** SPKI-DER base64url Ed25519 public key pinned for the ENVELOPE signer. */
    envelopePublicKeyBase64url: string;
    /** SPKI-DER base64url Ed25519 public key pinned for the RECEIPT issuer. */
    receiptIssuerPublicKeyBase64url: string;
    /** Optional caller-pinned CAID; refuses on mismatch when supplied. */
    expectedCaid?: string;
    /**
     * Optional caller-pinned kid. `kid` is ALWAYS required in the envelope; when
     * this is supplied the envelope's kid must match it byte-for-byte, else the
     * envelope is refused (`kid_mismatch`).
     */
    expectedKid?: string;
}
export interface VerifyCoseResult {
    valid: boolean;
    checks: {
        deterministic_encoding: boolean;
        cose_structure: boolean;
        envelope_signature: boolean;
        payload_canonical: boolean;
        receipt_signature: boolean;
        caid_consistent: boolean;
    };
    reason?: string;
    receipt?: unknown;
    caid?: string;
    payloadSha256?: string;
}
/**
 * Verify a COSE_Sign1 transport envelope carrying an EP receipt, fail-closed.
 *
 * A `valid: true` result establishes, under the two PINNED keys the caller
 * supplied: the envelope bytes are deterministically encoded; the envelope
 * signer attested to exactly these payload bytes (transport attestation, no
 * approval semantics); the payload is the receipt's canonical JSON form; the
 * receipt verifies under its OWN signature and the pinned issuer key; and the
 * CAID in the protected headers recomputes from the carried action object.
 * It does NOT establish acceptance, authorization, execution, or currency.
 *
 * PROFILE STRICTNESS (closed profile, RFC 9052). The protected headers MUST be
 * exactly { alg (1), content type (3), kid (4), ep.caid } and nothing else;
 * an unknown protected label refuses (`unexpected_protected_header`). `kid` is
 * REQUIRED (`kid_missing`) and, when the caller pins one, must match byte-for-
 * byte (`kid_mismatch`). Any `crit` header refuses (`crit_unsupported`, RFC
 * 9052 Section 5.4: this profile marks no header critical). The unprotected
 * bucket MUST be empty (`unprotected_headers_present`); RFC 9052 Section 3
 * warns that labels duplicated across the protected and unprotected buckets are
 * an error, and the unprotected bucket is unsigned, so this profile authorizes
 * nothing from it.
 */
export declare function verifyReceiptCoseSign1(coseBytes: Uint8Array, opts: VerifyCoseOptions): VerifyCoseResult;
//# sourceMappingURL=receipt-cose-encoding.d.ts.map