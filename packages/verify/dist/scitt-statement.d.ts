/**
 * EP-SCITT-STATEMENT-v1 - a SCITT Signed Statement profile for EP receipts.
 *
 * WHAT THIS IS. RFC 9943 (SCITT architecture) Section 6 defines a Signed
 * Statement as a COSE_Sign1 whose PROTECTED header carries the CWT Claims
 * header parameter (label 15, RFC 9597 Section 2) with at least the Issuer
 * claim (1) and the Subject claim (2). This module produces exactly that
 * shape over an EP authorization receipt and verifies it fail-closed.
 *
 * The sibling module `receipt-cose-encoding.ts` (EP-COSE-ENCODING-v0.1) ships a
 * COSE_Sign1 TRANSPORT envelope for the same receipts. That envelope carries no
 * CWT Claims header, so it is not a conforming Signed Statement; its own README
 * says so and names a SCITT profile as future work. This module IS that
 * profile. It reuses that module's deterministic CBOR codec (RFC 8949 Section
 * 4.2.1) rather than re-implementing one, and adds the CWT Claims header plus
 * the subject-binding rule below.
 *
 * WHAT IT IS NOT. Producing and verifying a Signed Statement is a purely local,
 * cryptographic act. It establishes NOTHING about transparency:
 *
 *   - VERIFIED means the signatures check out under the caller's pinned keys.
 *   - REGISTERED means a Transparency Service accepted the statement into its
 *     verifiable data structure and issued a Receipt (RFC 9943 Section 6.3).
 *   - A Signed Statement plus a Receipt in the unprotected header is a
 *     TRANSPARENT Statement (RFC 9943 Section 7).
 *
 * This module produces and verifies the FIRST of those three only. It never
 * sets, reads, or asserts a registration status, and it emits no Receipt. No
 * Transparency Service has accepted a statement produced by this module.
 *
 * TWO SIGNATURES, NEVER CONFLATED. A verified statement has two independent
 * signature checks reported as two separate booleans:
 *
 *   `statement_signature` - the COSE_Sign1 signature over the RFC 9052 Section
 *     4.4 Sig_structure. This is the SCITT Issuer's attestation that it emitted
 *     these payload bytes. It is a transport/registration attestation. It
 *     confers no approval or authorization semantics whatsoever.
 *   `receipt_signature` - the EP receipt's OWN Ed25519 signature over its
 *     canonical JSON payload, verified offline under the relying party's pinned
 *     receipt-issuer key. This, and only this, is the approval evidence.
 *
 * Because the COSE payload IS the receipt's canonical JSON bytes, wrapping and
 * unwrapping the statement changes nothing the receipt signature covers.
 *
 * SUBJECT SEMANTICS. `sub` is the receipt action's CAID
 * (`caid:1:<action_type>:jcs-sha256:<digest>`), recomputed from the payload at
 * verification time and required to match. See the profile README in
 * conformance/scitt-statement/ for the argument against the alternatives.
 *
 * CWT CLAIMS AND THE PAYLOAD. RFC 9597 Section 2 requires an application that
 * sees CWT claims in BOTH the payload and the header to check they are
 * identical, "unless the application defines other specific processing rules
 * for these claims". This profile defines such a rule: the payload is an EP
 * receipt document, not a CWT, and carries no CWT claims; `iss` is checked
 * against the relying party's pin, and `sub` is checked by recomputation from
 * the payload. So the header claims are bound to the payload by construction
 * rather than by field comparison.
 *
 * Fail-closed: every path returns a named refusal. Nothing here throws on
 * untrusted input.
 */
import crypto from 'node:crypto';
import { type CborResult } from './receipt-cose-encoding.js';
export declare const EP_SCITT_STATEMENT_PROFILE = "EP-SCITT-STATEMENT-v1";
/** RFC 9943 Section 10.1: media type of the Signed Statement COSE object. */
export declare const SCITT_STATEMENT_MEDIA_TYPE = "application/scitt-statement+cose";
/** COSE protected header label 3 value: the media type of the PAYLOAD. */
export declare const EP_STATEMENT_PAYLOAD_CONTENT_TYPE = "application/emilia-receipt+json";
/** RFC 9597 Section 2, Table 1: the "CWT Claims" COSE header parameter. */
export declare const COSE_HEADER_CWT_CLAIMS = 15;
/** RFC 8392 claim labels carried inside the CWT Claims header. */
export declare const CWT_CLAIM_ISS = 1;
export declare const CWT_CLAIM_SUB = 2;
/**
 * RFC 9943 Section 6: "The iss Claim value's length MUST be between 1 and 8192
 * characters in length." That sentence is scoped to x5t/x5chain statements;
 * this profile applies it unconditionally.
 */
export declare const ISS_MIN_LENGTH = 1;
export declare const ISS_MAX_LENGTH = 8192;
/** Every refusal reason this module can return. */
export declare const EP_SCITT_REFUSALS: readonly ["invalid_receipt_document", "outside_canonical_profile", "invalid_action_object", "invalid_action_type", "invalid_kid", "invalid_iss", "invalid_signing_key", "malformed_cbor", "non_deterministic_encoding", "unsupported_item", "trailing_bytes", "duplicate_map_key", "cose_structure_invalid", "unprotected_headers_present", "crit_unsupported", "unexpected_protected_header", "unsupported_statement_alg", "content_type_mismatch", "kid_missing", "kid_mismatch", "cwt_claims_missing", "cwt_claims_malformed", "unexpected_cwt_claim", "iss_missing", "iss_malformed", "iss_mismatch", "sub_missing", "sub_malformed", "sub_mismatch", "invalid_public_key", "statement_signature_invalid", "payload_not_canonical_json", "receipt_invalid", "sub_not_bound_to_payload", "invalid_endpoint_url"];
export type EpScittRefusal = (typeof EP_SCITT_REFUSALS)[number];
export interface BuildScittStatementOptions {
    /**
     * Ed25519 private key of the SCITT Issuer (the statement signer). This is a
     * transport/registration identity. It is NOT the receipt approver key and
     * confers no approval semantics.
     */
    statementPrivateKey: crypto.KeyObject;
    /** COSE `kid` (protected label 4). Encoded as the UTF-8 bytes of this string. */
    kid: string;
    /** CWT `iss` (claim 1). URI-shaped; EP form is `ep:issuer:<name>`. */
    iss: string;
}
export interface BuiltScittStatement {
    /** The tagged COSE_Sign1 bytes: the Signed Statement. */
    statement: Uint8Array;
    /** Canonical JSON bytes of the receipt: the COSE payload. */
    payload: Uint8Array;
    /** The bstr-wrapped protected header contents (the signed header bytes). */
    protectedHeaderBytes: Uint8Array;
    iss: string;
    /** The CWT `sub` claim value, which is the action CAID. */
    sub: string;
    /** Same value as `sub`, named for callers that think in CAIDs. */
    caid: string;
    /** SHA-256 (hex) of the payload bytes. */
    payloadSha256: string;
}
/**
 * Wrap an EP receipt as an EP-SCITT-STATEMENT-v1 Signed Statement.
 *
 * Protected header (RFC 9943 Section 6.1 Figure 3):
 *   { 1: -8 (EdDSA), 3: "<payload media type>", 4: kid (bstr),
 *     15: { 1: iss, 2: sub } }
 *
 * The payload is the receipt's canonical JSON bytes, attached (not detached),
 * so the receipt's own signature keeps verifying over exactly these bytes.
 */
export declare function buildEpScittSignedStatement(receipt: unknown, opts: BuildScittStatementOptions): CborResult<BuiltScittStatement>;
export interface VerifyScittStatementOptions {
    /** SPKI-DER base64url Ed25519 public key pinned for the SCITT Issuer. */
    statementPublicKeyBase64url: string;
    /** SPKI-DER base64url Ed25519 public key pinned for the RECEIPT issuer. */
    receiptIssuerPublicKeyBase64url: string;
    /** Optional pinned `iss`; refuses `iss_mismatch` when it does not match. */
    expectedIss?: string;
    /** Optional pinned `sub`; refuses `sub_mismatch` when it does not match. */
    expectedSub?: string;
    /** Optional pinned `kid`; refuses `kid_mismatch` when it does not match. */
    expectedKid?: string;
    /**
     * Optional override for the EP receipt verifier. Defaults to the package's
     * `verifyReceipt`. Present so the profile check can be exercised against a
     * pinned receipt verifier without coupling this module's tests to the
     * package index.
     */
    receiptVerifier?: (receipt: unknown, publicKeyBase64url: string) => {
        valid?: unknown;
    };
}
export interface VerifyScittStatementResult {
    /**
     * True iff every check below passed under the caller's PINNED keys.
     *
     * `valid` means VERIFIED, never REGISTERED. It says nothing about whether any
     * Transparency Service has accepted this statement.
     */
    valid: boolean;
    checks: {
        deterministic_encoding: boolean;
        cose_structure: boolean;
        cwt_claims: boolean;
        /** The SCITT Issuer's COSE_Sign1 signature. Transport attestation only. */
        statement_signature: boolean;
        payload_canonical: boolean;
        /** The EP receipt's own signature. The approval evidence. Separate. */
        receipt_signature: boolean;
        /** `sub` recomputes from the carried payload's action object. */
        sub_binding: boolean;
    };
    reason?: string;
    /** Always false. This module never registers anything; see the module docs. */
    registered: false;
    receipt?: unknown;
    iss?: string;
    sub?: string;
    kid?: string;
    payloadSha256?: string;
}
/**
 * Verify an EP-SCITT-STATEMENT-v1 Signed Statement, fail-closed.
 *
 * A `valid: true` result establishes, under the two PINNED keys supplied:
 *  - the statement bytes are deterministically encoded (RFC 8949 4.2.1);
 *  - the COSE_Sign1 structure and protected headers match this profile exactly,
 *    including the RFC 9943 Section 6 mandatory CWT Claims header with iss and
 *    sub (RFC 9597 label 15);
 *  - the SCITT Issuer signed exactly these payload bytes (RFC 9052 4.4);
 *  - the payload IS the receipt's canonical JSON form;
 *  - the receipt verifies under its OWN signature and the pinned issuer key;
 *  - `sub` recomputes from the carried action object.
 *
 * It does NOT establish registration, transparency, acceptance under a policy,
 * authorization, execution, or currency.
 */
export declare function verifyEpScittSignedStatement(statementBytes: Uint8Array, opts: VerifyScittStatementOptions): VerifyScittStatementResult;
export interface ScittRegistrationRequest {
    method: 'POST';
    /** Absolute URL of the Transparency Service registration endpoint. */
    url: string;
    headers: Record<string, string>;
    /** The exact request body bytes: the tagged COSE_Sign1 Signed Statement. */
    body: Uint8Array;
    bodySha256: string;
    bodyBytes: number;
}
/**
 * Describe the HTTP request that WOULD register a Signed Statement with a
 * Transparency Service. This function performs no I/O of any kind: it returns a
 * description for a human to inspect and approve. Sending it is a separate,
 * explicit act.
 */
export declare function describeScittRegistrationRequest(statement: Uint8Array, endpointUrl: string): CborResult<ScittRegistrationRequest>;
//# sourceMappingURL=scitt-statement.d.ts.map