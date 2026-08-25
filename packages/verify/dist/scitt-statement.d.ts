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
import { type AgilityOptions } from './pq-signature-agility.js';
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
/**
 * Three identities that MUST NOT be substituted for one another.
 *
 * `statement_entry_digest` names the exact COSE_Sign1 envelope bytes. A
 * signature normalization or a second valid randomized signature changes it.
 * `signing_input_digest` names the RFC 9052 Sig_structure and is unchanged
 * when only the signature bytes change. `authorization_payload_digest` is an
 * EP-specific logical identity over a canonical receipt payload. The generic
 * analyzer intentionally leaves it absent: JSON shape alone cannot establish
 * that bytes are an EP receipt. `verifyEpScittSignedStatement` adds it only
 * after the complete profile and both signature legs verify.
 */
export interface ScittStatementIdentityLayers {
    statement_entry_digest: string;
    signing_input_digest: string;
    statement_payload_digest: string;
    authorization_payload_digest?: string;
}
/**
 * Derive identity layers from a deterministically encoded COSE_Sign1 object.
 *
 * This function verifies neither the COSE signature nor authorization. It is
 * deliberately an identity analyzer. Callers still MUST verify the relevant
 * signature, issuer, profile, and relying-party policy before relying on any
 * layer.
 */
export declare function deriveScittStatementIdentityLayers(statementBytes: Uint8Array): CborResult<ScittStatementIdentityLayers>;
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
    /** Identity layers, kept separate so entry identity cannot mint authority. */
    identity?: ScittStatementIdentityLayers & {
        authorization_payload_digest: string;
    };
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
/**
 * ALGORITHM IDENTIFIER PROVENANCE. `COSE_ALG_ML_DSA_65` is imported from
 * `receipt-cose-encoding.ts`, which traces it to
 * `packages/verify/src/aeb-mcgraw-delegation-adapter.ts`
 * (`MCGRAW_BUDGET_COSE_ALGORITHM = -49`, "RFC 9964 COSE Algorithms registry
 * value for ML-DSA-65") -- a value this repository already verifies foreign
 * COSE_Sign1 objects under. Nothing here is recalled from memory or invented.
 *
 * WHY A PAIR. RFC 9943 Section 6 defines a Signed Statement as a COSE_Sign1,
 * which carries exactly one signature. The multi-signer COSE container
 * (COSE_Sign) has no definition anywhere in this repository, so it is not
 * hand-rolled here. v2 is therefore an EP-DEFINED PAIRING of two individually
 * conforming Signed Statements over the SAME payload, one per registered
 * algorithm, each carrying the required set in a PROTECTED header. RFC 9943
 * Section 6.1 Figure 3 permits additional protected labels (`* label => any`),
 * so each half remains a conforming Signed Statement in its own right.
 *
 * THE COORDINATION BOUNDARY, STATED PLAINLY AND NOT SMOOTHED OVER. A
 * Transparency Service registers ONE Signed Statement. Register one half of a
 * v2 pair and the resulting Receipt covers that half only; there is no
 * transparency mechanism here that carries the pairing. The hybrid property is
 * a RELYING-PARTY pin evaluated by verifyEpScittSignedStatementHybrid over both
 * halves, and it does not survive a round trip through a Transparency Service.
 * Making it survive requires a SCITT-side profile that this repository cannot
 * define unilaterally.
 *
 * The five moves are identical to EP-COSE-ENCODING-v0.2:
 *   1. VERSION BUMP. New profile marker; `verifyEpScittSignedStatement` is
 *      UNTOUCHED and refuses either half with `unexpected_protected_header`
 *      (its closed label set has no `ep.required_algs`) before any signature
 *      work. Asserted by test.
 *   2. SET SHAPE. COSE algorithm VALUES [-8, -49] in registered order.
 *   3. ANTI-STRIPPING BYTES. The set is a protected header in BOTH halves, so
 *      it is inside each Sig_structure; the verifier rebuilds both expected
 *      protected headers from the REGISTERED set, the pinned kid, the pinned
 *      iss, and the `sub` it recomputed from the payload, and requires byte
 *      equality.
 *   4. V1 COMPATIBILITY. The v1 builder and verifier stay synchronous and
 *      unchanged; v2 is a separate async entry point.
 *   5. NAMED REFUSALS. Every path returns a named reason; nothing throws on
 *      untrusted input; a missing ML-DSA backend refuses.
 *
 * WHAT IT IS STILL NOT. `valid: true` means VERIFIED, never REGISTERED. Both
 * statement signatures are transport/registration attestations. The EP
 * receipt's own approval signature inside the payload is Ed25519 only, so a v2
 * pair does not make the carried receipt post-quantum protected. Opt-in; not
 * deployed, default, or certified.
 */
export declare const EP_SCITT_STATEMENT_HYBRID_PROFILE = "EP-SCITT-STATEMENT-v2";
/** The registered required COSE algorithm set, in canonical order. */
export declare const EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS: readonly [-8, -49];
/** Every refusal reason the v2 entry points add on top of EP_SCITT_REFUSALS. */
export declare const EP_SCITT_V2_REFUSALS: readonly ["hybrid_pair_incomplete", "hybrid_payload_mismatch", "algorithm_set_mismatch", "protected_header_mismatch", "pq_backend_unavailable", "invalid_pq_signing_key", "invalid_pq_public_key"];
/** The protected header of one half of a v2 pair; the set is a signed member. */
export declare function epScittV2ProtectedHeader(alg: number, kid: string, iss: string, sub: string, requiredAlgorithms?: readonly number[]): Map<unknown, unknown>;
export interface BuildScittHybridOptions extends BuildScittStatementOptions {
    /** ML-DSA-65 raw 4032-byte secret key of the SCITT Issuer, or base64url. */
    statementPqSecretKey: Uint8Array | string;
}
export interface BuiltScittHybridPair {
    /** Tagged COSE_Sign1 Signed Statement, alg -8 (EdDSA). */
    classical: Uint8Array;
    /** Tagged COSE_Sign1 Signed Statement, alg -49 (ML-DSA-65). */
    pq: Uint8Array;
    payload: Uint8Array;
    iss: string;
    sub: string;
    caid: string;
    payloadSha256: string;
}
/** Build an EP-SCITT-STATEMENT-v2 hybrid Signed Statement pair. */
export declare function buildEpScittHybridSignedStatement(receipt: unknown, opts: BuildScittHybridOptions, agility?: AgilityOptions): Promise<CborResult<BuiltScittHybridPair>>;
export interface VerifyScittHybridOptions {
    /** SPKI-DER base64url Ed25519 public key pinned for the SCITT Issuer. */
    statementPublicKeyBase64url: string;
    /** base64url raw 1952-byte ML-DSA-65 public key pinned for the SCITT Issuer. */
    statementPqPublicKeyBase64url: string;
    /** SPKI-DER base64url Ed25519 public key pinned for the RECEIPT issuer. */
    receiptIssuerPublicKeyBase64url: string;
    /** REQUIRED in v2: both halves must carry exactly this iss. */
    expectedIss: string;
    /** REQUIRED in v2: both halves must carry exactly this kid. */
    expectedKid: string;
    expectedSub?: string;
    receiptVerifier?: (receipt: unknown, publicKeyBase64url: string) => {
        valid?: unknown;
    };
    agility?: AgilityOptions;
}
export interface VerifyScittHybridResult {
    valid: boolean;
    checks: {
        pair_present: boolean;
        deterministic_encoding: boolean;
        cose_structure: boolean;
        algorithm_set: boolean;
        payload_identical: boolean;
        cwt_claims: boolean;
        statement_signatures: boolean;
        payload_canonical: boolean;
        receipt_signature: boolean;
        sub_binding: boolean;
    };
    reason?: string;
    /** Always false. This module never registers anything. */
    registered: false;
    receipt?: unknown;
    iss?: string;
    sub?: string;
    payloadSha256?: string;
}
/**
 * Verify an EP-SCITT-STATEMENT-v2 hybrid Signed Statement pair, fail-closed.
 * `valid: true` still means VERIFIED, never REGISTERED, and the pairing is a
 * relying-party pin that no Transparency Service conveys.
 */
export declare function verifyEpScittSignedStatementHybrid(pair: {
    classical?: unknown;
    pq?: unknown;
} | null | undefined, opts: VerifyScittHybridOptions): Promise<VerifyScittHybridResult>;
//# sourceMappingURL=scitt-statement.d.ts.map