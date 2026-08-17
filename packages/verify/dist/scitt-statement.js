// SPDX-License-Identifier: Apache-2.0
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
import { canonicalize, verifyReceipt } from './index.js';
import { COSE_ALG_EDDSA, COSE_RECEIPT_CONTENT_TYPE, decodeDeterministicCbor8949, encodeDeterministicCbor8949, receiptActionCaid, } from './receipt-cose-encoding.js';
// ---------------------------------------------------------------------------
// Profile constants
// ---------------------------------------------------------------------------
export const EP_SCITT_STATEMENT_PROFILE = 'EP-SCITT-STATEMENT-v1';
/** RFC 9943 Section 10.1: media type of the Signed Statement COSE object. */
export const SCITT_STATEMENT_MEDIA_TYPE = 'application/scitt-statement+cose';
/** COSE protected header label 3 value: the media type of the PAYLOAD. */
export const EP_STATEMENT_PAYLOAD_CONTENT_TYPE = COSE_RECEIPT_CONTENT_TYPE;
/** RFC 9597 Section 2, Table 1: the "CWT Claims" COSE header parameter. */
export const COSE_HEADER_CWT_CLAIMS = 15;
/** RFC 8392 claim labels carried inside the CWT Claims header. */
export const CWT_CLAIM_ISS = 1;
export const CWT_CLAIM_SUB = 2;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_CRIT = 2;
const COSE_HEADER_CONTENT_TYPE = 3;
const COSE_HEADER_KID = 4;
const COSE_SIGN1_TAG_BYTE = 0xd2; // CBOR tag 18, shortest form
/**
 * The closed protected-header label set for this profile. RFC 9943 Section 6.1
 * Figure 3 allows `* label => any`; this profile deliberately closes the set so
 * that an unrecognized signed label is a refusal rather than something a
 * verifier silently ignores.
 */
const PROFILE_PROTECTED_LABELS = new Set([
    COSE_HEADER_ALG,
    COSE_HEADER_CONTENT_TYPE,
    COSE_HEADER_KID,
    COSE_HEADER_CWT_CLAIMS,
]);
/** The closed CWT Claims label set for this profile. */
const PROFILE_CWT_CLAIM_LABELS = new Set([
    CWT_CLAIM_ISS,
    CWT_CLAIM_SUB,
]);
/**
 * RFC 9943 Section 6: "The iss Claim value's length MUST be between 1 and 8192
 * characters in length." That sentence is scoped to x5t/x5chain statements;
 * this profile applies it unconditionally.
 */
export const ISS_MIN_LENGTH = 1;
export const ISS_MAX_LENGTH = 8192;
/** Every refusal reason this module can return. */
export const EP_SCITT_REFUSALS = [
    // build-side
    'invalid_receipt_document',
    'outside_canonical_profile',
    'invalid_action_object',
    'invalid_action_type',
    'invalid_kid',
    'invalid_iss',
    'invalid_signing_key',
    // decode-side
    'malformed_cbor',
    'non_deterministic_encoding',
    'unsupported_item',
    'trailing_bytes',
    'duplicate_map_key',
    'cose_structure_invalid',
    'unprotected_headers_present',
    'crit_unsupported',
    'unexpected_protected_header',
    'unsupported_statement_alg',
    'content_type_mismatch',
    'kid_missing',
    'kid_mismatch',
    'cwt_claims_missing',
    'cwt_claims_malformed',
    'unexpected_cwt_claim',
    'iss_missing',
    'iss_malformed',
    'iss_mismatch',
    'sub_missing',
    'sub_malformed',
    'sub_mismatch',
    'invalid_public_key',
    'statement_signature_invalid',
    'payload_not_canonical_json',
    'receipt_invalid',
    'sub_not_bound_to_payload',
    // registration-request description
    'invalid_endpoint_url',
];
const UTF8 = new TextEncoder();
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
function refuse(reason) {
    return { ok: false, reason };
}
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function compareBytes(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
        if (a[i] !== b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}
function concatBytes(parts) {
    let total = 0;
    for (const p of parts)
        total += p.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
    }
    return out;
}
/**
 * An `iss` acceptable to this profile: a URI-shaped string (RFC 3986 scheme
 * followed by a colon) of 1..8192 characters with no whitespace or control
 * characters. EP issuer identifiers use the `ep:issuer:<name>` form.
 */
function isAcceptableIss(value) {
    if (typeof value !== 'string')
        return false;
    if (value.length < ISS_MIN_LENGTH || value.length > ISS_MAX_LENGTH)
        return false;
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u0020\u007f]/.test(value))
        return false;
    return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value);
}
/** A CAID string as minted by `receiptActionCaid`. */
function isCaidString(value) {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= 4096
        && /^caid:1:[^:]+:jcs-sha256:[A-Za-z0-9_-]+$/.test(value);
}
function sigStructureBytes(protectedBytes, payload) {
    // RFC 9052 Section 4.4: Sig_structure for COSE_Sign1 is
    //   [ "Signature1", body_protected, external_aad, payload ]
    return encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(0), payload]);
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
export function buildEpScittSignedStatement(receipt, opts) {
    if (!isPlainObject(receipt) || !isPlainObject(receipt.payload)) {
        return refuse('invalid_receipt_document');
    }
    if (typeof opts?.kid !== 'string' || opts.kid.length === 0 || opts.kid.length > 1024) {
        return refuse('invalid_kid');
    }
    if (!isAcceptableIss(opts?.iss))
        return refuse('invalid_iss');
    let canonical;
    try {
        canonical = canonicalize(receipt);
    }
    catch {
        return refuse('outside_canonical_profile');
    }
    const caidResult = receiptActionCaid(receipt.payload.action);
    if (!caidResult.ok)
        return caidResult;
    const sub = caidResult.value.caid;
    const payload = UTF8.encode(canonical);
    const cwtClaims = new Map([
        [CWT_CLAIM_ISS, opts.iss],
        [CWT_CLAIM_SUB, sub],
    ]);
    const protectedMap = new Map([
        [COSE_HEADER_ALG, COSE_ALG_EDDSA],
        [COSE_HEADER_CONTENT_TYPE, EP_STATEMENT_PAYLOAD_CONTENT_TYPE],
        [COSE_HEADER_KID, UTF8.encode(opts.kid)],
        [COSE_HEADER_CWT_CLAIMS, cwtClaims],
    ]);
    const protectedEncoded = encodeDeterministicCbor8949(protectedMap);
    if (!protectedEncoded.ok)
        return protectedEncoded;
    const sigStruct = sigStructureBytes(protectedEncoded.value, payload);
    if (!sigStruct.ok)
        return sigStruct;
    let signature;
    try {
        const key = opts.statementPrivateKey;
        if (!(key instanceof crypto.KeyObject) || key.asymmetricKeyType !== 'ed25519') {
            return refuse('invalid_signing_key');
        }
        signature = new Uint8Array(crypto.sign(null, sigStruct.value, key));
    }
    catch {
        return refuse('invalid_signing_key');
    }
    // Unprotected header is an EMPTY map at build time. RFC 9943 Section 6.3
    // requires the unprotected header of a Signed Statement to be set to an empty
    // map before it can be included in a Statement Sequence, and Section 7 uses
    // that bucket for Receipts (label 394) only AFTER registration.
    const body = encodeDeterministicCbor8949([
        protectedEncoded.value,
        new Map(),
        payload,
        signature,
    ]);
    if (!body.ok)
        return body;
    return {
        ok: true,
        value: {
            statement: concatBytes([Uint8Array.of(COSE_SIGN1_TAG_BYTE), body.value]),
            payload,
            protectedHeaderBytes: protectedEncoded.value,
            iss: opts.iss,
            sub,
            caid: sub,
            payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
        },
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
export function verifyEpScittSignedStatement(statementBytes, opts) {
    const checks = {
        deterministic_encoding: false,
        cose_structure: false,
        cwt_claims: false,
        statement_signature: false,
        payload_canonical: false,
        receipt_signature: false,
        sub_binding: false,
    };
    const fail = (reason) => ({ valid: false, checks, reason, registered: false });
    if (!(statementBytes instanceof Uint8Array) || statementBytes.length < 2) {
        return fail('malformed_cbor');
    }
    if (statementBytes[0] !== COSE_SIGN1_TAG_BYTE)
        return fail('cose_structure_invalid');
    const decoded = decodeDeterministicCbor8949(statementBytes.subarray(1), { textKeysOnly: false });
    if (!decoded.ok)
        return fail(decoded.reason);
    checks.deterministic_encoding = true;
    const arr = decoded.value;
    if (!Array.isArray(arr) || arr.length !== 4)
        return fail('cose_structure_invalid');
    const [protectedBytes, unprotected, payload, signature] = arr;
    if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array)
        || !(signature instanceof Uint8Array) || !(unprotected instanceof Map)) {
        return fail('cose_structure_invalid');
    }
    // The unprotected bucket must be empty. RFC 9052 Section 3 makes a label in
    // BOTH buckets an error, and the bucket is unsigned. A registered statement
    // gains Receipts here (RFC 9943 Section 7, label 394) and becomes a
    // TRANSPARENT Statement, which is a different artifact this profile does not
    // verify: refusing here keeps the two from being mistaken for each other.
    if (unprotected.size !== 0)
        return fail('unprotected_headers_present');
    const headerResult = decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false });
    if (!headerResult.ok)
        return fail(headerResult.reason);
    if (!(headerResult.value instanceof Map))
        return fail('cose_structure_invalid');
    const headers = headerResult.value;
    // RFC 9052 Section 5.4 `crit`: every listed label must be understood. This is
    // a closed profile that marks nothing critical, so any `crit` names a label
    // this verifier does not understand.
    if (headers.has(COSE_HEADER_CRIT))
        return fail('crit_unsupported');
    for (const label of headers.keys()) {
        if (!PROFILE_PROTECTED_LABELS.has(label))
            return fail('unexpected_protected_header');
    }
    // `alg` is checked BEFORE any signature work: this closes algorithm
    // confusion, where an attacker swaps the declared algorithm and hopes the
    // verifier dispatches on the key instead of on the signed header.
    if (headers.get(COSE_HEADER_ALG) !== COSE_ALG_EDDSA)
        return fail('unsupported_statement_alg');
    if (headers.get(COSE_HEADER_CONTENT_TYPE) !== EP_STATEMENT_PAYLOAD_CONTENT_TYPE) {
        return fail('content_type_mismatch');
    }
    // RFC 9943 Section 6: "The kid header parameter MUST be present when neither
    // x5t nor x5chain is present in the protected header." This profile carries
    // neither, so kid is mandatory.
    const headerKid = headers.get(COSE_HEADER_KID);
    if (!(headerKid instanceof Uint8Array) || headerKid.length === 0)
        return fail('kid_missing');
    if (typeof opts?.expectedKid === 'string') {
        if (compareBytes(headerKid, UTF8.encode(opts.expectedKid)) !== 0)
            return fail('kid_mismatch');
    }
    let kidText;
    try {
        kidText = FATAL_UTF8.decode(headerKid);
    }
    catch {
        return fail('kid_missing');
    }
    checks.cose_structure = true;
    // RFC 9943 Section 6: "The protected header of a Signed Statement and a
    // Receipt MUST include the CWT Claims header parameter as specified in
    // Section 2 of [RFC9597]. The CWT Claims value MUST include the Issuer Claim
    // (Claim label 1) and the Subject Claim (Claim label 2)."
    if (!headers.has(COSE_HEADER_CWT_CLAIMS))
        return fail('cwt_claims_missing');
    const cwt = headers.get(COSE_HEADER_CWT_CLAIMS);
    if (!(cwt instanceof Map))
        return fail('cwt_claims_malformed');
    for (const label of cwt.keys()) {
        if (!PROFILE_CWT_CLAIM_LABELS.has(label))
            return fail('unexpected_cwt_claim');
    }
    if (!cwt.has(CWT_CLAIM_ISS))
        return fail('iss_missing');
    if (!cwt.has(CWT_CLAIM_SUB))
        return fail('sub_missing');
    const iss = cwt.get(CWT_CLAIM_ISS);
    const sub = cwt.get(CWT_CLAIM_SUB);
    if (!isAcceptableIss(iss))
        return fail('iss_malformed');
    if (!isCaidString(sub))
        return fail('sub_malformed');
    if (typeof opts?.expectedIss === 'string' && opts.expectedIss !== iss)
        return fail('iss_mismatch');
    if (typeof opts?.expectedSub === 'string' && opts.expectedSub !== sub)
        return fail('sub_mismatch');
    checks.cwt_claims = true;
    // ---- Signature leg 1 of 2: the SCITT Issuer's statement signature. --------
    let statementKey;
    try {
        const raw = opts?.statementPublicKeyBase64url;
        if (typeof raw !== 'string' || raw.length === 0 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
            return fail('invalid_public_key');
        }
        const der = Buffer.from(raw, 'base64url');
        if (der.toString('base64url') !== raw)
            return fail('invalid_public_key');
        statementKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (statementKey.asymmetricKeyType !== 'ed25519')
            return fail('invalid_public_key');
    }
    catch {
        return fail('invalid_public_key');
    }
    const sigStruct = sigStructureBytes(protectedBytes, payload);
    if (!sigStruct.ok)
        return fail(sigStruct.reason);
    let statementSigOk = false;
    try {
        statementSigOk = crypto.verify(null, sigStruct.value, statementKey, signature);
    }
    catch {
        statementSigOk = false;
    }
    if (!statementSigOk)
        return fail('statement_signature_invalid');
    checks.statement_signature = true;
    // ---- The payload must BE canonical JSON, byte for byte. ------------------
    let payloadText;
    try {
        payloadText = FATAL_UTF8.decode(payload);
    }
    catch {
        return fail('payload_not_canonical_json');
    }
    let receipt;
    try {
        receipt = JSON.parse(payloadText);
    }
    catch {
        return fail('payload_not_canonical_json');
    }
    let recanonical;
    try {
        recanonical = canonicalize(receipt);
    }
    catch {
        return fail('payload_not_canonical_json');
    }
    if (recanonical !== payloadText)
        return fail('payload_not_canonical_json');
    checks.payload_canonical = true;
    // ---- Signature leg 2 of 2: the EP receipt's OWN signature. ---------------
    // Deliberately separate from leg 1. A relying party that trusts the SCITT
    // Issuer key learns only that the statement was emitted; approval evidence
    // comes from here and nowhere else.
    const verifier = typeof opts?.receiptVerifier === 'function' ? opts.receiptVerifier : verifyReceipt;
    let receiptResult;
    try {
        receiptResult = verifier(receipt, opts?.receiptIssuerPublicKeyBase64url);
    }
    catch {
        return fail('receipt_invalid');
    }
    if (receiptResult?.valid !== true)
        return fail('receipt_invalid');
    checks.receipt_signature = true;
    // ---- `sub` is bound to the payload by recomputation, not by assertion. ---
    const recomputed = receiptActionCaid(receipt?.payload?.action);
    if (!recomputed.ok)
        return fail('sub_not_bound_to_payload');
    if (recomputed.value.caid !== sub)
        return fail('sub_not_bound_to_payload');
    checks.sub_binding = true;
    return {
        valid: true,
        checks,
        registered: false,
        receipt,
        iss,
        sub,
        kid: kidText,
        payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
    };
}
/**
 * Describe the HTTP request that WOULD register a Signed Statement with a
 * Transparency Service. This function performs no I/O of any kind: it returns a
 * description for a human to inspect and approve. Sending it is a separate,
 * explicit act.
 */
export function describeScittRegistrationRequest(statement, endpointUrl) {
    if (!(statement instanceof Uint8Array) || statement.length === 0) {
        return refuse('cose_structure_invalid');
    }
    if (typeof endpointUrl !== 'string' || !/^https:\/\/[^\s]+$/.test(endpointUrl)) {
        return refuse('invalid_endpoint_url');
    }
    return {
        ok: true,
        value: {
            method: 'POST',
            url: endpointUrl,
            headers: {
                // SCRAPI submits the COSE object itself; RFC 9943 Section 10.1
                // registers the more specific media type for a Signed Statement.
                'Content-Type': SCITT_STATEMENT_MEDIA_TYPE,
                Accept: 'application/json, application/cbor',
            },
            body: statement,
            bodySha256: crypto.createHash('sha256').update(statement).digest('hex'),
            bodyBytes: statement.length,
        },
    };
}
//# sourceMappingURL=scitt-statement.js.map