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
import {
  signAgile,
  verifyAgileSignature,
  type AgilityOptions,
} from './pq-signature-agility.js';
import {
  COSE_ALG_EDDSA,
  COSE_ALG_ML_DSA_65,
  COSE_HEADER_EP_REQUIRED_ALGS,
  COSE_RECEIPT_CONTENT_TYPE,
  decodeDeterministicCbor8949,
  encodeDeterministicCbor8949,
  receiptActionCaid,
  type CborResult,
} from './receipt-cose-encoding.js';

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
const PROFILE_PROTECTED_LABELS: ReadonlySet<unknown> = new Set<unknown>([
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
  COSE_HEADER_CWT_CLAIMS,
]);

/** The closed CWT Claims label set for this profile. */
const PROFILE_CWT_CLAIM_LABELS: ReadonlySet<unknown> = new Set<unknown>([
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
] as const;

export type EpScittRefusal = (typeof EP_SCITT_REFUSALS)[number];

const UTF8 = new TextEncoder();
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });

function refuse(reason: EpScittRefusal): { ok: false; reason: string } {
  return { ok: false, reason };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

/**
 * An `iss` acceptable to this profile: a URI-shaped string (RFC 3986 scheme
 * followed by a colon) of 1..8192 characters with no whitespace or control
 * characters. EP issuer identifiers use the `ep:issuer:<name>` form.
 */
function isAcceptableIss(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length < ISS_MIN_LENGTH || value.length > ISS_MAX_LENGTH) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0020\u007f]/.test(value)) return false;
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value);
}

/** A CAID string as minted by `receiptActionCaid`. */
function isCaidString(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 4096
    && /^caid:1:[^:]+:jcs-sha256:[A-Za-z0-9_-]+$/.test(value);
}

function sigStructureBytes(
  protectedBytes: Uint8Array,
  payload: Uint8Array,
): CborResult<Uint8Array> {
  // RFC 9052 Section 4.4: Sig_structure for COSE_Sign1 is
  //   [ "Signature1", body_protected, external_aad, payload ]
  return encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(0), payload]);
}

function sha256Digest(bytes: Uint8Array | string): string {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Three identities that MUST NOT be substituted for one another.
 *
 * `statement_entry_digest` names the exact COSE_Sign1 envelope bytes. A
 * signature normalization or a second valid randomized signature changes it.
 * `signing_input_digest` names the RFC 9052 Sig_structure and is unchanged
 * when only the signature bytes change. `authorization_payload_digest` is an
 * EP-specific logical identity over the canonical receipt payload. It is
 * present only when the COSE payload is a canonical EP-style receipt document.
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
export function deriveScittStatementIdentityLayers(
  statementBytes: Uint8Array,
): CborResult<ScittStatementIdentityLayers> {
  if (!(statementBytes instanceof Uint8Array) || statementBytes.length < 2) {
    return { ok: false, reason: 'malformed_cbor' };
  }
  if (statementBytes[0] !== COSE_SIGN1_TAG_BYTE) {
    return { ok: false, reason: 'cose_structure_invalid' };
  }
  const decoded = decodeDeterministicCbor8949(statementBytes.subarray(1), {
    textKeysOnly: false,
  });
  if (!decoded.ok) return decoded;
  if (!Array.isArray(decoded.value) || decoded.value.length !== 4) {
    return { ok: false, reason: 'cose_structure_invalid' };
  }
  const [protectedBytes, unprotected, payload, signature] = decoded.value as unknown[];
  if (!(protectedBytes instanceof Uint8Array)
      || !(unprotected instanceof Map)
      || !(payload instanceof Uint8Array)
      || !(signature instanceof Uint8Array)) {
    return { ok: false, reason: 'cose_structure_invalid' };
  }
  const sigStruct = sigStructureBytes(protectedBytes, payload);
  if (!sigStruct.ok) return sigStruct;

  const value: ScittStatementIdentityLayers = {
    statement_entry_digest: sha256Digest(statementBytes),
    signing_input_digest: sha256Digest(sigStruct.value),
    statement_payload_digest: sha256Digest(payload),
  };

  try {
    const payloadText = FATAL_UTF8.decode(payload);
    const document = JSON.parse(payloadText);
    if (isPlainObject(document) && isPlainObject(document.payload)
        && canonicalize(document) === payloadText) {
      value.authorization_payload_digest = sha256Digest(canonicalize(document.payload));
    }
  } catch {
    // Generic SCITT statements need not carry JSON or EP receipts. The three
    // generic identity layers above remain valid without an EP authorization
    // payload identity.
  }
  return { ok: true, value };
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

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
export function buildEpScittSignedStatement(
  receipt: unknown,
  opts: BuildScittStatementOptions,
): CborResult<BuiltScittStatement> {
  if (!isPlainObject(receipt) || !isPlainObject(receipt.payload)) {
    return refuse('invalid_receipt_document');
  }
  if (typeof opts?.kid !== 'string' || opts.kid.length === 0 || opts.kid.length > 1024) {
    return refuse('invalid_kid');
  }
  if (!isAcceptableIss(opts?.iss)) return refuse('invalid_iss');

  let canonical: string;
  try {
    canonical = canonicalize(receipt);
  } catch {
    return refuse('outside_canonical_profile');
  }

  const caidResult = receiptActionCaid(receipt.payload.action);
  if (!caidResult.ok) return caidResult;
  const sub = caidResult.value.caid;

  const payload = UTF8.encode(canonical);

  const cwtClaims = new Map<unknown, unknown>([
    [CWT_CLAIM_ISS, opts.iss],
    [CWT_CLAIM_SUB, sub],
  ]);
  const protectedMap = new Map<unknown, unknown>([
    [COSE_HEADER_ALG, COSE_ALG_EDDSA],
    [COSE_HEADER_CONTENT_TYPE, EP_STATEMENT_PAYLOAD_CONTENT_TYPE],
    [COSE_HEADER_KID, UTF8.encode(opts.kid)],
    [COSE_HEADER_CWT_CLAIMS, cwtClaims],
  ]);

  const protectedEncoded = encodeDeterministicCbor8949(protectedMap);
  if (!protectedEncoded.ok) return protectedEncoded;

  const sigStruct = sigStructureBytes(protectedEncoded.value, payload);
  if (!sigStruct.ok) return sigStruct;

  let signature: Uint8Array;
  try {
    const key = opts.statementPrivateKey;
    if (!(key instanceof crypto.KeyObject) || key.asymmetricKeyType !== 'ed25519') {
      return refuse('invalid_signing_key');
    }
    signature = new Uint8Array(crypto.sign(null, sigStruct.value, key));
  } catch {
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
  if (!body.ok) return body;

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

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

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
  receiptVerifier?: (receipt: unknown, publicKeyBase64url: string) => { valid?: unknown };
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
  identity?: ScittStatementIdentityLayers & { authorization_payload_digest: string };
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
export function verifyEpScittSignedStatement(
  statementBytes: Uint8Array,
  opts: VerifyScittStatementOptions,
): VerifyScittStatementResult {
  const checks: VerifyScittStatementResult['checks'] = {
    deterministic_encoding: false,
    cose_structure: false,
    cwt_claims: false,
    statement_signature: false,
    payload_canonical: false,
    receipt_signature: false,
    sub_binding: false,
  };
  const fail = (reason: string): VerifyScittStatementResult =>
    ({ valid: false, checks, reason, registered: false });

  if (!(statementBytes instanceof Uint8Array) || statementBytes.length < 2) {
    return fail('malformed_cbor');
  }
  if (statementBytes[0] !== COSE_SIGN1_TAG_BYTE) return fail('cose_structure_invalid');

  const decoded = decodeDeterministicCbor8949(statementBytes.subarray(1), { textKeysOnly: false });
  if (!decoded.ok) return fail(decoded.reason);
  checks.deterministic_encoding = true;

  const arr = decoded.value;
  if (!Array.isArray(arr) || arr.length !== 4) return fail('cose_structure_invalid');
  const [protectedBytes, unprotected, payload, signature] = arr as unknown[];
  if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array)
      || !(signature instanceof Uint8Array) || !(unprotected instanceof Map)) {
    return fail('cose_structure_invalid');
  }
  // The unprotected bucket must be empty. RFC 9052 Section 3 makes a label in
  // BOTH buckets an error, and the bucket is unsigned. A registered statement
  // gains Receipts here (RFC 9943 Section 7, label 394) and becomes a
  // TRANSPARENT Statement, which is a different artifact this profile does not
  // verify: refusing here keeps the two from being mistaken for each other.
  if (unprotected.size !== 0) return fail('unprotected_headers_present');

  const headerResult = decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false });
  if (!headerResult.ok) return fail(headerResult.reason);
  if (!(headerResult.value instanceof Map)) return fail('cose_structure_invalid');
  const headers = headerResult.value;

  // RFC 9052 Section 5.4 `crit`: every listed label must be understood. This is
  // a closed profile that marks nothing critical, so any `crit` names a label
  // this verifier does not understand.
  if (headers.has(COSE_HEADER_CRIT)) return fail('crit_unsupported');

  for (const label of headers.keys()) {
    if (!PROFILE_PROTECTED_LABELS.has(label)) return fail('unexpected_protected_header');
  }

  // `alg` is checked BEFORE any signature work: this closes algorithm
  // confusion, where an attacker swaps the declared algorithm and hopes the
  // verifier dispatches on the key instead of on the signed header.
  if (headers.get(COSE_HEADER_ALG) !== COSE_ALG_EDDSA) return fail('unsupported_statement_alg');
  if (headers.get(COSE_HEADER_CONTENT_TYPE) !== EP_STATEMENT_PAYLOAD_CONTENT_TYPE) {
    return fail('content_type_mismatch');
  }

  // RFC 9943 Section 6: "The kid header parameter MUST be present when neither
  // x5t nor x5chain is present in the protected header." This profile carries
  // neither, so kid is mandatory.
  const headerKid = headers.get(COSE_HEADER_KID);
  if (!(headerKid instanceof Uint8Array) || headerKid.length === 0) return fail('kid_missing');
  if (typeof opts?.expectedKid === 'string') {
    if (compareBytes(headerKid, UTF8.encode(opts.expectedKid)) !== 0) return fail('kid_mismatch');
  }
  let kidText: string;
  try {
    kidText = FATAL_UTF8.decode(headerKid);
  } catch {
    return fail('kid_missing');
  }
  checks.cose_structure = true;

  // RFC 9943 Section 6: "The protected header of a Signed Statement and a
  // Receipt MUST include the CWT Claims header parameter as specified in
  // Section 2 of [RFC9597]. The CWT Claims value MUST include the Issuer Claim
  // (Claim label 1) and the Subject Claim (Claim label 2)."
  if (!headers.has(COSE_HEADER_CWT_CLAIMS)) return fail('cwt_claims_missing');
  const cwt = headers.get(COSE_HEADER_CWT_CLAIMS);
  if (!(cwt instanceof Map)) return fail('cwt_claims_malformed');
  for (const label of cwt.keys()) {
    if (!PROFILE_CWT_CLAIM_LABELS.has(label)) return fail('unexpected_cwt_claim');
  }
  if (!cwt.has(CWT_CLAIM_ISS)) return fail('iss_missing');
  if (!cwt.has(CWT_CLAIM_SUB)) return fail('sub_missing');
  const iss = cwt.get(CWT_CLAIM_ISS);
  const sub = cwt.get(CWT_CLAIM_SUB);
  if (!isAcceptableIss(iss)) return fail('iss_malformed');
  if (!isCaidString(sub)) return fail('sub_malformed');
  if (typeof opts?.expectedIss === 'string' && opts.expectedIss !== iss) return fail('iss_mismatch');
  if (typeof opts?.expectedSub === 'string' && opts.expectedSub !== sub) return fail('sub_mismatch');
  checks.cwt_claims = true;

  // ---- Signature leg 1 of 2: the SCITT Issuer's statement signature. --------
  let statementKey: crypto.KeyObject;
  try {
    const raw = opts?.statementPublicKeyBase64url;
    if (typeof raw !== 'string' || raw.length === 0 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
      return fail('invalid_public_key');
    }
    const der = Buffer.from(raw, 'base64url');
    if (der.toString('base64url') !== raw) return fail('invalid_public_key');
    statementKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (statementKey.asymmetricKeyType !== 'ed25519') return fail('invalid_public_key');
  } catch {
    return fail('invalid_public_key');
  }

  const sigStruct = sigStructureBytes(protectedBytes, payload);
  if (!sigStruct.ok) return fail(sigStruct.reason);
  let statementSigOk = false;
  try {
    statementSigOk = crypto.verify(null, sigStruct.value, statementKey, signature);
  } catch {
    statementSigOk = false;
  }
  if (!statementSigOk) return fail('statement_signature_invalid');
  checks.statement_signature = true;

  // ---- The payload must BE canonical JSON, byte for byte. ------------------
  let payloadText: string;
  try {
    payloadText = FATAL_UTF8.decode(payload);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let receipt: unknown;
  try {
    receipt = JSON.parse(payloadText);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let recanonical: string;
  try {
    recanonical = canonicalize(receipt);
  } catch {
    return fail('payload_not_canonical_json');
  }
  if (recanonical !== payloadText) return fail('payload_not_canonical_json');
  checks.payload_canonical = true;

  // ---- Signature leg 2 of 2: the EP receipt's OWN signature. ---------------
  // Deliberately separate from leg 1. A relying party that trusts the SCITT
  // Issuer key learns only that the statement was emitted; approval evidence
  // comes from here and nowhere else.
  const verifier = typeof opts?.receiptVerifier === 'function' ? opts.receiptVerifier : verifyReceipt;
  let receiptResult: { valid?: unknown };
  try {
    receiptResult = verifier(receipt, opts?.receiptIssuerPublicKeyBase64url);
  } catch {
    return fail('receipt_invalid');
  }
  if (receiptResult?.valid !== true) return fail('receipt_invalid');
  checks.receipt_signature = true;

  // ---- `sub` is bound to the payload by recomputation, not by assertion. ---
  const recomputed = receiptActionCaid((receipt as Record<string, any>)?.payload?.action);
  if (!recomputed.ok) return fail('sub_not_bound_to_payload');
  if (recomputed.value.caid !== sub) return fail('sub_not_bound_to_payload');
  checks.sub_binding = true;

  const identity = deriveScittStatementIdentityLayers(statementBytes);
  if (!identity.ok || typeof identity.value.authorization_payload_digest !== 'string') {
    return fail('receipt_invalid');
  }

  return {
    valid: true,
    checks,
    registered: false,
    receipt,
    iss,
    sub,
    kid: kidText,
    payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
    identity: identity.value as ScittStatementIdentityLayers & {
      authorization_payload_digest: string;
    },
  };
}

// ---------------------------------------------------------------------------
// Registration request description (built, never sent)
// ---------------------------------------------------------------------------

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
export function describeScittRegistrationRequest(
  statement: Uint8Array,
  endpointUrl: string,
): CborResult<ScittRegistrationRequest> {
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

// ===========================================================================
// EP-SCITT-STATEMENT-v2 -- the hybrid (EdDSA + ML-DSA-65) Signed Statement pair
// ===========================================================================
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

export const EP_SCITT_STATEMENT_HYBRID_PROFILE = 'EP-SCITT-STATEMENT-v2';

/** The registered required COSE algorithm set, in canonical order. */
export const EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS = Object.freeze([
  COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65,
] as const);

const V2_PROFILE_PROTECTED_LABELS: ReadonlySet<unknown> = new Set<unknown>([
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
  COSE_HEADER_CWT_CLAIMS,
  COSE_HEADER_EP_REQUIRED_ALGS,
]);

/** Every refusal reason the v2 entry points add on top of EP_SCITT_REFUSALS. */
export const EP_SCITT_V2_REFUSALS = [
  'hybrid_pair_incomplete',
  'hybrid_payload_mismatch',
  'algorithm_set_mismatch',
  'protected_header_mismatch',
  'pq_backend_unavailable',
  'invalid_pq_signing_key',
  'invalid_pq_public_key',
] as const;

function scittV2SetMatchesRegistered(algorithms: unknown): algorithms is number[] {
  return Array.isArray(algorithms)
    && algorithms.length === EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS[i]);
}

/** The protected header of one half of a v2 pair; the set is a signed member. */
export function epScittV2ProtectedHeader(
  alg: number,
  kid: string,
  iss: string,
  sub: string,
  requiredAlgorithms: readonly number[] = EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS,
): Map<unknown, unknown> {
  if (!scittV2SetMatchesRegistered(requiredAlgorithms)) {
    throw new Error('epScittV2ProtectedHeader: algorithm set is not the registered EP-SCITT-STATEMENT-v2 set');
  }
  return new Map<unknown, unknown>([
    [COSE_HEADER_ALG, alg],
    [COSE_HEADER_CONTENT_TYPE, EP_STATEMENT_PAYLOAD_CONTENT_TYPE],
    [COSE_HEADER_KID, UTF8.encode(kid)],
    [COSE_HEADER_CWT_CLAIMS, new Map<unknown, unknown>([
      [CWT_CLAIM_ISS, iss],
      [CWT_CLAIM_SUB, sub],
    ])],
    [COSE_HEADER_EP_REQUIRED_ALGS, [...requiredAlgorithms]],
  ]);
}

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
export async function buildEpScittHybridSignedStatement(
  receipt: unknown,
  opts: BuildScittHybridOptions,
  agility: AgilityOptions = {},
): Promise<CborResult<BuiltScittHybridPair>> {
  if (!isPlainObject(receipt) || !isPlainObject(receipt.payload)) {
    return refuse('invalid_receipt_document');
  }
  if (typeof opts?.kid !== 'string' || opts.kid.length === 0 || opts.kid.length > 1024) {
    return refuse('invalid_kid');
  }
  if (!isAcceptableIss(opts?.iss)) return refuse('invalid_iss');
  const key = opts?.statementPrivateKey;
  if (!(key instanceof crypto.KeyObject) || key.asymmetricKeyType !== 'ed25519') {
    return refuse('invalid_signing_key');
  }

  let canonical: string;
  try {
    canonical = canonicalize(receipt);
  } catch {
    return refuse('outside_canonical_profile');
  }
  const caidResult = receiptActionCaid(receipt.payload.action);
  if (!caidResult.ok) return caidResult;
  const sub = caidResult.value.caid;
  const payload = UTF8.encode(canonical);

  const halves: Uint8Array[] = [];
  for (const alg of EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS) {
    const protectedEncoded = encodeDeterministicCbor8949(
      epScittV2ProtectedHeader(alg, opts.kid, opts.iss, sub),
    );
    if (!protectedEncoded.ok) return protectedEncoded;
    const sigStruct = sigStructureBytes(protectedEncoded.value, payload);
    if (!sigStruct.ok) return sigStruct;
    let signature: Uint8Array;
    try {
      const agile = await signAgile(
        new Uint8Array(sigStruct.value),
        alg === COSE_ALG_EDDSA
          ? { alg: 'Ed25519', private_key: key }
          : { alg: 'ML-DSA-65', private_key: opts.statementPqSecretKey },
        agility,
      );
      signature = new Uint8Array(Buffer.from(agile.sig, 'base64url'));
    } catch {
      return { ok: false, reason: alg === COSE_ALG_EDDSA ? 'invalid_signing_key' : 'pq_backend_unavailable' };
    }
    const body = encodeDeterministicCbor8949([
      protectedEncoded.value, new Map(), payload, signature,
    ]);
    if (!body.ok) return body;
    halves.push(concatBytes([Uint8Array.of(COSE_SIGN1_TAG_BYTE), body.value]));
  }

  return {
    ok: true,
    value: {
      classical: halves[0],
      pq: halves[1],
      payload,
      iss: opts.iss,
      sub,
      caid: sub,
      payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
    },
  };
}

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
  receiptVerifier?: (receipt: unknown, publicKeyBase64url: string) => { valid?: unknown };
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

interface ParsedScittHybridHalf {
  protectedBytes: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
  iss: string;
  sub: string;
}

function parseScittHybridHalf(
  statementBytes: unknown,
  expectedAlg: number,
  expectedKid: string,
): CborResult<ParsedScittHybridHalf> {
  if (!(statementBytes instanceof Uint8Array) || statementBytes.length < 2) {
    return refuse('malformed_cbor');
  }
  if (statementBytes[0] !== COSE_SIGN1_TAG_BYTE) return refuse('cose_structure_invalid');
  const decoded = decodeDeterministicCbor8949(statementBytes.subarray(1), { textKeysOnly: false });
  if (!decoded.ok) return { ok: false, reason: decoded.reason };
  const arr = decoded.value;
  if (!Array.isArray(arr) || arr.length !== 4) return refuse('cose_structure_invalid');
  const [protectedBytes, unprotected, payload, signature] = arr as unknown[];
  if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array)
      || !(signature instanceof Uint8Array) || !(unprotected instanceof Map)) {
    return refuse('cose_structure_invalid');
  }
  if (unprotected.size !== 0) return refuse('unprotected_headers_present');

  const headerResult = decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false });
  if (!headerResult.ok) return { ok: false, reason: headerResult.reason };
  if (!(headerResult.value instanceof Map)) return refuse('cose_structure_invalid');
  const headers = headerResult.value;
  if (headers.has(COSE_HEADER_CRIT)) return refuse('crit_unsupported');
  for (const label of headers.keys()) {
    if (!V2_PROFILE_PROTECTED_LABELS.has(label)) return refuse('unexpected_protected_header');
  }
  if (headers.get(COSE_HEADER_ALG) !== expectedAlg) return refuse('unsupported_statement_alg');
  if (headers.get(COSE_HEADER_CONTENT_TYPE) !== EP_STATEMENT_PAYLOAD_CONTENT_TYPE) {
    return refuse('content_type_mismatch');
  }
  const headerKid = headers.get(COSE_HEADER_KID);
  if (!(headerKid instanceof Uint8Array) || headerKid.length === 0) return refuse('kid_missing');
  if (compareBytes(headerKid, UTF8.encode(expectedKid)) !== 0) return refuse('kid_mismatch');
  if (!scittV2SetMatchesRegistered(headers.get(COSE_HEADER_EP_REQUIRED_ALGS))) {
    return { ok: false, reason: 'algorithm_set_mismatch' };
  }

  if (!headers.has(COSE_HEADER_CWT_CLAIMS)) return refuse('cwt_claims_missing');
  const cwt = headers.get(COSE_HEADER_CWT_CLAIMS);
  if (!(cwt instanceof Map)) return refuse('cwt_claims_malformed');
  for (const label of cwt.keys()) {
    if (!PROFILE_CWT_CLAIM_LABELS.has(label)) return refuse('unexpected_cwt_claim');
  }
  if (!cwt.has(CWT_CLAIM_ISS)) return refuse('iss_missing');
  if (!cwt.has(CWT_CLAIM_SUB)) return refuse('sub_missing');
  const iss = cwt.get(CWT_CLAIM_ISS);
  const sub = cwt.get(CWT_CLAIM_SUB);
  if (!isAcceptableIss(iss)) return refuse('iss_malformed');
  if (!isCaidString(sub)) return refuse('sub_malformed');

  return { ok: true, value: { protectedBytes, payload, signature, iss, sub } };
}

/**
 * Verify an EP-SCITT-STATEMENT-v2 hybrid Signed Statement pair, fail-closed.
 * `valid: true` still means VERIFIED, never REGISTERED, and the pairing is a
 * relying-party pin that no Transparency Service conveys.
 */
export async function verifyEpScittSignedStatementHybrid(
  pair: { classical?: unknown; pq?: unknown } | null | undefined,
  opts: VerifyScittHybridOptions,
): Promise<VerifyScittHybridResult> {
  const checks: VerifyScittHybridResult['checks'] = {
    pair_present: false,
    deterministic_encoding: false,
    cose_structure: false,
    algorithm_set: false,
    payload_identical: false,
    cwt_claims: false,
    statement_signatures: false,
    payload_canonical: false,
    receipt_signature: false,
    sub_binding: false,
  };
  const fail = (reason: string): VerifyScittHybridResult =>
    ({ valid: false, checks, reason, registered: false });

  if (!pair || typeof pair !== 'object'
      || !(pair.classical instanceof Uint8Array) || !(pair.pq instanceof Uint8Array)) {
    return fail('hybrid_pair_incomplete');
  }
  if (typeof opts?.expectedKid !== 'string' || opts.expectedKid.length === 0) return fail('invalid_kid');
  if (!isAcceptableIss(opts?.expectedIss)) return fail('invalid_iss');
  checks.pair_present = true;

  const classical = parseScittHybridHalf(pair.classical, COSE_ALG_EDDSA, opts.expectedKid);
  if (!classical.ok) return fail(classical.reason);
  const pq = parseScittHybridHalf(pair.pq, COSE_ALG_ML_DSA_65, opts.expectedKid);
  if (!pq.ok) return fail(pq.reason);
  checks.deterministic_encoding = true;
  checks.cose_structure = true;
  checks.algorithm_set = true;

  if (compareBytes(classical.value.payload, pq.value.payload) !== 0) {
    return fail('hybrid_payload_mismatch');
  }
  if (classical.value.iss !== pq.value.iss || classical.value.sub !== pq.value.sub) {
    return fail('hybrid_payload_mismatch');
  }
  checks.payload_identical = true;

  if (classical.value.iss !== opts.expectedIss) return fail('iss_mismatch');
  if (typeof opts.expectedSub === 'string' && opts.expectedSub !== classical.value.sub) {
    return fail('sub_mismatch');
  }
  checks.cwt_claims = true;

  const payload = classical.value.payload;
  let payloadText: string;
  try {
    payloadText = FATAL_UTF8.decode(payload);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let receipt: unknown;
  try {
    receipt = JSON.parse(payloadText);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let recanonical: string;
  try {
    recanonical = canonicalize(receipt);
  } catch {
    return fail('payload_not_canonical_json');
  }
  if (recanonical !== payloadText) return fail('payload_not_canonical_json');
  checks.payload_canonical = true;

  // `sub` is bound to the payload by recomputation, then BOTH protected headers
  // are rebuilt from the REGISTERED set, the pinned kid/iss, and that recomputed
  // sub. A presented header never chooses what it is checked against.
  const recomputed = receiptActionCaid((receipt as Record<string, any>)?.payload?.action);
  if (!recomputed.ok) return fail('sub_not_bound_to_payload');
  if (recomputed.value.caid !== classical.value.sub) return fail('sub_not_bound_to_payload');
  for (const [half, alg] of [
    [classical.value, COSE_ALG_EDDSA] as const,
    [pq.value, COSE_ALG_ML_DSA_65] as const,
  ]) {
    let expected;
    try {
      expected = encodeDeterministicCbor8949(
        epScittV2ProtectedHeader(alg, opts.expectedKid, opts.expectedIss, recomputed.value.caid),
      );
    } catch {
      return fail('algorithm_set_mismatch');
    }
    if (!expected.ok) return fail(expected.reason);
    if (compareBytes(expected.value, half.protectedBytes) !== 0) {
      return fail('protected_header_mismatch');
    }
  }
  checks.sub_binding = true;

  const classicalSig = sigStructureBytes(classical.value.protectedBytes, payload);
  if (!classicalSig.ok) return fail(classicalSig.reason);
  const pqSig = sigStructureBytes(pq.value.protectedBytes, payload);
  if (!pqSig.ok) return fail(pqSig.reason);
  const legs = [
    await verifyAgileSignature(
      classicalSig.value,
      { alg: 'Ed25519', sig: Buffer.from(classical.value.signature).toString('base64url') },
      { alg: 'Ed25519', public_key: opts.statementPublicKeyBase64url },
      opts.agility ?? {},
    ),
    await verifyAgileSignature(
      pqSig.value,
      { alg: 'ML-DSA-65', sig: Buffer.from(pq.value.signature).toString('base64url') },
      { alg: 'ML-DSA-65', public_key: opts.statementPqPublicKeyBase64url },
      opts.agility ?? {},
    ),
  ];
  const failedLeg = legs.find((leg) => leg.verified !== true);
  if (failedLeg) return fail(`statement_signature_invalid:${failedLeg.alg}:${failedLeg.reason}`);
  checks.statement_signatures = true;

  const verifier = typeof opts?.receiptVerifier === 'function' ? opts.receiptVerifier : verifyReceipt;
  let receiptResult: { valid?: unknown };
  try {
    receiptResult = verifier(receipt, opts.receiptIssuerPublicKeyBase64url);
  } catch {
    return fail('receipt_invalid');
  }
  if (receiptResult?.valid !== true) return fail('receipt_invalid');
  checks.receipt_signature = true;

  return {
    valid: true,
    checks,
    registered: false,
    receipt,
    iss: classical.value.iss,
    sub: classical.value.sub,
    payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
  };
}
