// SPDX-License-Identifier: Apache-2.0
//
// EP-PQ-CUSTODY-AWS-KMS-v1: the AWS KMS adapter for EP's external ML-DSA-65
// custody seam (lib/pq-custody-external.ts, EP-PQ-CUSTODY-EXTERNAL-v1).
//
// WHAT THIS IS. One provider adapter. It supplies the single `sign` callback
// the external seam asks for, fetches and pins the ML-DSA-65 public key from
// the same KMS key, and adds the provider-specific pins AWS's API makes
// possible. Everything about how a returned signature is checked (length pin,
// encoding pin, verify-on-sign against the pinned public key, timeout,
// cancellation, fail-closed) stays in the seam and is not reimplemented here.
// The adapter passes runExternalPqCustodyConformance() UNCHANGED; that is the
// definition of "this adapter works" and it is not negotiable.
//
// NO LIVE AWS CALL HAS EVER BEEN MADE AGAINST THIS ADAPTER. Every test in
// tests/pq-custody-aws-kms.test.ts runs against hand-built fakes that mimic
// the documented response shapes. Nothing here is an interop result, an
// integration test, or evidence that a real KMS key signs what this code
// expects. The first real call will be an operator's, not ours.
//
// ZERO NEW DEPENDENCIES, ON PURPOSE. This file imports no AWS package. The
// operator injects a client object with the two methods below, so EP stays
// dependency-free and the operator owns the SDK version, the credential
// chain, the region, the retry policy, and the endpoint. An EP release can
// never drag an AWS SDK upgrade into a deployment, and EP never sees a
// credential.
//
//   interface AwsKmsPqClient {
//     getPublicKey(
//       input: { KeyId: string },
//       options?: { abortSignal?: AbortSignal },
//     ): Promise<{
//       KeyId?: string;
//       PublicKey?: Uint8Array | string;   // DER X.509 SubjectPublicKeyInfo
//       KeySpec?: string;                  // expected: 'ML_DSA_65'
//       KeyUsage?: string;                 // expected: 'SIGN_VERIFY'
//       SigningAlgorithms?: string[];      // expected to include ML_DSA_SHAKE_256
//     }>;
//     sign(
//       input: {
//         KeyId: string;
//         Message: Uint8Array;
//         MessageType: 'RAW';
//         SigningAlgorithm: 'ML_DSA_SHAKE_256';
//       },
//       options?: { abortSignal?: AbortSignal },
//     ): Promise<{ Signature?: Uint8Array | string; SigningAlgorithm?: string; KeyId?: string }>;
//   }
//
// METHOD-STYLE, NOT COMMAND-STYLE, AND WHY. AWS SDK v3's `client.send(cmd)`
// takes command objects that only the SDK can construct, so a send-style seam
// would force the dependency this file exists to avoid. The method shape is
// what SDK v2 exposes directly and is three lines away from SDK v3:
//
//   import { KMSClient, GetPublicKeyCommand, SignCommand } from '@aws-sdk/client-kms';
//   const kms = new KMSClient({ region });
//   const client = {
//     getPublicKey: (input, opts) => kms.send(new GetPublicKeyCommand(input), opts),
//     sign:         (input, opts) => kms.send(new SignCommand(input), opts),
//   };
//
// CUSTODY IS 'kms', AND THAT IS A DECLARATION, NOT AN OBSERVATION. The signer
// reports custody 'kms' because the operator pointed it at a KMS key ARN and
// because AWS states its keys are generated in and confined to its hardware
// security modules. EP code cannot observe any of that. It sees an HTTPS
// response. custodyDeclaration.verified_by_code stays false here exactly as it
// does in the provider-agnostic seam.
//
// THIS ADAPTER DOES NOT IMPROVE EP'S FIPS POSTURE. Stated plainly because the
// opposite is the obvious thing for a reader to assume. CMVP certificate 4884
// (AWS Key Management Service HSM, FIPS 140-3 Level 3, validated 2024-11-18;
// certificate read 2026-08-18) does NOT list ML-DSA among its approved
// algorithms. So: pointing EP's PQ leg at a KMS ML-DSA-65 key moves the key
// out of EP's process memory, which is a real custody improvement, and it
// changes nothing about algorithm validation status. Never write, in a deck, a
// datasheet, an RFP answer, or a draft, that EP's ML-DSA-65 leg runs inside a
// validated cryptographic module. It does not, and this file is the reason
// nobody gets to say otherwise by accident.
//
// WHAT THE ADAPTER PINS THAT THE GENERIC SEAM CANNOT:
//   1. KeySpec must be exactly ML_DSA_65. A KMS key of any other spec is a
//      refusal at construction, not a runtime surprise.
//   2. WHEN the response carries them, KeyUsage must be SIGN_VERIFY and the
//      advertised SigningAlgorithms must include ML_DSA_SHAKE_256 (the only
//      signing algorithm AWS defines for ML-DSA keys). The limit, stated
//      because it is a real one: these two fields are checked only if present.
//      An injected client that drops them is not refused for dropping them,
//      because the shape of every SDK wrapper an operator might write was not
//      verified against a live response. KeySpec is NOT optional and its
//      absence is a refusal, because that is the field the whole pin rests on.
//   3. GetPublicKey returns a DER X.509 SubjectPublicKeyInfo, NOT the raw
//      1952-byte key EP pins. The adapter unwraps the SPKI itself and refuses
//      unless the unwrapped subjectPublicKey is exactly
//      ML_DSA_65_PUBLIC_KEY_BYTES. Handing a DER blob to the seam would fail
//      the seam's length pin with a confusing reason; unwrapping without the
//      length pin would let a mis-specced key through.
//   4. Sign's echoed SigningAlgorithm must be ML_DSA_SHAKE_256. A response
//      that signed under something else is a refusal even though the bytes
//      might be the right length.
//   5. The RAW message path has a 4 KB ceiling. Over it, the adapter refuses
//      BY NAME (see EXTERNAL_MU below).
//
// EXTERNAL_MU IS DELIBERATELY OUT OF SCOPE. AWS also accepts
// MessageType: EXTERNAL_MU, where the caller computes the FIPS 204 mu value
// itself and KMS signs that. That path is not implemented here and an oversize
// message is NOT silently switched onto it. The reason is specific: mu is a
// keyed digest over the public key and the message, and a wrong mu produces a
// signature that is structurally valid, passes every length pin, and attests
// to bytes nobody intended. A refusal is recoverable; a valid-looking
// signature over the wrong thing is not. An operator who needs to sign more
// than 4 KB should hash-then-sign at the EP layer over a canonical digest, or
// this adapter grows an EXTERNAL_MU mode in its own commit with its own
// FIPS 204 mu test vectors.
//
// SIGNATURES ARE NOT DETERMINISTIC HERE. AWS signs with the hedged
// (randomized) FIPS 204 variant, so two Sign calls over identical bytes return
// different signatures. Nothing in this adapter, and nothing any test may
// assert, depends on byte-stable signatures. Message binding is proved by
// verification against the pinned public key, which is what the seam already
// does.
//
// NOTHING HERE THROWS ON CALLER INPUT OR ON A MISBEHAVING CLIENT.
// Construction returns a refusal. trySign() returns a refusal. sign() rejects
// with the seam's ExternalPqCustodyError carrying the same named reason.

import {
  DEFAULT_EXTERNAL_PQ_TIMEOUT_MS,
  EXTERNAL_PQ_REASONS,
  MAX_EXTERNAL_PQ_TIMEOUT_MS,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  createExternalPqCustodySigner,
  ExternalPqCustodyError,
  type ExternalPqCustodySigner,
  type ExternalPqRefusal,
  type ExternalPqSignResult,
} from './pq-custody-external.js';

import type { AgilityMldsaBackend } from '@emilia-protocol/verify/pq-signature-agility';

/** Profile id for an AWS KMS-custodied ML-DSA-65 leg. */
export const AWS_KMS_PQ_CUSTODY_PROFILE = 'EP-PQ-CUSTODY-AWS-KMS-v1';

/** The only KMS key spec this adapter accepts. ML_DSA_44 and ML_DSA_87 exist; EP pins 65. */
export const AWS_KMS_ML_DSA_65_KEY_SPEC = 'ML_DSA_65';

/** The only signing algorithm AWS defines for ML-DSA KMS keys. */
export const AWS_KMS_ML_DSA_SIGNING_ALGORITHM = 'ML_DSA_SHAKE_256';

/** The only KeyUsage that can sign. */
export const AWS_KMS_SIGN_VERIFY_KEY_USAGE = 'SIGN_VERIFY';

/** The MessageType this adapter uses. EXTERNAL_MU is out of scope; see the header. */
export const AWS_KMS_RAW_MESSAGE_TYPE = 'RAW';

/** Documented ceiling on the RAW message path, in bytes. */
export const AWS_KMS_RAW_MESSAGE_MAX_BYTES = 4096;

/**
 * Adapter-named refusals. These names are the ADAPTER's, not entries in the
 * seam's EXTERNAL_PQ_REASONS registry, so isNamedExternalPqReason() does not
 * recognize them. That is intentional and harmless: every conformance case
 * exercises the seam's own reasons, which is why the harness passes unchanged.
 * Use isNamedAwsKmsPqReason() when handling adapter refusals.
 */
export const AWS_KMS_PQ_REASONS = Object.freeze({
  CLIENT_INVALID: 'aws_kms_client_invalid',
  KEY_ID_INVALID: 'aws_kms_key_id_invalid',
  GET_PUBLIC_KEY_FAILED: 'aws_kms_get_public_key_failed',
  GET_PUBLIC_KEY_TIMEOUT: 'aws_kms_get_public_key_timeout',
  KEY_SPEC_INVALID: 'aws_kms_key_spec_invalid',
  KEY_USAGE_INVALID: 'aws_kms_key_usage_invalid',
  SIGNING_ALGORITHM_INVALID: 'aws_kms_signing_algorithm_invalid',
  SPKI_UNWRAP_FAILED: 'aws_kms_spki_unwrap_failed',
  PUBLIC_KEY_LENGTH_INVALID: 'aws_kms_public_key_length_invalid',
  MESSAGE_TOO_LARGE: 'aws_kms_message_too_large',
  MESSAGE_TYPE_UNSUPPORTED: 'aws_kms_message_type_unsupported',
  SIGN_FAILED: 'aws_kms_sign_failed',
  SIGNATURE_MISSING: 'aws_kms_signature_missing',
  // Borrowed verbatim from the seam: a secret-key-shaped option is the seam's
  // refusal and keeps one name across every adapter.
  SECRET_KEY_OFFERED: EXTERNAL_PQ_REASONS.SECRET_KEY_OFFERED,
});

const AWS_NAMED_REASONS: ReadonlySet<string> = new Set(Object.values(AWS_KMS_PQ_REASONS));

/** Is `reason` one of this adapter's named refusals? */
export function isNamedAwsKmsPqReason(reason: unknown): boolean {
  return typeof reason === 'string' && AWS_NAMED_REASONS.has(reason);
}

// ---------------------------------------------------------------------------
// Injected client surface
// ---------------------------------------------------------------------------

export interface AwsKmsGetPublicKeyInput {
  KeyId: string;
}

export interface AwsKmsGetPublicKeyOutput {
  KeyId?: string;
  /** DER X.509 SubjectPublicKeyInfo, as bytes or base64. NOT the raw key. */
  PublicKey?: Uint8Array | string;
  KeySpec?: string;
  KeyUsage?: string;
  SigningAlgorithms?: string[];
}

export interface AwsKmsSignInput {
  KeyId: string;
  Message: Uint8Array;
  MessageType: 'RAW';
  SigningAlgorithm: 'ML_DSA_SHAKE_256';
}

export interface AwsKmsSignOutput {
  KeyId?: string;
  Signature?: Uint8Array | string;
  SigningAlgorithm?: string;
}

export interface AwsKmsCallOptions {
  abortSignal?: AbortSignal;
}

/**
 * The minimal injected client. Two methods, both promise-returning, both
 * taking the AWS input shape and an options bag carrying an AbortSignal.
 * A real SDK client satisfies this directly (v2) or via a three-line wrapper
 * (v3, see the module header).
 */
export interface AwsKmsPqClient {
  getPublicKey(
    input: AwsKmsGetPublicKeyInput,
    options?: AwsKmsCallOptions,
  ): Promise<AwsKmsGetPublicKeyOutput> | AwsKmsGetPublicKeyOutput;
  sign(
    input: AwsKmsSignInput,
    options?: AwsKmsCallOptions,
  ): Promise<AwsKmsSignOutput> | AwsKmsSignOutput;
}

export interface AwsKmsPqCustodyOptions {
  /** The injected KMS client. EP adds no AWS dependency and sees no credential. */
  client: AwsKmsPqClient;
  /** The KMS key ARN, key id, or alias this adapter signs with. */
  awsKeyId: string;
  /**
   * EP's stable, auditable identifier for the leg. Defaults to
   * `aws-kms:<awsKeyId>` so an operator who omits it still gets something
   * traceable rather than an opaque handle.
   */
  keyId?: string;
  /** Per-call deadline in ms, applied to GetPublicKey and to every Sign. */
  timeoutMs?: number;
  /** Process-lifetime cancellation. Aborts in-flight calls. */
  signal?: AbortSignal;
  /** Verify every returned signature under the pinned public key. Default true. */
  verifyOnSign?: boolean;
  /** Inject an ML-DSA backend for verify-on-sign instead of loading one. */
  mldsaBackend?: AgilityMldsaBackend | null;
  /** Operator evidence for the custody declaration. Recorded verbatim. */
  attestation?: string | null;
  /**
   * Present so that asking for EXTERNAL_MU is a named refusal instead of a
   * silently ignored field. 'RAW' is the only accepted value.
   */
  messageType?: 'RAW';
}

/**
 * The seam's signer plus what the adapter learned from KMS. Nothing here is
 * key material: the SPKI and its algorithm OID are public, and both are
 * recorded so an audit can see exactly what KMS returned.
 */
export interface AwsKmsPqCustodySigner extends ExternalPqCustodySigner {
  readonly adapterProfile: string;
  readonly awsKeyId: string;
  readonly awsKeySpec: string;
  readonly awsKeyUsage: string | null;
  readonly awsSigningAlgorithm: string;
  readonly awsMessageType: 'RAW';
  readonly maxMessageBytes: number;
  /** The DER SPKI exactly as KMS returned it, base64url. Public data. */
  readonly publicKeySpkiDerB64u: string;
  /**
   * The AlgorithmIdentifier OID inside that SPKI, dotted-decimal. RECORDED,
   * NOT GATED ON: the ML-DSA OID assignment was not verified from a primary
   * source in the session that wrote this file, so making it a pass/fail
   * condition would be a guess wearing a check's clothes. The gates are the
   * KeySpec KMS reports and the unwrapped key length.
   */
  readonly publicKeyAlgorithmOid: string | null;
}

export type CreateAwsKmsPqCustodySignerResult =
  | { ok: true; signer: AwsKmsPqCustodySigner }
  | ExternalPqRefusal;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function refuse(reason: string, detail: string): ExternalPqRefusal {
  return { ok: false, reason, detail };
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/** Strict standard-base64 decode with a canonical round trip. AWS JSON uses this. */
function decodeBase64(value: string): Buffer | null {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) return null;
  if (!BASE64_RE.test(value)) return null;
  let bytes: Buffer;
  try {
    bytes = Buffer.from(value, 'base64');
  } catch {
    return null;
  }
  if (bytes.toString('base64') !== value) return null;
  return bytes;
}

/** Accept the byte forms an SDK may hand back: Uint8Array, Buffer, or base64. */
function toResponseBytes(value: unknown): Buffer | null {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return decodeBase64(value);
  return null;
}

function errorText(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return String(err);
}

// ---------------------------------------------------------------------------
// Minimal strict DER reader, enough for SubjectPublicKeyInfo and no more
//
// Written here rather than pulled in because the alternative is a dependency,
// and because "enough for SPKI" is a genuinely small, auditable amount of DER:
// definite lengths only, no indefinite form, no trailing bytes tolerated.
// ---------------------------------------------------------------------------

const DER_SEQUENCE = 0x30;
const DER_OBJECT_IDENTIFIER = 0x06;
const DER_BIT_STRING = 0x03;

interface DerTlv {
  tag: number;
  contents: Buffer;
  /** Offset of the first byte after this TLV. */
  end: number;
}

/** Read one definite-length DER TLV at `offset`. Returns null on anything malformed. */
function readTlv(buf: Buffer, offset: number): DerTlv | null {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset];
  // High-tag-number form is not used anywhere in an SPKI we accept.
  if ((tag & 0x1f) === 0x1f) return null;
  const first = buf[offset + 1];
  let length: number;
  let cursor = offset + 2;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    return null; // indefinite length is not DER
  } else {
    const numBytes = first & 0x7f;
    // 4 bytes of length is far more than any SPKI needs and keeps this in
    // safe-integer range without a bigint path.
    if (numBytes === 0 || numBytes > 4) return null;
    if (cursor + numBytes > buf.length) return null;
    length = 0;
    // DER forbids a leading zero byte in the long form (non-minimal encoding).
    if (buf[cursor] === 0x00) return null;
    for (let i = 0; i < numBytes; i += 1) {
      length = length * 256 + buf[cursor + i];
    }
    cursor += numBytes;
    // DER also forbids the long form where the short form would do.
    if (length < 0x80) return null;
  }
  if (cursor + length > buf.length) return null;
  return { tag, contents: buf.subarray(cursor, cursor + length), end: cursor + length };
}

/** Decode a DER OBJECT IDENTIFIER body to dotted-decimal. Returns null if malformed. */
function decodeOid(contents: Buffer): string | null {
  if (contents.length === 0) return null;
  const parts: number[] = [];
  const firstByte = contents[0];
  parts.push(Math.floor(firstByte / 40) > 2 ? 2 : Math.floor(firstByte / 40));
  parts.push(parts[0] === 2 ? firstByte - 80 : firstByte % 40);
  let value = 0;
  let started = false;
  for (let i = 1; i < contents.length; i += 1) {
    const byte = contents[i];
    // Non-minimal subidentifier encoding (leading 0x80) is malformed DER.
    if (!started && byte === 0x80) return null;
    started = true;
    value = value * 128 + (byte & 0x7f);
    if (!Number.isSafeInteger(value)) return null;
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
      started = false;
    }
  }
  // A subidentifier left unterminated (high bit still set at the end).
  if (started) return null;
  return parts.join('.');
}

export interface SpkiUnwrapResult {
  ok: true;
  /** The raw subjectPublicKey bits, unused-bits byte stripped. */
  publicKey: Buffer;
  /** Dotted-decimal AlgorithmIdentifier OID. */
  algorithmOid: string | null;
}

/**
 * Unwrap a DER X.509 SubjectPublicKeyInfo to its raw subjectPublicKey bytes.
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm         AlgorithmIdentifier,   -- SEQUENCE { OID, params OPTIONAL }
 *   subjectPublicKey  BIT STRING             -- raw ML-DSA key, 0 unused bits
 * }
 *
 * Structure only. It does not decide whether the key is an ML-DSA-65 key;
 * that is the KeySpec check plus the length pin in the caller.
 * Never throws.
 */
export function unwrapSpkiPublicKey(der: unknown): SpkiUnwrapResult | ExternalPqRefusal {
  const buf = toResponseBytes(der);
  if (!buf || buf.length === 0) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      'GetPublicKey returned no DER SubjectPublicKeyInfo bytes (expected Uint8Array, Buffer, or base64).',
    );
  }

  const outer = readTlv(buf, 0);
  if (!outer || outer.tag !== DER_SEQUENCE) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      'the returned public key is not a DER SEQUENCE; it is not a SubjectPublicKeyInfo.',
    );
  }
  if (outer.end !== buf.length) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      `${buf.length - outer.end} trailing byte(s) after the SubjectPublicKeyInfo SEQUENCE; refusing a non-canonical encoding.`,
    );
  }

  const body = outer.contents;
  const algId = readTlv(body, 0);
  if (!algId || algId.tag !== DER_SEQUENCE) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      'the SubjectPublicKeyInfo has no AlgorithmIdentifier SEQUENCE.',
    );
  }
  const oidTlv = readTlv(algId.contents, 0);
  const algorithmOid = oidTlv && oidTlv.tag === DER_OBJECT_IDENTIFIER ? decodeOid(oidTlv.contents) : null;

  const bitString = readTlv(body, algId.end);
  if (!bitString || bitString.tag !== DER_BIT_STRING) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      'the SubjectPublicKeyInfo has no subjectPublicKey BIT STRING.',
    );
  }
  if (bitString.end !== body.length) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      'unexpected extra element after the subjectPublicKey BIT STRING.',
    );
  }
  if (bitString.contents.length < 1) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      'the subjectPublicKey BIT STRING is empty.',
    );
  }
  if (bitString.contents[0] !== 0x00) {
    return refuse(
      AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED,
      `the subjectPublicKey BIT STRING declares ${bitString.contents[0]} unused bits; a public key is whole bytes.`,
    );
  }

  return { ok: true, publicKey: Buffer.from(bitString.contents.subarray(1)), algorithmOid };
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

const SECRET_SHAPED_OPTION_RE = /(secret|private|seed|passphrase|password|pkcs8|pem)/i;
const SECRET_SHAPED_EXACT = new Set(['sk', 'key', 'keyMaterial']);

/**
 * Per-call slot. The seam has no channel for an adapter-named refusal (its
 * `sign` callback either returns a signature or fails), so the callback writes
 * its named refusal into a FRESH object attached to that call's context and
 * the wrapper reads it back. Fresh per call, symbol-keyed, never shared, so
 * concurrent signing calls cannot see each other's refusal.
 */
const AWS_CALL_SLOT = Symbol('ep.awsKmsPqCallSlot');

interface AwsCallSlot {
  refusal: ExternalPqRefusal | null;
}

async function withDeadline<T>(
  work: (signal: AbortSignal) => Promise<T> | T,
  timeoutMs: number,
  lifetimeSignal: AbortSignal | null,
): Promise<{ ok: true; value: T } | { ok: false; timedOut: boolean; error: unknown }> {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  lifetimeSignal?.addEventListener('abort', onAbort, { once: true });
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    if (lifetimeSignal?.aborted) return { ok: false, timedOut: false, error: new Error('aborted before the call started') };
    const call = Promise.resolve().then(() => work(controller.signal));
    call.catch(() => {}); // a late rejection must not surface as unhandled
    const deadline = new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve('timeout');
      }, timeoutMs);
      if (typeof (timer as { unref?: () => void }).unref === 'function') {
        (timer as { unref?: () => void }).unref!();
      }
    });
    const raced = await Promise.race([call.then((value) => ({ __v: value })), deadline]);
    if (raced === 'timeout') return { ok: false, timedOut: true, error: null };
    return { ok: true, value: (raced as { __v: T }).__v };
  } catch (err) {
    return { ok: false, timedOut: false, error: err };
  } finally {
    if (timer) clearTimeout(timer);
    lifetimeSignal?.removeEventListener('abort', onAbort);
  }
}

/**
 * Build the AWS KMS ML-DSA-65 leg of EP's hybrid custody seam.
 *
 * Asynchronous because it fetches and pins the public key from the same KMS
 * key it will sign with. A signer that pinned a key an operator pasted in by
 * hand could verify happily against a key the signing key is not.
 *
 * Never throws: every failure is a returned refusal naming a reason.
 *
 * @example
 *   const built = await createAwsKmsPqCustodySigner({
 *     client,                                     // operator's own SDK instance
 *     awsKeyId: 'arn:aws:kms:us-east-1:1234:key/abcd',
 *   });
 *   if (!built.ok) throw new Error(`${built.reason}: ${built.detail}`);
 */
export async function createAwsKmsPqCustodySigner(
  options: AwsKmsPqCustodyOptions,
): Promise<CreateAwsKmsPqCustodySignerResult> {
  if (!options || typeof options !== 'object') {
    return refuse(
      AWS_KMS_PQ_REASONS.CLIENT_INVALID,
      'createAwsKmsPqCustodySigner requires an options object carrying an injected KMS client.',
    );
  }

  // Same rule as the seam: a secret-key-shaped option is refused, never
  // ignored. KMS never hands out an ML-DSA secret key, so an option that looks
  // like one means the caller has misunderstood what this adapter is.
  for (const name of Object.keys(options)) {
    if (SECRET_SHAPED_OPTION_RE.test(name) || SECRET_SHAPED_EXACT.has(name)) {
      return refuse(
        AWS_KMS_PQ_REASONS.SECRET_KEY_OFFERED,
        `option "${name}" looks like key material. This adapter takes an injected KMS client and a key id; `
        + 'the ML-DSA-65 secret key stays in KMS and is never accepted, derived, or stored here.',
      );
    }
  }

  const client = options.client;
  if (!client || typeof client !== 'object'
    || typeof client.getPublicKey !== 'function'
    || typeof client.sign !== 'function') {
    return refuse(
      AWS_KMS_PQ_REASONS.CLIENT_INVALID,
      'client must be an object exposing getPublicKey(input, options) and sign(input, options). '
      + 'EP ships no AWS SDK; the operator injects their own instance.',
    );
  }

  const awsKeyId = options.awsKeyId;
  if (typeof awsKeyId !== 'string' || awsKeyId.trim() === '') {
    return refuse(
      AWS_KMS_PQ_REASONS.KEY_ID_INVALID,
      'awsKeyId must be a non-empty KMS key ARN, key id, or alias.',
    );
  }

  if (options.messageType !== undefined && options.messageType !== AWS_KMS_RAW_MESSAGE_TYPE) {
    return refuse(
      AWS_KMS_PQ_REASONS.MESSAGE_TYPE_UNSUPPORTED,
      `messageType "${String(options.messageType)}" is not implemented. This adapter signs `
      + `MessageType: ${AWS_KMS_RAW_MESSAGE_TYPE} only. EXTERNAL_MU requires the caller to compute the `
      + 'FIPS 204 mu value, and a wrong mu yields a structurally valid signature over bytes nobody '
      + 'intended, so it is out of scope until it ships with its own mu test vectors.',
    );
  }

  const keyId = typeof options.keyId === 'string' && options.keyId.trim() !== ''
    ? options.keyId
    : `aws-kms:${awsKeyId}`;

  const lifetimeSignal = options.signal instanceof AbortSignal ? options.signal : null;

  // The deadline must exist BEFORE the GetPublicKey call below, so it is
  // checked here against the seam's own constants and the seam's own reason
  // name rather than a second name for the same mistake. The seam re-validates
  // the identical value when the signer is constructed further down, so a
  // divergence here cannot admit a value the seam would reject.
  let timeoutMs = DEFAULT_EXTERNAL_PQ_TIMEOUT_MS;
  if (options.timeoutMs !== undefined) {
    if (typeof options.timeoutMs !== 'number'
      || !Number.isInteger(options.timeoutMs)
      || options.timeoutMs <= 0
      || options.timeoutMs > MAX_EXTERNAL_PQ_TIMEOUT_MS) {
      return refuse(
        EXTERNAL_PQ_REASONS.TIMEOUT_INVALID,
        `timeoutMs must be a positive integer of at most ${MAX_EXTERNAL_PQ_TIMEOUT_MS} ms; `
        + 'an unbounded deadline against a remote signer is a hang.',
      );
    }
    timeoutMs = options.timeoutMs;
  }

  // --- GetPublicKey -------------------------------------------------------
  const fetched = await withDeadline(
    (signal) => client.getPublicKey({ KeyId: awsKeyId }, { abortSignal: signal }),
    timeoutMs,
    lifetimeSignal,
  );
  if (!fetched.ok) {
    if (fetched.timedOut) {
      return refuse(
        AWS_KMS_PQ_REASONS.GET_PUBLIC_KEY_TIMEOUT,
        `KMS GetPublicKey for ${awsKeyId} did not answer within ${timeoutMs} ms.`,
      );
    }
    return refuse(
      AWS_KMS_PQ_REASONS.GET_PUBLIC_KEY_FAILED,
      `KMS GetPublicKey for ${awsKeyId} failed: ${errorText(fetched.error)}`,
    );
  }
  const response = fetched.value;
  if (!response || typeof response !== 'object') {
    return refuse(
      AWS_KMS_PQ_REASONS.GET_PUBLIC_KEY_FAILED,
      `KMS GetPublicKey for ${awsKeyId} returned no response object.`,
    );
  }

  if (response.KeySpec !== AWS_KMS_ML_DSA_65_KEY_SPEC) {
    return refuse(
      AWS_KMS_PQ_REASONS.KEY_SPEC_INVALID,
      `KMS reports KeySpec "${String(response.KeySpec)}" for ${awsKeyId}; EP's PQ leg pins `
      + `${AWS_KMS_ML_DSA_65_KEY_SPEC}. ML_DSA_44 and ML_DSA_87 are real KMS key specs and are still `
      + 'the wrong key here: the seam pins FIPS 204 ML-DSA-65 sizes.',
    );
  }

  if (response.KeyUsage !== undefined && response.KeyUsage !== AWS_KMS_SIGN_VERIFY_KEY_USAGE) {
    return refuse(
      AWS_KMS_PQ_REASONS.KEY_USAGE_INVALID,
      `KMS reports KeyUsage "${String(response.KeyUsage)}" for ${awsKeyId}; signing requires `
      + `${AWS_KMS_SIGN_VERIFY_KEY_USAGE}.`,
    );
  }

  if (response.SigningAlgorithms !== undefined) {
    const advertised = Array.isArray(response.SigningAlgorithms) ? response.SigningAlgorithms : [];
    if (!advertised.includes(AWS_KMS_ML_DSA_SIGNING_ALGORITHM)) {
      return refuse(
        AWS_KMS_PQ_REASONS.SIGNING_ALGORITHM_INVALID,
        `KMS advertises signing algorithms [${advertised.map(String).join(', ')}] for ${awsKeyId}; `
        + `${AWS_KMS_ML_DSA_SIGNING_ALGORITHM} is the only one that signs an ML-DSA key and it is absent.`,
      );
    }
  }

  const spkiBytes = toResponseBytes(response.PublicKey);
  const unwrapped = unwrapSpkiPublicKey(response.PublicKey);
  if (unwrapped.ok !== true) return unwrapped;

  if (unwrapped.publicKey.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
    return refuse(
      AWS_KMS_PQ_REASONS.PUBLIC_KEY_LENGTH_INVALID,
      `the SubjectPublicKeyInfo from ${awsKeyId} unwrapped to ${unwrapped.publicKey.length} bytes; `
      + `an ML-DSA-65 public key is exactly ${ML_DSA_65_PUBLIC_KEY_BYTES}. Refusing rather than pinning `
      + 'a key EP cannot be verifying against.',
    );
  }

  // --- The seam does the rest --------------------------------------------
  const built = createExternalPqCustodySigner({
    keyId,
    custody: 'kms',
    publicKey: unwrapped.publicKey,
    timeoutMs: options.timeoutMs,
    signal: lifetimeSignal ?? undefined,
    verifyOnSign: options.verifyOnSign,
    mldsaBackend: options.mldsaBackend,
    attestation: options.attestation,
    sign: async (request) => {
      const slot = (request.context as Record<string | symbol, unknown>)[AWS_CALL_SLOT] as AwsCallSlot | undefined;
      const fail = (reason: string, detail: string): undefined => {
        if (slot) slot.refusal = refuse(reason, detail);
        // Returning undefined makes the seam refuse too (SIGNER_UNAVAILABLE);
        // the wrapper below then replaces that with the adapter's named reason.
        return undefined;
      };

      // Belt and braces: the wrapper already refuses oversize messages, but a
      // caller reaching the seam's signer directly must not slip past it.
      if (request.bytes.length > AWS_KMS_RAW_MESSAGE_MAX_BYTES) {
        return fail(
          AWS_KMS_PQ_REASONS.MESSAGE_TOO_LARGE,
          oversizeDetail(request.bytes.length),
        );
      }

      let signResponse: AwsKmsSignOutput;
      try {
        signResponse = await client.sign(
          {
            KeyId: awsKeyId,
            Message: new Uint8Array(request.bytes),
            MessageType: AWS_KMS_RAW_MESSAGE_TYPE,
            SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
          },
          { abortSignal: request.signal },
        );
      } catch (err) {
        return fail(
          AWS_KMS_PQ_REASONS.SIGN_FAILED,
          `KMS Sign for ${awsKeyId} failed: ${errorText(err)}`,
        );
      }

      if (!signResponse || typeof signResponse !== 'object') {
        return fail(
          AWS_KMS_PQ_REASONS.SIGNATURE_MISSING,
          `KMS Sign for ${awsKeyId} returned no response object.`,
        );
      }
      if (signResponse.SigningAlgorithm !== undefined
        && signResponse.SigningAlgorithm !== AWS_KMS_ML_DSA_SIGNING_ALGORITHM) {
        return fail(
          AWS_KMS_PQ_REASONS.SIGNING_ALGORITHM_INVALID,
          `KMS Sign echoed SigningAlgorithm "${String(signResponse.SigningAlgorithm)}"; the request asked for `
          + `${AWS_KMS_ML_DSA_SIGNING_ALGORITHM}. A signature produced under a different algorithm is not the `
          + 'artifact EP asked for, whatever its length.',
        );
      }
      const signature = toResponseBytes(signResponse.Signature);
      if (!signature) {
        return fail(
          AWS_KMS_PQ_REASONS.SIGNATURE_MISSING,
          `KMS Sign for ${awsKeyId} returned no Signature bytes.`,
        );
      }
      // Raw bytes to the seam. The seam owns the 3309-byte pin, the encoding
      // pin, and verify-on-sign; duplicating them here would create a second
      // place for those numbers to drift.
      return signature;
    },
  });
  if (!built.ok) return built;
  const core = built.signer;

  async function trySign(
    bytes: unknown,
    context: Record<string, unknown> = {},
  ): Promise<ExternalPqSignResult> {
    if ((Buffer.isBuffer(bytes) || bytes instanceof Uint8Array)
      && bytes.length > AWS_KMS_RAW_MESSAGE_MAX_BYTES) {
      return refuse(AWS_KMS_PQ_REASONS.MESSAGE_TOO_LARGE, oversizeDetail(bytes.length));
    }
    const slot: AwsCallSlot = { refusal: null };
    const baseContext = (context && typeof context === 'object' && !Array.isArray(context)) ? context : {};
    const merged = { ...baseContext, [AWS_CALL_SLOT]: slot } as unknown as Record<string, unknown>;
    const result = await core.trySign(bytes, merged);
    if (result.ok) return result;
    // A deadline or cancellation refusal always wins. An aborted SDK call
    // usually rejects too, and reporting "the SDK threw AbortError" when the
    // real answer is "the remote missed its deadline" would hide the cause.
    if (result.reason === EXTERNAL_PQ_REASONS.SIGNER_TIMEOUT
      || result.reason === EXTERNAL_PQ_REASONS.SIGNER_CANCELLED) {
      return result;
    }
    // Otherwise an adapter-level failure recorded during this call names
    // itself; the seam's generic SIGNER_UNAVAILABLE is the fallback, not the
    // answer.
    return slot.refusal ?? result;
  }

  const signer: AwsKmsPqCustodySigner = {
    keyId: core.keyId,
    algorithm: core.algorithm,
    custody: core.custody,
    profile: core.profile,
    custodyDeclaration: core.custodyDeclaration,
    publicKeyRawB64u: core.publicKeyRawB64u,
    timeoutMs: core.timeoutMs,
    verifiesOnSign: core.verifiesOnSign,
    adapterProfile: AWS_KMS_PQ_CUSTODY_PROFILE,
    awsKeyId,
    awsKeySpec: AWS_KMS_ML_DSA_65_KEY_SPEC,
    awsKeyUsage: typeof response.KeyUsage === 'string' ? response.KeyUsage : null,
    awsSigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
    awsMessageType: AWS_KMS_RAW_MESSAGE_TYPE,
    maxMessageBytes: AWS_KMS_RAW_MESSAGE_MAX_BYTES,
    publicKeySpkiDerB64u: (spkiBytes ?? Buffer.alloc(0)).toString('base64url'),
    publicKeyAlgorithmOid: unwrapped.algorithmOid,
    trySign,
    async sign(messageBytes, context = {}) {
      const result = await trySign(messageBytes, context);
      if (!result.ok) throw new ExternalPqCustodyError(result.reason, result.detail);
      return result.sig;
    },
  };
  return { ok: true, signer };
}

function oversizeDetail(length: number): string {
  return `the message is ${length} bytes; KMS Sign with MessageType: ${AWS_KMS_RAW_MESSAGE_TYPE} accepts at most `
    + `${AWS_KMS_RAW_MESSAGE_MAX_BYTES}. This adapter refuses rather than switching to EXTERNAL_MU, which is `
    + 'deliberately out of scope: EXTERNAL_MU makes the caller responsible for the FIPS 204 mu value, and a '
    + 'wrong mu yields a signature that is the right length, verifies structurally, and attests to bytes '
    + 'nobody intended. Sign a canonical digest at the EP layer instead.';
}

/** Is this an AWS KMS PQ custody signer built by this adapter? */
export function isAwsKmsPqCustodySigner(value: unknown): value is AwsKmsPqCustodySigner {
  const s = value as AwsKmsPqCustodySigner | null | undefined;
  return !!s
    && s.adapterProfile === AWS_KMS_PQ_CUSTODY_PROFILE
    && s.algorithm === 'ML-DSA-65'
    && s.custody === 'kms'
    && typeof s.trySign === 'function';
}

const awsKmsPqCustody = {
  AWS_KMS_PQ_CUSTODY_PROFILE,
  AWS_KMS_PQ_REASONS,
  AWS_KMS_RAW_MESSAGE_MAX_BYTES,
  createAwsKmsPqCustodySigner,
  isAwsKmsPqCustodySigner,
  isNamedAwsKmsPqReason,
  unwrapSpkiPublicKey,
};
export default awsKmsPqCustody;
