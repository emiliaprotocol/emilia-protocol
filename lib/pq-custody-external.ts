// SPDX-License-Identifier: Apache-2.0
//
// EP-PQ-CUSTODY-EXTERNAL-v1: the provider-agnostic seam for an ML-DSA-65 leg
// that is signed OUTSIDE this process.
//
// WHY THIS EXISTS. lib/key-custody.ts's PQ leg is software-held by
// construction: lib/custody-signers.ts#softwareMldsaSigner takes a 4032-byte
// ML-DSA-65 secret key and keeps it in process memory. That is the honest
// state of EP's PQ custody today and this module does not change it. What it
// changes is what an operator has to build to move off it: this file is the
// CONTRACT and the CONFORMANCE HARNESS a remote signing backend has to
// satisfy, so wiring a named provider later is mechanical rather than a
// redesign.
//
// NO PROVIDER IS NAMED HERE, ON PURPOSE. This module contains no vendor SDK
// code and asserts nothing about which KMS, HSM, or signing service can sign
// ML-DSA-65. That question is open at the time of writing and a wrong answer
// baked into an interface is worse than no answer. An adapter for a specific
// backend is a separate file that supplies one `sign` callback and passes
// runExternalPqCustodyConformance() unchanged. THAT REQUIREMENT IS NOT
// OPTIONAL: an adapter that has not passed this harness is not an adapter.
//
// THE CUSTODY CLAIM IS THE OPERATOR'S DECLARATION, NOT A FACT THIS CODE
// CHECKED. `custody` is whatever the operator says about where their key
// lives ('kms' | 'hsm' | 'external'). Nothing here can observe a hardware
// security module, an enclave, or a key-export policy. A remote endpoint that
// answers over HTTP is indistinguishable from a hardware-backed one at this
// boundary, so the module records the declaration (custodyDeclaration.
// verified_by_code is always false) and never upgrades it into a claim that
// the key is hardware-backed. What the code DOES enforce is narrower and
// real: this factory never accepts, derives, or stores a secret key.
//
// The exact limit of that, stated so nobody reads it wider: the `sign`
// callback is the operator's own code. If an operator writes a callback that
// closes over a local ML-DSA-65 secret key, the key is in their process
// because they put it there, and `custody` then says something untrue. This
// module cannot see inside the callback. It can only refuse to be the thing
// that puts a key in the process, and it does.
//
// WHAT IS ENFORCED HERE (each pinned by a test in
// tests/pq-custody-external.test.ts):
//   1. No secret key ever enters the process. The contract takes a sign
//      callback plus a public key. Offering a secret-key-shaped option is a
//      REFUSAL, not an ignored field.
//   2. The remote's output is never trusted. Every returned signature is
//      re-encoded and length-pinned to the FIPS 204 ML-DSA-65 size, and by
//      default is cryptographically verified against the pinned public key
//      over the exact bytes that were sent, before the value is handed to
//      anything. The pins and the reason names come from
//      packages/verify/src/pq-signature-agility.ts; none is reimplemented.
//   3. No silent downgrade. A failed, timed out, cancelled, malformed, or
//      unconfigured remote is a NAMED refusal and signing fails closed. There
//      is no fallback to the software backend: this module does not import
//      lib/custody-signers.ts, holds no key material, and has no branch that
//      could emit a classical-only artifact.
//   4. Timeout and cancellation are explicit, with conservative defaults. A
//      hung remote is a refusal at the deadline, never a hang.
//   5. Construction and trySign() never throw. sign() REJECTS with a named
//      reason (the PqCustodySigner contract has no refusal channel, so the
//      rejection is how the hybrid seam fails closed); it never resolves to
//      anything but a validated signature.
//
// BOUNDARY, STATED PLAINLY. Verify-on-sign proves the remote returned a
// signature that verifies under the public key the operator pinned. It does
// not prove the key was generated in, or is confined to, the custody boundary
// the operator declared. That is an operational and procurement fact, evidenced
// by the provider, not by this file.

import {
  AGILITY_REASONS,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  verifyAgileSignature,
  type AgilityMldsaBackend,
} from '@emilia-protocol/verify/pq-signature-agility';

import {
  isHybridCustodySigner,
  type CustodySigner,
  type PqCustodySigner,
} from './key-custody.js';

/** Profile id for an externally custodied ML-DSA-65 leg. */
export const EXTERNAL_PQ_CUSTODY_PROFILE = 'EP-PQ-CUSTODY-EXTERNAL-v1';

/**
 * The custody kinds an operator may DECLARE for an external PQ leg. 'software'
 * is deliberately absent: a software-held key is lib/custody-signers.ts's
 * softwareMldsaSigner, and calling it external here would be the exact
 * mislabelling this seam exists to prevent.
 *
 * Note these are not EP_KEY_CUSTODY_MODE values. assertProductionKeyCustody()
 * governs the CLASSICAL leg's mode and is unchanged; an external PQ leg does
 * not satisfy it and does not weaken it.
 */
export const EXTERNAL_PQ_CUSTODY_KINDS = Object.freeze(['kms', 'hsm', 'external'] as const);
export type ExternalPqCustodyKind = (typeof EXTERNAL_PQ_CUSTODY_KINDS)[number];

/** Conservative default deadline for one remote signing call (milliseconds). */
export const DEFAULT_EXTERNAL_PQ_TIMEOUT_MS = 5000;

/**
 * Upper bound on a configurable deadline. An "unbounded" timeout is a hang
 * with extra steps, so the ceiling is part of the contract rather than advice.
 */
export const MAX_EXTERNAL_PQ_TIMEOUT_MS = 60_000;

/**
 * Named refusals. The two borrowed entries keep the agility module as the one
 * definition of what a bad ML-DSA signature is called.
 */
export const EXTERNAL_PQ_REASONS = Object.freeze({
  SIGNER_NOT_CONFIGURED: 'external_pq_signer_not_configured',
  SIGNER_UNAVAILABLE: 'external_pq_signer_unavailable',
  SIGNER_TIMEOUT: 'external_pq_signer_timeout',
  SIGNER_CANCELLED: 'external_pq_signer_cancelled',
  SIGNATURE_LENGTH_INVALID: 'external_pq_signature_length_invalid',
  SIGNATURE_ENCODING_INVALID: 'external_pq_signature_encoding_invalid',
  SIGNATURE_MALFORMED: 'external_pq_signature_malformed',
  SIGNATURE_NOT_MESSAGE_BOUND: 'external_pq_signature_not_message_bound',
  PUBLIC_KEY_INVALID: 'external_pq_public_key_invalid',
  CUSTODY_KIND_INVALID: 'external_pq_custody_kind_invalid',
  TIMEOUT_INVALID: 'external_pq_timeout_invalid',
  MESSAGE_INVALID: 'external_pq_message_invalid',
  SECRET_KEY_OFFERED: 'external_pq_secret_key_offered',
  KEY_ID_INVALID: 'external_pq_key_id_invalid',
  LEG_MISSING: 'external_pq_leg_missing',
  LEG_NOT_EXTERNAL: 'external_pq_leg_not_external',
  ADAPTER_THREW: 'external_pq_adapter_threw',
  REFUSAL_UNNAMED: 'external_pq_refusal_unnamed',
  SECRET_KEY_SURFACE: 'external_pq_secret_key_surface',
  // Borrowed verbatim from packages/verify/src/pq-signature-agility.ts.
  SIGNATURE_INVALID: AGILITY_REASONS.SIGNATURE_INVALID,
  PQ_BACKEND_UNAVAILABLE: AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE,
});

/** Re-exported so adapters pin the same sizes this module pins. */
export { ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES };

const NAMED_REASONS: ReadonlySet<string> = new Set(Object.values(EXTERNAL_PQ_REASONS));

/** Is `reason` one of this module's named refusals? */
export function isNamedExternalPqReason(reason: unknown): boolean {
  return typeof reason === 'string' && NAMED_REASONS.has(reason);
}

/** A refusal: a named reason plus an operator-readable detail. Never thrown. */
export interface ExternalPqRefusal {
  ok: false;
  reason: string;
  detail: string;
}

/** What the remote is asked to sign, and how it is told to give up. */
export interface ExternalPqSignRequest {
  /** The exact bytes to sign. A private copy: mutating it changes nothing. */
  bytes: Buffer;
  /** The operator's stable, auditable identifier for the remote key. */
  keyId: string;
  algorithm: 'ML-DSA-65';
  /** The operator's declared custody kind. Passed through, never checked. */
  custody: ExternalPqCustodyKind;
  /** Aborted at the deadline and on caller cancellation. Honour it. */
  signal: AbortSignal;
  /** The deadline this call is being held to. */
  timeoutMs: number;
  /** Caller context (request ids, tenant, tracing). Never key material. */
  context: Record<string, unknown>;
}

/**
 * The one function an adapter supplies. Return the raw 3309-byte ML-DSA-65
 * signature (Uint8Array/Buffer) or its base64url encoding. Anything else,
 * including a rejection, is a refusal on this side.
 */
export type ExternalPqSignFn = (request: ExternalPqSignRequest) => Promise<unknown> | unknown;

export interface ExternalPqCustodyOptions {
  /** Stable, auditable identifier for the remote key. */
  keyId: string;
  /** The operator's declaration about where the secret key lives. */
  custody: ExternalPqCustodyKind;
  /** The remote signing callback. */
  sign: ExternalPqSignFn;
  /** base64url of the raw 1952-byte ML-DSA-65 public key, or those bytes. */
  publicKey: string | Uint8Array;
  /** Per-call deadline in ms. Default DEFAULT_EXTERNAL_PQ_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Process-lifetime cancellation (shutdown). Aborts every in-flight call. */
  signal?: AbortSignal;
  /**
   * Cryptographically verify every returned signature against `publicKey`
   * before handing it out. Default TRUE. Setting it false keeps the encoding
   * and length pins but accepts a signature this process never checked, which
   * is a real weakening: a remote signing under a different key, or returning
   * a replayed or all-zero buffer of the right length, is then caught only by
   * the relying party.
   */
  verifyOnSign?: boolean;
  /** Inject an ML-DSA backend for verify-on-sign instead of loading one. */
  mldsaBackend?: AgilityMldsaBackend | null;
  /**
   * Free-form operator evidence for the custody declaration (a ticket, a
   * policy id, an attestation document reference). Recorded verbatim and
   * never interpreted; it does not make the declaration verified.
   */
  attestation?: string | null;
}

/** The recorded custody claim. `verified_by_code` is always false. */
export interface ExternalPqCustodyDeclaration {
  profile: string;
  kind: ExternalPqCustodyKind;
  declared_by: 'operator';
  /** Always false: no code in this repository can observe a custody boundary. */
  verified_by_code: false;
  attestation: string | null;
}

export type ExternalPqSignResult = { ok: true; sig: string } | ExternalPqRefusal;

/**
 * The PQ leg the hybrid custody seam consumes, plus the external-custody
 * surface. Satisfies PqCustodySigner exactly, so createHybridCustodySigner()
 * takes it with no change.
 */
export interface ExternalPqCustodySigner extends PqCustodySigner {
  readonly profile: string;
  readonly custody: ExternalPqCustodyKind;
  readonly custodyDeclaration: ExternalPqCustodyDeclaration;
  /** base64url of the pinned 1952-byte public key. Validated at construction. */
  readonly publicKeyRawB64u: string;
  readonly timeoutMs: number;
  readonly verifiesOnSign: boolean;
  /** Non-throwing form: a refusal is a value. */
  trySign(bytes: unknown, context?: Record<string, unknown>): Promise<ExternalPqSignResult>;
  /** Fails closed by REJECTING with an ExternalPqCustodyError. */
  sign(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<string>;
}

export type CreateExternalPqCustodySignerResult =
  | { ok: true; signer: ExternalPqCustodySigner }
  | ExternalPqRefusal;

/** The error sign() rejects with. Carries the same named reason trySign returns. */
export class ExternalPqCustodyError extends Error {
  readonly reason: string;
  readonly code: string;
  readonly detail: string;

  constructor(reason: string, detail: string) {
    super(`${EXTERNAL_PQ_CUSTODY_PROFILE}: refusing to sign: ${reason}: ${detail}`);
    this.name = 'ExternalPqCustodyError';
    this.reason = reason;
    this.code = reason;
    this.detail = detail;
  }
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
// Any option whose NAME looks like key material. A general rule rather than a
// list, so no secret-key-shaped option name can be added by omission later.
const SECRET_SHAPED_OPTION_RE = /(secret|private|seed|passphrase|password|pkcs8|pem)/i;
const SECRET_SHAPED_EXACT = new Set(['sk', 'key', 'keyMaterial']);

function refuse(reason: string, detail: string): ExternalPqRefusal {
  return { ok: false, reason, detail };
}

/** Strict base64url with a canonical-encoding round trip. */
function decodeB64u(value: string): Buffer | null {
  if (typeof value !== 'string' || value.length === 0 || !B64URL_RE.test(value)) return null;
  let bytes: Buffer;
  try {
    bytes = Buffer.from(value, 'base64url');
  } catch {
    return null;
  }
  // Buffer.from is lenient about trailing bits; a value that does not
  // re-encode to itself was not a canonical encoding of these bytes.
  if (bytes.toString('base64url') !== value) return null;
  return bytes;
}

function toBytes(value: unknown): Buffer | null {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return null;
}

/**
 * Validate a public key the way the agility verifier does: strict base64url
 * (or raw bytes) at exactly ML_DSA_65_PUBLIC_KEY_BYTES.
 */
export function validateMldsaPublicKey(value: unknown): { ok: true; b64u: string } | ExternalPqRefusal {
  const raw = value instanceof Uint8Array
    ? Buffer.from(value)
    : (typeof value === 'string' ? decodeB64u(value) : null);
  if (!raw) {
    return refuse(
      EXTERNAL_PQ_REASONS.PUBLIC_KEY_INVALID,
      'ML-DSA-65 public key must be raw bytes or a strict base64url encoding of them.',
    );
  }
  if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
    return refuse(
      EXTERNAL_PQ_REASONS.PUBLIC_KEY_INVALID,
      `ML-DSA-65 public key must be exactly ${ML_DSA_65_PUBLIC_KEY_BYTES} bytes, got ${raw.length}.`,
    );
  }
  return { ok: true, b64u: raw.toString('base64url') };
}

/**
 * Validate whatever the remote handed back. Shape only; this is the pin that
 * runs even when verify-on-sign is disabled.
 */
export function validateRemoteSignature(value: unknown): { ok: true; sig: string } | ExternalPqRefusal {
  if (typeof value === 'string') {
    const decoded = decodeB64u(value);
    if (!decoded) {
      return refuse(
        EXTERNAL_PQ_REASONS.SIGNATURE_ENCODING_INVALID,
        'remote returned a string that is not a strict base64url encoding.',
      );
    }
    if (decoded.length !== ML_DSA_65_SIGNATURE_BYTES) {
      return refuse(
        EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID,
        `remote returned ${decoded.length} bytes; ML-DSA-65 signatures are exactly ${ML_DSA_65_SIGNATURE_BYTES}.`,
      );
    }
    return { ok: true, sig: value };
  }
  const bytes = toBytes(value);
  if (!bytes) {
    return refuse(
      EXTERNAL_PQ_REASONS.SIGNATURE_MALFORMED,
      'remote returned neither raw signature bytes nor a base64url string.',
    );
  }
  if (bytes.length !== ML_DSA_65_SIGNATURE_BYTES) {
    return refuse(
      EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID,
      `remote returned ${bytes.length} bytes; ML-DSA-65 signatures are exactly ${ML_DSA_65_SIGNATURE_BYTES}.`,
    );
  }
  return { ok: true, sig: bytes.toString('base64url') };
}

function validateTimeout(value: unknown): { ok: true; timeoutMs: number } | ExternalPqRefusal {
  if (value === undefined) return { ok: true, timeoutMs: DEFAULT_EXTERNAL_PQ_TIMEOUT_MS };
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    return refuse(
      EXTERNAL_PQ_REASONS.TIMEOUT_INVALID,
      'timeoutMs must be a positive integer number of milliseconds.',
    );
  }
  if (value > MAX_EXTERNAL_PQ_TIMEOUT_MS) {
    return refuse(
      EXTERNAL_PQ_REASONS.TIMEOUT_INVALID,
      `timeoutMs must not exceed ${MAX_EXTERNAL_PQ_TIMEOUT_MS}; an unbounded deadline is a hang.`,
    );
  }
  return { ok: true, timeoutMs: value };
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return typeof AbortSignal !== 'undefined' && value instanceof AbortSignal;
}

/**
 * Wrap a remote ML-DSA-65 signing callback as the PQ leg of EP's hybrid
 * custody seam.
 *
 * Never throws: a bad configuration is a returned refusal.
 *
 * @example
 *   const built = createExternalPqCustodySigner({
 *     keyId: 'ep:key:pq#external-1',
 *     custody: 'hsm',                  // OPERATOR DECLARATION, unverifiable here
 *     publicKey: pinnedPublicKeyB64u,  // 1952 bytes
 *     sign: async ({ bytes, signal }) => myBackend.signMldsa65(bytes, { signal }),
 *   });
 *   if (!built.ok) throw new Error(built.reason);
 */
export function createExternalPqCustodySigner(
  options: ExternalPqCustodyOptions,
): CreateExternalPqCustodySignerResult {
  if (!options || typeof options !== 'object') {
    return refuse(
      EXTERNAL_PQ_REASONS.SIGNER_NOT_CONFIGURED,
      'createExternalPqCustodySigner requires an options object.',
    );
  }

  // Property 1, enforced rather than documented: a secret-key-shaped option is
  // refused outright. Ignoring it would leave a caller believing they had
  // handed over a key that is now somewhere in this process.
  for (const name of Object.keys(options)) {
    if (SECRET_SHAPED_OPTION_RE.test(name) || SECRET_SHAPED_EXACT.has(name)) {
      return refuse(
        EXTERNAL_PQ_REASONS.SECRET_KEY_OFFERED,
        `option "${name}" looks like key material. This seam takes a sign callback and a public key only; `
        + 'no ML-DSA-65 secret key is accepted, derived, or stored here. For a software-held key use '
        + 'lib/custody-signers.ts#softwareMldsaSigner, which says software.',
      );
    }
  }

  const keyId = options.keyId;
  if (typeof keyId !== 'string' || keyId.trim() === '') {
    return refuse(
      EXTERNAL_PQ_REASONS.KEY_ID_INVALID,
      'a stable, auditable keyId is required for the external PQ leg.',
    );
  }

  const custody = options.custody as ExternalPqCustodyKind;
  if (!(EXTERNAL_PQ_CUSTODY_KINDS as readonly string[]).includes(custody)) {
    return refuse(
      EXTERNAL_PQ_REASONS.CUSTODY_KIND_INVALID,
      `custody must be one of ${EXTERNAL_PQ_CUSTODY_KINDS.join(', ')}. `
      + 'A software-held key is not an external custody signer and must use '
      + 'lib/custody-signers.ts#softwareMldsaSigner instead.',
    );
  }

  if (typeof options.sign !== 'function') {
    return refuse(
      EXTERNAL_PQ_REASONS.SIGNER_NOT_CONFIGURED,
      'a sign(request) callback reaching the external signing backend is required.',
    );
  }
  const remoteSign = options.sign;

  const pk = validateMldsaPublicKey(options.publicKey);
  if (!pk.ok) return pk;
  const publicKeyB64u = pk.b64u;

  const timeout = validateTimeout(options.timeoutMs);
  if (!timeout.ok) return timeout;
  const timeoutMs = timeout.timeoutMs;

  if (options.signal !== undefined && options.signal !== null && !isAbortSignal(options.signal)) {
    return refuse(
      EXTERNAL_PQ_REASONS.SIGNER_NOT_CONFIGURED,
      'signal must be an AbortSignal when supplied.',
    );
  }

  const lifetimeSignal = isAbortSignal(options.signal) ? options.signal : null;
  const verifyOnSign = options.verifyOnSign !== false;
  const injectedBackend = options.mldsaBackend ?? null;
  const declaration: ExternalPqCustodyDeclaration = Object.freeze({
    profile: EXTERNAL_PQ_CUSTODY_PROFILE,
    kind: custody,
    declared_by: 'operator' as const,
    verified_by_code: false as const,
    attestation: typeof options.attestation === 'string' ? options.attestation : null,
  });

  async function trySign(
    bytes: unknown,
    context: Record<string, unknown> = {},
  ): Promise<ExternalPqSignResult> {
    const message = toBytes(bytes);
    if (!message) {
      return refuse(
        EXTERNAL_PQ_REASONS.MESSAGE_INVALID,
        'bytes to sign must be a Uint8Array or Buffer.',
      );
    }
    const callContext = (context && typeof context === 'object' && !Array.isArray(context))
      ? context
      : {};
    const callerSignal = isAbortSignal(callContext.signal) ? callContext.signal : null;

    if (lifetimeSignal?.aborted) {
      return refuse(EXTERNAL_PQ_REASONS.SIGNER_CANCELLED, 'the signer lifetime signal is already aborted.');
    }
    if (callerSignal?.aborted) {
      return refuse(EXTERNAL_PQ_REASONS.SIGNER_CANCELLED, 'the caller signal is already aborted.');
    }

    const controller = new AbortController();
    // One handler for both signals: abort the request the remote was given AND
    // settle the cancellation arm of the race. Registered once and removed in
    // the finally below, so a long-lived shutdown signal does not accumulate a
    // listener per signing call.
    let resolveCancelled: ((refusal: ExternalPqRefusal) => void) | null = null;
    const cancellation = new Promise<ExternalPqRefusal>((resolve) => { resolveCancelled = resolve; });
    const onAbort = () => {
      controller.abort();
      resolveCancelled?.(refuse(
        EXTERNAL_PQ_REASONS.SIGNER_CANCELLED,
        'the signing call was cancelled before the external signer answered.',
      ));
    };
    lifetimeSignal?.addEventListener('abort', onAbort, { once: true });
    callerSignal?.addEventListener('abort', onAbort, { once: true });

    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      const request: ExternalPqSignRequest = {
        // A private copy: the remote cannot mutate what we verify against.
        bytes: Buffer.from(message),
        keyId,
        algorithm: 'ML-DSA-65',
        custody,
        signal: controller.signal,
        timeoutMs,
        context: callContext,
      };

      const remote = Promise.resolve().then(() => remoteSign(request));
      // A late rejection after a timeout refusal must not surface as an
      // unhandled rejection; the race below still sees an early one.
      remote.catch(() => {});

      const deadline = new Promise<ExternalPqRefusal>((resolve) => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(refuse(
            EXTERNAL_PQ_REASONS.SIGNER_TIMEOUT,
            `the external signer did not answer within ${timeoutMs} ms.`,
          ));
        }, timeoutMs);
        if (typeof (timer as { unref?: () => void }).unref === 'function') {
          (timer as { unref?: () => void }).unref!();
        }
      });

      let raced: unknown;
      try {
        raced = await Promise.race([
          remote.then((value) => ({ __remote: true, value })),
          deadline,
          cancellation,
        ]);
      } catch (err) {
        return refuse(
          EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE,
          `the external signer failed: ${errorText(err)}`,
        );
      }

      if (isRefusal(raced)) return raced;
      const returned = (raced as { value: unknown }).value;
      if (returned === null || returned === undefined) {
        return refuse(
          EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE,
          'the external signer returned no signature.',
        );
      }

      const shaped = validateRemoteSignature(returned);
      if (!shaped.ok) return shaped;

      if (!verifyOnSign) return shaped;

      // Same closed registry, same pins, same reason names as every EP
      // verifier: packages/verify/src/pq-signature-agility.ts.
      const verdict = await verifyAgileSignature(
        new Uint8Array(message),
        { alg: 'ML-DSA-65', sig: shaped.sig, key_id: keyId },
        { alg: 'ML-DSA-65', public_key: publicKeyB64u, key_id: keyId },
        injectedBackend ? { mldsaBackend: injectedBackend } : {},
      );
      if (verdict.verified === true) return shaped;

      const reason = verdict.reason === AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE
        ? EXTERNAL_PQ_REASONS.PQ_BACKEND_UNAVAILABLE
        : EXTERNAL_PQ_REASONS.SIGNATURE_INVALID;
      return refuse(
        reason,
        reason === EXTERNAL_PQ_REASONS.PQ_BACKEND_UNAVAILABLE
          ? 'no ML-DSA backend is available to check the external signature; refusing rather than '
            + 'emitting an unchecked one. Install an ML-DSA-65 backend or set verifyOnSign:false '
            + 'and accept that weakening explicitly.'
          : `the external signature does not verify under the pinned public key for ${keyId} `
            + `(agility reason: ${String(verdict.reason)}).`,
      );
    } catch (err) {
      // Defensive: nothing above is expected to throw, and a throw escaping
      // this seam would be an unnamed failure.
      return refuse(
        EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE,
        `the external signing call failed unexpectedly: ${errorText(err)}`,
      );
    } finally {
      if (timer) clearTimeout(timer);
      lifetimeSignal?.removeEventListener('abort', onAbort);
      callerSignal?.removeEventListener('abort', onAbort);
    }
  }

  const signer: ExternalPqCustodySigner = {
    keyId,
    algorithm: 'ML-DSA-65',
    custody,
    profile: EXTERNAL_PQ_CUSTODY_PROFILE,
    custodyDeclaration: declaration,
    publicKeyRawB64u: publicKeyB64u,
    timeoutMs,
    verifiesOnSign: verifyOnSign,
    trySign,
    async sign(bytes, context = {}) {
      const result = await trySign(bytes, context);
      if (!result.ok) throw new ExternalPqCustodyError(result.reason, result.detail);
      return result.sig;
    },
  };
  return { ok: true, signer };
}

function isRefusal(value: unknown): value is ExternalPqRefusal {
  return !!value
    && typeof value === 'object'
    && (value as ExternalPqRefusal).ok === false
    && typeof (value as ExternalPqRefusal).reason === 'string';
}

function errorText(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return String(err);
}

/** Is this an external PQ custody signer built by this module? */
export function isExternalPqCustodySigner(value: unknown): value is ExternalPqCustodySigner {
  const s = value as ExternalPqCustodySigner | null | undefined;
  return !!s
    && s.profile === EXTERNAL_PQ_CUSTODY_PROFILE
    && s.algorithm === 'ML-DSA-65'
    && typeof s.trySign === 'function'
    && (EXTERNAL_PQ_CUSTODY_KINDS as readonly string[]).includes(s.custody);
}

/**
 * Boot-time pin: refuse a registered signer whose PQ leg is not externally
 * custodied. This is the check that makes "we run external PQ custody" a
 * verifiable configuration statement instead of an intention. An operator who
 * meant to move off the software backend and did not is told so, rather than
 * issuing under software custody that reads as external in a deployment doc.
 */
export function requireExternalPqLeg(
  signer: CustodySigner | null | undefined,
): { ok: true; signer: ExternalPqCustodySigner } | ExternalPqRefusal {
  if (!isHybridCustodySigner(signer)) {
    return refuse(
      EXTERNAL_PQ_REASONS.LEG_MISSING,
      'the registered custody signer carries no ML-DSA-65 leg.',
    );
  }
  const pq = signer.hybrid.pq;
  if (!isExternalPqCustodySigner(pq)) {
    return refuse(
      EXTERNAL_PQ_REASONS.LEG_NOT_EXTERNAL,
      `the ML-DSA-65 leg declares custody "${String((pq as PqCustodySigner)?.custody)}" and was not built by `
      + `${EXTERNAL_PQ_CUSTODY_PROFILE}. A software-held PQ key does not become external by configuration.`,
    );
  }
  return { ok: true, signer: pq };
}

// ---------------------------------------------------------------------------
// Adapter conformance harness
//
// EVERY provider adapter must pass this UNCHANGED. It is the definition of
// "this adapter works", and it is deliberately hostile: it checks what the
// adapter does with bytes it has never seen, not that it can reproduce a
// fixture. It never throws; an adapter that throws is reported as a failed
// case.
// ---------------------------------------------------------------------------

export interface PqCustodyConformanceCase {
  name: string;
  ok: boolean;
  reason: string | null;
  detail: string | null;
}

export interface PqCustodyConformanceReport {
  profile: string;
  ok: boolean;
  keyId: string | null;
  custody: string | null;
  cases: PqCustodyConformanceCase[];
  /** Names of the cases that failed, in order. Convenience for assertions. */
  failed: string[];
}

export interface PqCustodyConformanceOptions {
  /** Backend used for the harness's own verification. Default: loaded lazily. */
  mldsaBackend?: AgilityMldsaBackend | null;
}

/** The adapter under test, as a value, a construction result, or a factory. */
export type PqCustodyConformanceCandidate =
  | ExternalPqCustodySigner
  | CreateExternalPqCustodySignerResult
  | (() => ExternalPqCustodySigner | CreateExternalPqCustodySignerResult
    | Promise<ExternalPqCustodySigner | CreateExternalPqCustodySignerResult>);

const CONFORMANCE_CASES = Object.freeze([
  'adapter_constructs',
  'custody_declared_external',
  'public_key_pinned',
  'no_secret_key_surface',
  'timeout_bounded',
  'signs_bound_message',
  'signature_is_message_bound',
  'refuses_malformed_message',
  'sign_fails_closed',
] as const);

/** The case names any adapter is judged on, in run order. */
export const PQ_CUSTODY_CONFORMANCE_CASES = CONFORMANCE_CASES;

function randomMessage(label: string): Buffer {
  // Node's webcrypto is always present; keeping the harness free of a
  // node:crypto import keeps it usable from the same places the seam is.
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return Buffer.concat([Buffer.from(`${EXTERNAL_PQ_CUSTODY_PROFILE}/${label}/`, 'utf8'), Buffer.from(nonce)]);
}

function namedReason(reason: unknown): string {
  return isNamedExternalPqReason(reason) ? String(reason) : EXTERNAL_PQ_REASONS.REFUSAL_UNNAMED;
}

/**
 * Run the adapter conformance battery. Returns a report; never throws.
 *
 * A conforming adapter reports ok:true on every case. A failing case names the
 * refusal that made it fail, so a provider integration reads its own error.
 */
export async function runExternalPqCustodyConformance(
  candidate: PqCustodyConformanceCandidate,
  options: PqCustodyConformanceOptions = {},
): Promise<PqCustodyConformanceReport> {
  const cases: PqCustodyConformanceCase[] = [];
  const record = (name: string, ok: boolean, reason: string | null = null, detail: string | null = null) => {
    cases.push({ name, ok, reason, detail });
  };
  const finish = (keyId: string | null, custody: string | null): PqCustodyConformanceReport => {
    const failed = cases.filter((c) => !c.ok).map((c) => c.name);
    return {
      profile: EXTERNAL_PQ_CUSTODY_PROFILE,
      ok: failed.length === 0,
      keyId,
      custody,
      cases,
      failed,
    };
  };
  const skipRemaining = (from: number) => {
    for (const name of CONFORMANCE_CASES.slice(from)) {
      record(name, false, EXTERNAL_PQ_REASONS.SIGNER_NOT_CONFIGURED, 'not run: the adapter did not construct.');
    }
  };

  // 1. adapter_constructs
  let signer: ExternalPqCustodySigner | null = null;
  try {
    const resolved = typeof candidate === 'function' ? await candidate() : candidate;
    if (isExternalPqCustodySigner(resolved)) {
      signer = resolved;
    } else if (resolved && typeof resolved === 'object' && (resolved as { ok?: unknown }).ok === true) {
      const built = (resolved as { signer?: unknown }).signer;
      if (isExternalPqCustodySigner(built)) signer = built;
    } else if (isRefusal(resolved)) {
      record('adapter_constructs', false, namedReason(resolved.reason), resolved.detail);
    }
    if (!signer && cases.length === 0) {
      record(
        'adapter_constructs',
        false,
        EXTERNAL_PQ_REASONS.SIGNER_NOT_CONFIGURED,
        'the candidate did not yield an EP-PQ-CUSTODY-EXTERNAL-v1 signer.',
      );
    }
  } catch (err) {
    record('adapter_constructs', false, EXTERNAL_PQ_REASONS.ADAPTER_THREW, errorText(err));
  }
  if (!signer) {
    skipRemaining(1);
    return finish(null, null);
  }
  record('adapter_constructs', true);

  const keyId = typeof signer.keyId === 'string' ? signer.keyId : null;
  const custody = typeof signer.custody === 'string' ? signer.custody : null;

  // 2. custody_declared_external
  if ((EXTERNAL_PQ_CUSTODY_KINDS as readonly string[]).includes(signer.custody) && signer.custody !== ('software' as string)) {
    record('custody_declared_external', true);
  } else {
    record(
      'custody_declared_external',
      false,
      EXTERNAL_PQ_REASONS.CUSTODY_KIND_INVALID,
      `custody is "${String(signer.custody)}"; an external adapter declares one of ${EXTERNAL_PQ_CUSTODY_KINDS.join(', ')}.`,
    );
  }

  // 3. public_key_pinned
  let publicKeyB64u: string | null = null;
  const pkCheck = validateMldsaPublicKey(signer.publicKeyRawB64u);
  if (pkCheck.ok) {
    publicKeyB64u = pkCheck.b64u;
    record('public_key_pinned', true);
  } else {
    record('public_key_pinned', false, pkCheck.reason, pkCheck.detail);
  }

  // 4. no_secret_key_surface
  const surfaced: string[] = [];
  for (const name of Object.keys(signer as unknown as Record<string, unknown>)) {
    if (SECRET_SHAPED_OPTION_RE.test(name) || SECRET_SHAPED_EXACT.has(name)) surfaced.push(name);
  }
  for (const [name, value] of Object.entries(signer as unknown as Record<string, unknown>)) {
    const bytes = toBytes(value);
    // 4032 is the FIPS 204 ML-DSA-65 secret key size. A member of that size on
    // a signer that is supposed to hold no key is the thing to catch.
    if (bytes && bytes.length === 4032) surfaced.push(name);
  }
  if (surfaced.length === 0) {
    record('no_secret_key_surface', true);
  } else {
    record(
      'no_secret_key_surface',
      false,
      EXTERNAL_PQ_REASONS.SECRET_KEY_SURFACE,
      `signer exposes key-material-shaped members: ${surfaced.join(', ')}.`,
    );
  }

  // 5. timeout_bounded
  if (Number.isInteger(signer.timeoutMs) && signer.timeoutMs > 0 && signer.timeoutMs <= MAX_EXTERNAL_PQ_TIMEOUT_MS) {
    record('timeout_bounded', true);
  } else {
    record(
      'timeout_bounded',
      false,
      EXTERNAL_PQ_REASONS.TIMEOUT_INVALID,
      `timeoutMs is ${String(signer.timeoutMs)}; a hung remote must become a refusal at a bounded deadline.`,
    );
  }

  // 6. signs_bound_message: a fresh message the adapter has never seen, and
  //    the signature must verify under the adapter's OWN pinned public key.
  const messageA = randomMessage('case6');
  let sigA: string | null = null;
  const signA = await callTrySign(signer, messageA);
  if (!signA.ok) {
    record('signs_bound_message', false, namedReason(signA.reason), signA.detail);
  } else if (!publicKeyB64u) {
    record(
      'signs_bound_message',
      false,
      EXTERNAL_PQ_REASONS.PUBLIC_KEY_INVALID,
      'cannot check the signature: the adapter pins no usable public key.',
    );
  } else {
    const shaped = validateRemoteSignature(signA.sig);
    if (!shaped.ok) {
      record('signs_bound_message', false, shaped.reason, shaped.detail);
    } else {
      const verdict = await verifyOne(messageA, shaped.sig, publicKeyB64u, options);
      if (verdict.ok) {
        sigA = shaped.sig;
        record('signs_bound_message', true);
      } else {
        record('signs_bound_message', false, verdict.reason, verdict.detail);
      }
    }
  }

  // 7. signature_is_message_bound: the signature over A must NOT verify over a
  //    different message B. Catches a cached, constant, or replayed signature,
  //    which is exactly what a shape-only check lets through.
  if (!sigA || !publicKeyB64u) {
    record(
      'signature_is_message_bound',
      false,
      EXTERNAL_PQ_REASONS.SIGNATURE_NOT_MESSAGE_BOUND,
      'not run: no verified signature from the previous case.',
    );
  } else {
    const messageB = randomMessage('case7');
    const crossed = await verifyOne(messageB, sigA, publicKeyB64u, options);
    if (crossed.ok) {
      record(
        'signature_is_message_bound',
        false,
        EXTERNAL_PQ_REASONS.SIGNATURE_NOT_MESSAGE_BOUND,
        'a signature over one message verified over a different one.',
      );
    } else if (crossed.reason === EXTERNAL_PQ_REASONS.PQ_BACKEND_UNAVAILABLE) {
      record('signature_is_message_bound', false, crossed.reason, crossed.detail);
    } else {
      record('signature_is_message_bound', true);
    }
  }

  // 8. refuses_malformed_message: caller input is a named refusal, not a throw
  //    and never a value that could be mistaken for a signature.
  let malformed: ExternalPqSignResult | null = null;
  let threw: string | null = null;
  try {
    malformed = await signer.trySign('not-bytes' as unknown);
  } catch (err) {
    threw = errorText(err);
  }
  if (threw) {
    record('refuses_malformed_message', false, EXTERNAL_PQ_REASONS.ADAPTER_THREW, threw);
  } else if (malformed && malformed.ok) {
    record(
      'refuses_malformed_message',
      false,
      EXTERNAL_PQ_REASONS.MESSAGE_INVALID,
      'the adapter signed something that was not a byte sequence.',
    );
  } else if (malformed && namedReason(malformed.reason) === EXTERNAL_PQ_REASONS.REFUSAL_UNNAMED) {
    record('refuses_malformed_message', false, EXTERNAL_PQ_REASONS.REFUSAL_UNNAMED, String(malformed.reason));
  } else {
    record('refuses_malformed_message', true);
  }

  // 9. sign_fails_closed: the throwing form either returns a signature that
  //    passes the same pins, or rejects with a NAMED reason. It must never
  //    resolve to anything else.
  try {
    const value = await signer.sign(randomMessage('case9'));
    const shaped = validateRemoteSignature(value);
    if (shaped.ok) record('sign_fails_closed', true);
    else record('sign_fails_closed', false, shaped.reason, 'sign() resolved to a value that is not a signature.');
  } catch (err) {
    const reason = (err as ExternalPqCustodyError)?.reason;
    if (isNamedExternalPqReason(reason)) {
      record('sign_fails_closed', true);
    } else {
      record('sign_fails_closed', false, EXTERNAL_PQ_REASONS.REFUSAL_UNNAMED, errorText(err));
    }
  }

  return finish(keyId, custody);
}

async function callTrySign(
  signer: ExternalPqCustodySigner,
  message: Buffer,
): Promise<{ ok: true; sig: string } | { ok: false; reason: string; detail: string }> {
  try {
    const result = await signer.trySign(message);
    if (result.ok) return result;
    return { ok: false, reason: namedReason(result.reason), detail: result.detail };
  } catch (err) {
    return { ok: false, reason: EXTERNAL_PQ_REASONS.ADAPTER_THREW, detail: errorText(err) };
  }
}

async function verifyOne(
  message: Buffer,
  sig: string,
  publicKeyB64u: string,
  options: PqCustodyConformanceOptions,
): Promise<{ ok: true } | { ok: false; reason: string; detail: string }> {
  try {
    const verdict = await verifyAgileSignature(
      new Uint8Array(message),
      { alg: 'ML-DSA-65', sig },
      { alg: 'ML-DSA-65', public_key: publicKeyB64u },
      options.mldsaBackend ? { mldsaBackend: options.mldsaBackend } : {},
    );
    if (verdict.verified === true) return { ok: true };
    if (verdict.reason === AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE) {
      return {
        ok: false,
        reason: EXTERNAL_PQ_REASONS.PQ_BACKEND_UNAVAILABLE,
        detail: 'no ML-DSA backend is available to run the harness; a skipped check is not a pass.',
      };
    }
    return {
      ok: false,
      reason: EXTERNAL_PQ_REASONS.SIGNATURE_INVALID,
      detail: `agility verdict: ${String(verdict.reason)}.`,
    };
  } catch (err) {
    return { ok: false, reason: EXTERNAL_PQ_REASONS.ADAPTER_THREW, detail: errorText(err) };
  }
}

const externalPqCustody = {
  EXTERNAL_PQ_CUSTODY_PROFILE,
  EXTERNAL_PQ_CUSTODY_KINDS,
  EXTERNAL_PQ_REASONS,
  createExternalPqCustodySigner,
  isExternalPqCustodySigner,
  requireExternalPqLeg,
  runExternalPqCustodyConformance,
  validateMldsaPublicKey,
  validateRemoteSignature,
};
export default externalPqCustody;
