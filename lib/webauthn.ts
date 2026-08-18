// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — WebAuthn helpers (docs/WEBAUTHN-SIGNOFF.md).
//
// The one non-negotiable, from the EP draft §5.1: the WebAuthn challenge IS
// the context hash — SHA-256 over the JCS-canonical Authorization Context.
// The context contains the action hash, the nonce, and the expiry, so the
// challenge is action-bound and single-use by construction: a replayed
// assertion fails at the WebAuthn layer (wrong challenge) and at the
// consumption layer (spent nonce).
//
// EP DOES NOT SUPPORT POST-QUANTUM WEBAUTHN TODAY. No browser, platform
// passkey provider, or certified authenticator produces an ML-DSA WebAuthn
// credential or assertion, and the FIDO Registry v2.3 carries no ALG_SIGN
// constant for ML-DSA, so certified hardware cannot even declare it. What this
// module carries is the RELYING-PARTY half -- EP's own code, never FIDO-gated
// -- built and tested against synthetic keys so EP can verify a PQ credential
// the day one exists. Until then every ML-DSA path refuses by name, and the
// default for every existing call site is ES256 only.

import crypto from 'node:crypto';
import { Decoder } from 'cbor-x';
import { getWebAuthnConfig } from './env.js';
import { canonicalize as canonicalizeJson } from './canonical-json.js';
import type { SignoffCeremonyBinding } from './signoff/ceremony-policy.js';

export interface RpConfig {
  rpName: string;
  rpID: string;
  origin: string;
}

// rpID is the registrable domain so credentials work on www and any future
// subdomain; origin must match the page the approver actually signs on.
export function getRpConfig(): RpConfig {
  const { rpId, origin, isDevelopment } = getWebAuthnConfig();
  return {
    rpName: 'EMILIA Protocol',
    rpID: rpId || (isDevelopment ? 'localhost' : 'emiliaprotocol.ai'),
    origin: origin || (isDevelopment
        ? 'http://localhost:3000'
        : 'https://www.emiliaprotocol.ai'),
  };
}

// Use the repository's checked-in canonicalization source of truth. The
// portable verifier remains byte-compatible for the EP I-JSON profile, while
// this server-side signer now refuses undefined, unsafe numbers, and other
// values that cannot be reproduced across implementations.
export const canonicalize = canonicalizeJson;

export interface AuthorizationContextParams {
  actionHash: string;
  policyId?: string | null;
  policyHash?: string | null;
  initiatorId: string;
  approverId: string;
  signoffId: string;
  issuedAt: string;
  expiresAt: string;
  decision?: 'approved' | 'denied' | null;
  displayHash?: string | null;
  ceremony?: SignoffCeremonyBinding | null;
}

export interface AuthorizationContext {
  ep_version: string;
  context_type: string;
  action_hash: string;
  policy_id: string | null;
  policy_hash: string | null;
  initiator: string;
  approver: string;
  approver_index: number;
  required_approvals: number;
  nonce: string;
  issued_at: string;
  expires_at: string;
  decision?: 'approved' | 'denied';
  display_hash?: string;
  ceremony?: SignoffCeremonyBinding;
}

/**
 * Build the Authorization Context an approver signs (EP draft §4).
 * The signoff_id doubles as the nonce: sig_<32hex> is 128 bits of CSPRNG
 * output, globally unique per authorization attempt.
 */
export function buildAuthorizationContext({
  actionHash,
  policyId,
  policyHash,
  initiatorId,
  approverId,
  signoffId,
  issuedAt,
  expiresAt,
  decision = null,
  displayHash = null,
  ceremony = null,
}: AuthorizationContextParams): AuthorizationContext {
  if (decision !== null && decision !== 'approved' && decision !== 'denied') {
    throw new TypeError('decision must be approved, denied, or null');
  }
  const ctx: AuthorizationContext = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash: actionHash,
    policy_id: policyId || null,
    policy_hash: policyHash || null,
    initiator: initiatorId,
    approver: approverId,
    approver_index: 1,
    required_approvals: 1,
    nonce: signoffId,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  // Approval and denial are co-equal signed outcomes. New ceremonies always
  // supply this field; keeping null as an omission preserves verification of
  // pre-parity contexts while preventing callers from smuggling another value.
  if (decision) ctx.decision = decision;
  // WYSIWYS (EP draft §11.3): when the human-visible rendering is known, bind
  // its display_hash INTO the signed context so the approver's signature covers
  // what was displayed — not just the action hash. Conditional so existing
  // no-display flows hash byte-identically (back-compat).
  if (displayHash) ctx.display_hash = displayHash;
  // Class-A ceremony policy is signed alongside the action and display. The
  // canonical round-trip both detaches the caller's object and rejects values
  // that cannot be reproduced by an offline verifier.
  if (ceremony) ctx.ceremony = JSON.parse(canonicalizeJson(ceremony));
  return ctx;
}

/** SHA-256 of the canonical context — raw bytes (the WebAuthn challenge). */
export function contextHashBytes(context: unknown): Buffer {
  return crypto.createHash('sha256').update(canonicalize(context), 'utf8').digest();
}

/** Hex form, for storage/display alongside the b64u challenge. */
export function contextHashHex(context: unknown): string {
  return contextHashBytes(context).toString('hex');
}

// Uncompressed-point SPKI header for P-256 (id-ecPublicKey + prime256v1 +
// BIT STRING of 65 bytes). Constant by construction; the point follows.
const P256_SPKI_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex',
);

// SPKI header for an ML-DSA-65 public key: SEQUENCE { SEQUENCE { OID
// 2.16.840.1.101.3.4.3.18 (id-ml-dsa-65) }, BIT STRING(1953, 0 unused) }.
// Constant by construction because the FIPS 204 ML-DSA-65 public key is a
// fixed 1952 bytes, so prefix || raw IS the whole encoding. Cross-checked
// against node's own SPKI export in tests/webauthn-lib.test.ts so it cannot
// silently drift.
const ML_DSA_65_SPKI_PREFIX = Buffer.from(
  '308207b2300b0609608648016503040312038207a100',
  'hex',
);
const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;

/** COSE key types used by Class A credentials: EC2 (RFC 9052), AKP (RFC 9964). */
const COSE_KTY_EC2 = 2;
const COSE_KTY_AKP = 7;
/** IANA COSE algorithm identifiers. ML-DSA-65 = -49 is assigned by RFC 9964. */
const COSE_ALG_ES256 = -7;
const COSE_ALG_ML_DSA_65 = -49;

/** The Class A credential algorithms this module can convert. */
export const WEBAUTHN_COSE_ALGORITHMS = Object.freeze(['ES256', 'ML-DSA-65'] as const);
export type WebAuthnCoseAlgorithm = (typeof WEBAUTHN_COSE_ALGORITHMS)[number];

/**
 * PER-ALGORITHM input caps, applied BEFORE the CBOR decoder ever sees the
 * bytes, so a hostile oversized or deeply-nested key cannot exhaust memory or
 * the stack (DoS via WebAuthn registration, NASTY-4). This is deliberately NOT
 * one global cap raised to fit the largest algorithm: an ES256 credential is
 * still held to the same 1 KiB it always was, and only a caller that has opted
 * into ML-DSA-65 gets the larger bound.
 *
 *   ES256      real COSE key ~77 bytes   -> 1024 (~13x, unchanged)
 *   ML-DSA-65  real COSE key ~1962 bytes -> 2048 (just above the real size)
 */
export const COSE_KEY_MAX_BYTES: Readonly<Record<WebAuthnCoseAlgorithm, number>> = Object.freeze({
  ES256: 1024,
  'ML-DSA-65': 2048,
});

export interface CoseToSpkiOptions {
  /**
   * The algorithms this conversion will accept. Defaults to ES256 ONLY --
   * fail-closed: a caller that has not thought about ML-DSA-65 does not
   * silently start accepting it.
   */
  allowedAlgorithms?: readonly WebAuthnCoseAlgorithm[];
}

function normalizeAllowed(allowed: readonly WebAuthnCoseAlgorithm[] | undefined): WebAuthnCoseAlgorithm[] {
  const list = allowed === undefined ? (['ES256'] as const) : allowed;
  if (!Array.isArray(list) || list.length === 0) {
    throw new TypeError('allowedAlgorithms must be a non-empty array');
  }
  for (const alg of list) {
    if (!(WEBAUTHN_COSE_ALGORITHMS as readonly string[]).includes(alg)) {
      throw new Error(`Unsupported COSE algorithm "${String(alg)}"`);
    }
  }
  return [...new Set(list)];
}

/**
 * Convert a registered COSE public key (what WebAuthn hands back) into SPKI
 * DER, the form the zero-dependency offline verifier consumes with nothing but
 * node:crypto. Throws on anything outside `allowedAlgorithms`.
 *
 * ML-DSA-65 IS NOT PRODUCED BY ANY AUTHENTICATOR TODAY. No browser, platform
 * passkey provider, or certified authenticator emits an ML-DSA WebAuthn
 * credential, and the FIDO Registry v2.3 has no ALG_SIGN constant for ML-DSA,
 * so certified hardware cannot declare it. This branch exists so the relying-
 * party half -- which was never FIDO-gated, because it is EP's own code -- is
 * ready and provably correct against synthetic keys before the ecosystem
 * arrives. Enabling it does not make a PQ credential appear.
 */
export function coseToSpki(
  coseKeyBytes: Uint8Array | Buffer | null | undefined,
  options: CoseToSpkiOptions = {},
): Buffer {
  const allowed = normalizeAllowed(options.allowedAlgorithms);
  const bytes = coseKeyBytes instanceof Uint8Array ? coseKeyBytes : new Uint8Array(coseKeyBytes || []);
  if (bytes.length === 0) throw new Error('COSE key is empty');
  // Pre-decode cap: the largest bound among the ALLOWED algorithms. The tight
  // per-algorithm bound is re-applied below once the key names its algorithm.
  const preDecodeCap = Math.max(...allowed.map((alg) => COSE_KEY_MAX_BYTES[alg]));
  if (bytes.length > preDecodeCap) {
    throw new Error(`COSE key too large (${bytes.length} bytes, max ${preDecodeCap})`);
  }
  const decoded = new Decoder({ mapsAsObjects: false }).decode(bytes);
  if (!(decoded instanceof Map)) throw new Error('COSE key is not a CBOR map');

  const kty = decoded.get(1);
  const alg = decoded.get(3);

  const enforceTightBound = (name: WebAuthnCoseAlgorithm): void => {
    const cap = COSE_KEY_MAX_BYTES[name];
    if (bytes.length > cap) {
      throw new Error(`COSE key too large for ${name} (${bytes.length} bytes, max ${cap})`);
    }
  };

  if (kty === COSE_KTY_AKP && allowed.includes('ML-DSA-65')) {
    if (alg !== COSE_ALG_ML_DSA_65) throw new Error(`Unsupported COSE alg ${alg} (want ML-DSA-65)`);
    enforceTightBound('ML-DSA-65');
    // RFC 9964 AKP key: the public key lives at label -1 ("pub").
    const pub = decoded.get(-1);
    if (!(pub instanceof Uint8Array) || pub.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
      throw new Error('Bad COSE ML-DSA-65 public key');
    }
    const spki = Buffer.concat([ML_DSA_65_SPKI_PREFIX, Buffer.from(pub)]);
    // Round-trip through node:crypto exactly as the P-256 path does. On a
    // runtime with no ML-DSA provider this throws, which is the honest
    // outcome: EP refuses to store a credential it could not verify.
    const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    if (keyObject.asymmetricKeyType !== 'ml-dsa-65') {
      throw new Error('Bad COSE ML-DSA-65 public key');
    }
    return spki;
  }

  const wantKty = allowed.includes('ML-DSA-65')
    ? allowed.includes('ES256') ? 'EC2 or AKP' : 'AKP'
    : 'EC2';
  if (kty !== COSE_KTY_EC2) throw new Error(`Unsupported COSE kty ${kty} (want ${wantKty})`);
  if (!allowed.includes('ES256')) throw new Error(`Unsupported COSE kty ${kty} (want ${wantKty})`);

  const crv = decoded.get(-1);
  const x = decoded.get(-2);
  const y = decoded.get(-3);

  if (alg !== COSE_ALG_ES256) throw new Error(`Unsupported COSE alg ${alg} (want ES256)`);
  enforceTightBound('ES256');
  if (crv !== 1) throw new Error(`Unsupported COSE crv ${crv} (want P-256)`);
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error('Bad COSE x coordinate');
  if (!(y instanceof Uint8Array) || y.length !== 32) throw new Error('Bad COSE y coordinate');

  const spki = Buffer.concat([P256_SPKI_PREFIX, Buffer.from([0x04]), x, y]);
  // Round-trip through node:crypto so a malformed point is rejected at
  // enrollment, not discovered at verification time.
  crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return spki;
}

/**
 * ES256-PINNED conversion. This is the frozen contract every existing Class A
 * enrollment call site uses: same accepted keys, same 1 KiB cap, same error
 * strings as before algorithm dispatch existed. A caller that wants ML-DSA-65
 * must ask for it explicitly through coseToSpki().
 */
export function coseToSpkiP256(coseKeyBytes: Uint8Array | Buffer | null | undefined): Buffer {
  return coseToSpki(coseKeyBytes, { allowedAlgorithms: ['ES256'] });
}

export const APPROVER_ID_PATTERN = /^[A-Za-z0-9:_.@-]{3,128}$/;
export const SIGNOFF_ID_PATTERN = /^sig_[a-f0-9]{32}$/;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
