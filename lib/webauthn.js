// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — WebAuthn helpers (docs/WEBAUTHN-SIGNOFF.md).
//
// The one non-negotiable, from the EP draft §5.1: the WebAuthn challenge IS
// the context hash — SHA-256 over the JCS-canonical Authorization Context.
// The context contains the action hash, the nonce, and the expiry, so the
// challenge is action-bound and single-use by construction: a replayed
// assertion fails at the WebAuthn layer (wrong challenge) and at the
// consumption layer (spent nonce).

import crypto from 'node:crypto';
import { Decoder } from 'cbor-x';
import { getWebAuthnConfig } from './env.js';

// rpID is the registrable domain so credentials work on www and any future
// subdomain; origin must match the page the approver actually signs on.
export function getRpConfig() {
  const { rpId, origin, isDevelopment } = getWebAuthnConfig();
  return {
    rpName: 'EMILIA Protocol',
    rpID: rpId || (isDevelopment ? 'localhost' : 'emiliaprotocol.ai'),
    origin: origin || (isDevelopment
        ? 'http://localhost:3000'
        : 'https://www.emiliaprotocol.ai'),
  };
}

// Recursive canonical JSON — byte-identical to packages/verify/index.js and
// lib/guard-policies.js. Signer and verifier MUST produce the same bytes;
// if you change one, you break every receipt in the field. Don't.
export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
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
}) {
  if (decision !== null && decision !== 'approved' && decision !== 'denied') {
    throw new TypeError('decision must be approved, denied, or null');
  }
  const ctx = {
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
  return ctx;
}

/** SHA-256 of the canonical context — raw bytes (the WebAuthn challenge). */
export function contextHashBytes(context) {
  return crypto.createHash('sha256').update(canonicalize(context), 'utf8').digest();
}

/** Hex form, for storage/display alongside the b64u challenge. */
export function contextHashHex(context) {
  return contextHashBytes(context).toString('hex');
}

// Uncompressed-point SPKI header for P-256 (id-ecPublicKey + prime256v1 +
// BIT STRING of 65 bytes). Constant by construction; the point follows.
const P256_SPKI_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex',
);

/**
 * Convert a registered COSE EC2/P-256 public key (what WebAuthn hands back —
 * registration is restricted to ES256 via supportedAlgorithmIDs: [-7]) into
 * SPKI DER, the form the zero-dependency offline verifier consumes with
 * nothing but node:crypto. Throws on anything that isn't EC2/ES256/P-256.
 */
export function coseToSpkiP256(coseKeyBytes) {
  const bytes = coseKeyBytes instanceof Uint8Array ? coseKeyBytes : new Uint8Array(coseKeyBytes || []);
  // A COSE EC2/P-256 key is ~77 bytes. Hard-cap the input BEFORE handing it to
  // the CBOR decoder so a hostile oversized / deeply-nested key can't exhaust
  // memory or the stack (DoS via WebAuthn registration). 1 KiB is ~13x the real
  // size — generous but bounded, and far too small to nest a stack-overflowing
  // depth bomb. (NASTY-4)
  if (bytes.length === 0) throw new Error('COSE key is empty');
  if (bytes.length > 1024) throw new Error(`COSE key too large (${bytes.length} bytes, max 1024)`);
  const decoded = new Decoder({ mapsAsObjects: false }).decode(bytes);
  if (!(decoded instanceof Map)) throw new Error('COSE key is not a CBOR map');

  const kty = decoded.get(1);
  const alg = decoded.get(3);
  const crv = decoded.get(-1);
  const x = decoded.get(-2);
  const y = decoded.get(-3);

  if (kty !== 2) throw new Error(`Unsupported COSE kty ${kty} (want EC2)`);
  if (alg !== -7) throw new Error(`Unsupported COSE alg ${alg} (want ES256)`);
  if (crv !== 1) throw new Error(`Unsupported COSE crv ${crv} (want P-256)`);
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error('Bad COSE x coordinate');
  if (!(y instanceof Uint8Array) || y.length !== 32) throw new Error('Bad COSE y coordinate');

  const spki = Buffer.concat([P256_SPKI_PREFIX, Buffer.from([0x04]), x, y]);
  // Round-trip through node:crypto so a malformed point is rejected at
  // enrollment, not discovered at verification time.
  crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return spki;
}

export const APPROVER_ID_PATTERN = /^[A-Za-z0-9:_.@-]{3,128}$/;
export const SIGNOFF_ID_PATTERN = /^sig_[a-f0-9]{32}$/;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
