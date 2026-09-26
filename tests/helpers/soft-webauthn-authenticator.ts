// SPDX-License-Identifier: Apache-2.0
// A software WebAuthn authenticator for tests that must exercise the REAL
// @simplewebauthn/server verifier rather than a mock of it.
//
// It produces spec-shaped registration and authentication responses
// (W3C WebAuthn L3 sections 6.1, 6.5, 7.1, 7.2) signed with a real P-256 key,
// and lets a test bend exactly one property at a time: the origin or RP ID
// the authenticator claims, the UP/UV flags, the signature counter, the
// cross-origin / topOrigin client data members, or the COSE key algorithm.
//
// Nothing here is used outside tests.

import crypto from 'node:crypto';

// ── Minimal deterministic CBOR (RFC 8949 section 4.2.1 core rules) ─────────
// Only what WebAuthn structures need: ints, byte strings, text strings, and
// maps keyed by ints or text. Shortest-form heads; no tags, no floats.

type CborValue = number | string | Uint8Array | CborMap | CborValue[];
type CborMap = Map<number | string, CborValue>;

function head(major: number, value: number): Buffer {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value < 0x100) return Buffer.from([(major << 5) | 24, value]);
  if (value < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(value, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(value, 1);
  return b;
}

export function cborEncode(value: CborValue): Buffer {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('cborEncode: integers only');
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([head(4, value.length), ...value.map(cborEncode)]);
  }
  if (value instanceof Map) {
    const parts: Buffer[] = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v));
    return Buffer.concat(parts);
  }
  throw new TypeError('cborEncode: unsupported value');
}

// ── Authenticator ──────────────────────────────────────────────────────────

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;

const sha256 = (data: Uint8Array | string): Buffer => crypto.createHash('sha256').update(data).digest();
const b64u = (data: Uint8Array): string => Buffer.from(data).toString('base64url');

export interface ClientDataOverrides {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  topOrigin?: string;
}

export interface CeremonyInput {
  /** The challenge the authenticator claims to have signed (base64url string). */
  challenge: string;
  /** The origin the browser reports in clientDataJSON. */
  origin: string;
  /** The RP ID whose SHA-256 goes into authenticatorData. */
  rpId: string;
  /** authenticatorData flags. Defaults to UP|UV. */
  flags?: number;
  /** Signature counter. Defaults to 0. */
  counter?: number;
  /** Extra clientDataJSON members (crossOrigin, topOrigin, type override). */
  clientData?: ClientDataOverrides;
}

export interface RegistrationInput extends CeremonyInput {
  /** 'none' (default) or 'packed' self-attestation. */
  fmt?: 'none' | 'packed';
  /**
   * Replace the credential public key in authenticatorData with this COSE
   * map. Used to present a non-ES256 algorithm the verifier must refuse.
   */
  coseKeyOverride?: CborMap;
  transports?: string[];
}

function clientDataJSON(type: string, input: CeremonyInput): Buffer {
  const body: Record<string, unknown> = {
    type: input.clientData?.type ?? type,
    challenge: input.clientData?.challenge ?? input.challenge,
    origin: input.clientData?.origin ?? input.origin,
  };
  if (input.clientData && 'crossOrigin' in input.clientData) body.crossOrigin = input.clientData.crossOrigin;
  if (input.clientData && 'topOrigin' in input.clientData) body.topOrigin = input.clientData.topOrigin;
  return Buffer.from(JSON.stringify(body), 'utf8');
}

function counterBytes(counter: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(counter >>> 0, 0);
  return b;
}

export function createSoftAuthenticator() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const coseKey: CborMap = new Map<number | string, CborValue>([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ]);
  const cosePublicKey = cborEncode(coseKey);
  const credentialId = crypto.randomBytes(32);

  function sign(data: Buffer): Buffer {
    // ES256 WebAuthn signatures are ASN.1 DER, which is node's default.
    return crypto.sign('sha256', data, privateKey);
  }

  function register(input: RegistrationInput) {
    const flags = input.flags ?? (FLAG_UP | FLAG_UV);
    const key = input.coseKeyOverride ? cborEncode(input.coseKeyOverride) : cosePublicKey;
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credentialId.length, 0);
    const authData = Buffer.concat([
      sha256(input.rpId),
      Buffer.from([flags | FLAG_AT]),
      counterBytes(input.counter ?? 0),
      Buffer.alloc(16), // AAGUID: zero (no attestation metadata claimed)
      credIdLen,
      credentialId,
      key,
    ]);
    const cdj = clientDataJSON('webauthn.create', input);
    const attStmt: CborMap = new Map();
    if (input.fmt === 'packed') {
      attStmt.set('alg', -7);
      attStmt.set('sig', sign(Buffer.concat([authData, sha256(cdj)])));
    }
    const attestationObject = cborEncode(new Map<number | string, CborValue>([
      ['fmt', input.fmt ?? 'none'],
      ['attStmt', attStmt],
      ['authData', authData],
    ]));
    return {
      id: b64u(credentialId),
      rawId: b64u(credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(cdj),
        attestationObject: b64u(attestationObject),
        transports: input.transports ?? ['internal'],
      },
      clientExtensionResults: {},
    };
  }

  function assert(input: CeremonyInput) {
    const flags = input.flags ?? (FLAG_UP | FLAG_UV);
    const authData = Buffer.concat([
      sha256(input.rpId),
      Buffer.from([flags]),
      counterBytes(input.counter ?? 0),
    ]);
    const cdj = clientDataJSON('webauthn.get', input);
    const signature = sign(Buffer.concat([authData, sha256(cdj)]));
    return {
      id: b64u(credentialId),
      rawId: b64u(credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(cdj),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
      },
      clientExtensionResults: {},
    };
  }

  return {
    credentialId: b64u(credentialId),
    /** COSE_Key bytes as enrolled (what approver_credentials.public_key_cose holds). */
    cosePublicKey,
    cosePublicKeyB64u: b64u(cosePublicKey),
    /** P-256 SPKI DER, base64url. */
    spkiB64u: b64u(publicKey.export({ format: 'der', type: 'spki' }) as Buffer),
    register,
    assert,
  };
}

/** A COSE OKP/Ed25519 key map (alg -8). Only its shape matters to the alg gate. */
export function ed25519CoseKey(): CborMap {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return new Map<number | string, CborValue>([
    [1, 1], // kty: OKP
    [3, -8], // alg: EdDSA
    [-1, 6], // crv: Ed25519
    [-2, Buffer.from(jwk.x, 'base64url')],
  ]);
}

/** A COSE AKP/ML-DSA-44 key map (alg -48, RFC 9964 layout). Random public bytes. */
export function mlDsa44CoseKey(): CborMap {
  return new Map<number | string, CborValue>([
    [1, 7], // kty: AKP
    [3, -48], // alg: ML-DSA-44
    [-1, crypto.randomBytes(1312)], // pub
  ]);
}
