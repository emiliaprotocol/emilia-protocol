// SPDX-License-Identifier: Apache-2.0
//
// Concrete custody signers for the issuer-side signing seam (lib/key-custody.js).
// EP issues Ed25519 signatures, so the realistic external-custody backends are:
//
//   - HashiCorp Vault Transit  — supports ed25519 keys natively. The private key
//     never leaves Vault; you call /transit/sign/<key> and get a signature back.
//   - PKCS#11 HSM (Luna, CloudHSM-in-PKCS11-mode, YubiHSM, SoftHSM) — supports
//     Ed25519; the key lives in the HSM.
//
// IMPORTANT — AWS KMS and GCP Cloud KMS do NOT support Ed25519 signing today
// (they offer ECDSA P-256/384/521 and RSA only). So there is no honest "AWS KMS
// Ed25519 signer." For cloud-resident Ed25519 custody, use Vault Transit (works
// in every cloud) or an Ed25519-capable HSM. If you must use AWS/GCP KMS, the
// pattern is a KMS-sealed Ed25519 seed unsealed only inside an enclave — out of
// scope here; use `externalSigner` with your own sign() in that case.
//
// Each factory returns the shape lib/key-custody.js#registerCustodySigner wants:
//   { keyId, custody, async sign(bytes) -> base64url, async publicKeySpkiB64u() }
//
//   import { registerCustodySigner } from './key-custody.js';
//   import { vaultTransitSigner } from './custody-signers.js';
//   registerCustodySigner(vaultTransitSigner({ vault, keyName, publicKeySpkiB64u }));

// POST-QUANTUM LEG (see softwareMldsaSigner below). This file's concrete PQ
// factory is intentionally SOFTWARE custody. For remote custody, use
// lib/pq-custody-external.ts; lib/pq-custody-aws-kms.ts implements that contract
// for AWS KMS. The external seam pins the 3309-byte signature and 1952-byte
// public key, refuses fail-closed, and never falls back to this software backend.
//
// THAT LABEL IS LOAD-BEARING, NOT DECORATION. describeHybridCustodyPosture()
// in lib/key-custody.js reads it to resolve a deployment's DEFAULT issuance
// posture, and a gov-strict (or production) deployment refuses a PQ leg whose
// custody is not kms/hsm with the named reason `pq_custody_not_permitted`.
// A signer built here therefore does NOT hand a kms/hsm-requiring deployment a
// software-held PQ key by default; that deployment gets classical-only issuance
// and a reason it can read, until an operator sets the mode explicitly.

import { createPqCustodySigner, createExternalCustodySigner, createHybridCustodySigner, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES } from './key-custody.js';

/**
 * Generic external signer — wrap any async Ed25519 sign callback.
 * @param {object} o
 * @param {'kms'|'hsm'} [o.mode='hsm']
 * @param {string} o.keyId stable key identifier (auditable)
 * @param {(bytes:Buffer)=>Promise<Buffer|string>} o.sign returns a 64-byte Ed25519 signature (Buffer, base64, or base64url)
 * @param {string} o.publicKeySpkiB64u base64url SPKI-DER (or raw 32-byte) public key, to register the verification key
 */
export function externalSigner({ mode = 'hsm', keyId, sign, publicKeySpkiB64u }) {
  if (typeof sign !== 'function') throw new Error('externalSigner requires an async sign(bytes) callback');
  return createExternalCustodySigner({
    mode,
    keyId,
    sign: async (bytes) => toB64u(await sign(Buffer.from(bytes))),
    getPublicKey: () => publicKeySpkiB64u,
  });
}

/**
 * HashiCorp Vault Transit Ed25519 signer. The Ed25519 key lives in Vault; we
 * call its sign endpoint per signature.
 * @param {object} o
 * @param {{ sign:(keyName:string, b64Input:string)=>Promise<string> }} o.vault
 *   a thin client whose sign() POSTs to /v1/transit/sign/<keyName> with
 *   { input: <base64> } and returns the bare base64 signature (strip the
 *   "vault:v1:" prefix Vault adds).
 * @param {string} o.keyName the transit key name (also the auditable keyId)
 * @param {string} o.publicKeySpkiB64u the key's public half (base64url SPKI/raw)
 */
export function vaultTransitSigner({ vault, keyName, publicKeySpkiB64u }) {
  if (!vault || typeof vault.sign !== 'function') throw new Error('vaultTransitSigner requires a vault client with sign(keyName, b64Input)');
  if (!keyName) throw new Error('vaultTransitSigner requires a keyName');
  return externalSigner({
    mode: 'kms',
    keyId: `vault-transit:${keyName}`,
    publicKeySpkiB64u,
    sign: async (bytes) => {
      const sigB64 = await vault.sign(keyName, bytes.toString('base64'));
      return String(sigB64).replace(/^vault:v\d+:/, ''); // strip Vault's versioned prefix if present
    },
  });
}

/**
 * PKCS#11 HSM Ed25519 signer. The key lives in the HSM (Luna, YubiHSM, SoftHSM,
 * CloudHSM in PKCS#11 mode).
 * @param {object} o
 * @param {{ signEd25519:(keyLabel:string, data:Buffer)=>Promise<Buffer> }} o.hsm
 *   a thin client that performs C_Sign with CKM_EDDSA over `data`.
 * @param {string} o.keyLabel the HSM object label (also the auditable keyId)
 * @param {string} o.publicKeySpkiB64u the key's public half (base64url SPKI/raw)
 */
export function hsmEd25519Signer({ hsm, keyLabel, publicKeySpkiB64u }) {
  if (!hsm || typeof hsm.signEd25519 !== 'function') throw new Error('hsmEd25519Signer requires an hsm client with signEd25519(keyLabel, data)');
  if (!keyLabel) throw new Error('hsmEd25519Signer requires a keyLabel');
  return externalSigner({
    mode: 'hsm',
    keyId: `pkcs11:${keyLabel}`,
    publicKeySpkiB64u,
    sign: (bytes) => hsm.signEd25519(keyLabel, bytes),
  });
}

/**
 * SOFTWARE-held ML-DSA-65 signer: the post-quantum leg of a dual-signer
 * custody configuration. The secret key lives in process memory, NOT behind a
 * custody boundary, and the default backend is @noble/post-quantum's pure-JS
 * FIPS 204 implementation, which is not independently audited and is not a
 * FIPS validated module. That is the whole honest story; `custody` is
 * 'software' and this factory has no mode that says otherwise.
 *
 * The backend is resolved lazily (dynamic import) so this module stays free of
 * a static @noble/post-quantum dependency, exactly as
 * packages/verify/src/pq-signature-agility.ts does. An absent backend is a
 * THROW at signing time, never a silently skipped PQ leg.
 *
 * @param {object} o
 * @param {string} o.keyId stable, auditable key identifier for the PQ leg
 * @param {Uint8Array|string} o.secretKey 4032 raw bytes, or base64url of them
 * @param {Uint8Array|string} [o.publicKeyRawB64u] 1952 raw bytes, or base64url of them
 * @param {{sign?:(msg:Uint8Array, sk:Uint8Array, opts?:object)=>Uint8Array}} [o.mldsaBackend]
 *   inject a backend instead of loading @noble/post-quantum
 * @param {boolean} [o.deterministic] FIPS 204 deterministic variant (conformance vectors only)
 */
export function softwareMldsaSigner({ keyId, secretKey, publicKeyRawB64u, mldsaBackend, deterministic = false }) {
  const sk = toRawBytes(secretKey);
  if (!sk || sk.length !== ML_DSA_65_SECRET_KEY_BYTES) {
    throw new Error(`softwareMldsaSigner requires a ${ML_DSA_65_SECRET_KEY_BYTES}-byte ML-DSA-65 secret key (raw bytes or base64url)`);
  }
  const pk = publicKeyRawB64u === undefined ? null : toRawBytes(publicKeyRawB64u);
  if (publicKeyRawB64u !== undefined && (!pk || pk.length !== ML_DSA_65_PUBLIC_KEY_BYTES)) {
    throw new Error(`softwareMldsaSigner public key must be ${ML_DSA_65_PUBLIC_KEY_BYTES} raw bytes (or base64url of them)`);
  }
  const publicB64u = pk ? Buffer.from(pk).toString('base64url') : null;

  return createPqCustodySigner({
    keyId,
    custody: 'software',
    getPublicKey: () => publicB64u,
    sign: async (bytes) => {
      const backend = mldsaBackend ?? await loadDefaultMldsaBackend();
      if (!backend || typeof backend.sign !== 'function') {
        throw new Error('softwareMldsaSigner: refusing to sign: pq_backend_unavailable (@noble/post-quantum ml_dsa65 not resolvable)');
      }
      const opts = deterministic === true ? { extraEntropy: false } : undefined;
      const sig = backend.sign(new Uint8Array(bytes), new Uint8Array(sk), opts);
      if (!(sig instanceof Uint8Array) || sig.length === 0) {
        throw new Error('softwareMldsaSigner: ML-DSA backend returned an invalid signature');
      }
      return Buffer.from(sig).toString('base64url');
    },
  });
}

/**
 * Convenience: compose an Ed25519 CustodySigner (from any factory above) with
 * a software ML-DSA-65 leg into one registrable dual-signer.
 *
 *   registerCustodySigner(hybridSigner({
 *     classical: vaultTransitSigner({ vault, keyName, publicKeySpkiB64u }),
 *     pq: softwareMldsaSigner({ keyId: 'ep:key:pq#1', secretKey, publicKeyRawB64u }),
 *   }));
 *
 * The classical leg keeps whatever custody it actually has (kms/hsm); the PQ
 * leg is software. The pair is NOT a uniform custody claim and this repository
 * does not make one, and describeHybridCustodyPosture() reports the two labels
 * separately for exactly that reason.
 */
export function hybridSigner({ classical, pq }) {
  return createHybridCustodySigner({ classical, pq });
}

const MLDSA_PACKAGE_SPECIFIER = '@noble/post-quantum/ml-dsa.js';

/** Load ml_dsa65; returns null (never throws) so callers refuse with a reason. */
async function loadDefaultMldsaBackend() {
  try {
    const mod = await import(MLDSA_PACKAGE_SPECIFIER);
    const impl = mod?.ml_dsa65;
    if (!impl || typeof impl.sign !== 'function') return null;
    return { sign: (msg, sk, opts) => impl.sign(msg, sk, opts) };
  } catch {
    return null;
  }
}

function toRawBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string' && value.length > 0) {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
    try { return new Uint8Array(Buffer.from(value, 'base64url')); } catch { return null; }
  }
  return null;
}

function toB64u(sig) {
  if (Buffer.isBuffer(sig)) return sig.toString('base64url');
  const s = String(sig);
  // Accept base64url already, or convert from standard base64.
  if (/^[A-Za-z0-9_-]+$/.test(s) && !s.includes('+') && !s.includes('/') && !s.includes('=')) return s;
  return Buffer.from(s, 'base64').toString('base64url');
}

const custodySigners = { externalSigner, vaultTransitSigner, hsmEd25519Signer, softwareMldsaSigner, hybridSigner };
export default custodySigners;
