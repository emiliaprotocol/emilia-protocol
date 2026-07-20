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

import { createExternalCustodySigner } from './key-custody.js';

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

function toB64u(sig) {
  if (Buffer.isBuffer(sig)) return sig.toString('base64url');
  const s = String(sig);
  // Accept base64url already, or convert from standard base64.
  if (/^[A-Za-z0-9_-]+$/.test(s) && !s.includes('+') && !s.includes('/') && !s.includes('=')) return s;
  return Buffer.from(s, 'base64').toString('base64url');
}

const custodySigners = { externalSigner, vaultTransitSigner, hsmEd25519Signer };
export default custodySigners;
