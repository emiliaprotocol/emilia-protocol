// SPDX-License-Identifier: Apache-2.0
//
// Key custody abstraction for high-assurance deployments.
//
// The important government posture is not "EP has a private key in env." It is:
// signing is behind a custody boundary (KMS/HSM), the key id is auditable, and
// production refuses dev-local signing. This module gives callers that seam
// without binding the protocol to a specific cloud vendor.

import crypto from 'node:crypto';
import { getKeyCustodyConfig } from './env.js';

const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function assertProductionKeyCustody(config = getKeyCustodyConfig()) {
  const mode = config.mode || 'local-dev';
  const govStrict = config.govStrict || config.isProduction;
  if (!govStrict) return { ok: true, mode };
  if (mode === 'local-dev' || mode === 'env') {
    return {
      ok: false,
      reason: 'local_key_custody_forbidden',
      detail: 'Production/government mode requires EP_KEY_CUSTODY_MODE=kms or hsm; local/env private keys are dev-only.',
    };
  }
  if (!['kms', 'hsm'].includes(mode)) {
    return { ok: false, reason: 'unknown_key_custody_mode', detail: `Unsupported key custody mode "${mode}".` };
  }
  if (!config.keyId) {
    return { ok: false, reason: 'missing_custody_key_id', detail: 'EP_KMS_KEY_ID or EP_HSM_KEY_ID is required.' };
  }
  return { ok: true, mode, keyId: config.keyId };
}

export function privateKeyFromSeedB64(seedB64) {
  const seed = Buffer.from(String(seedB64 || ''), 'base64');
  if (seed.length !== 32) {
    throw new Error('Ed25519 seed must be a base64-encoded 32-byte value');
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * @param {object} [opts]
 * @param {string} [opts.keyId]
 * @param {string} [opts.seedB64]
 * @param {import('crypto').KeyObject} [opts.privateKey]
 */
export function createLocalDevSigner({ keyId = 'local-dev#1', seedB64, privateKey } = {}) {
  const key = privateKey || privateKeyFromSeedB64(seedB64);
  const publicKey = crypto.createPublicKey(/** @type {any} */ (key));
  return {
    keyId,
    custody: 'local-dev',
    publicKeySpkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    async sign(bytes) {
      return crypto.sign(null, Buffer.from(bytes), key).toString('base64url');
    },
  };
}

export function createExternalCustodySigner({ mode, keyId, sign, getPublicKey }) {
  if (!['kms', 'hsm'].includes(mode)) {
    throw new Error('external custody signer mode must be "kms" or "hsm"');
  }
  if (!keyId || typeof keyId !== 'string') {
    throw new Error('external custody signer requires a stable keyId');
  }
  if (typeof sign !== 'function') {
    throw new Error('external custody signer requires a sign(bytes) function');
  }
  return {
    keyId,
    custody: mode,
    async publicKeySpkiB64u() {
      if (typeof getPublicKey !== 'function') return null;
      return getPublicKey();
    },
    async sign(bytes, context = {}) {
      return sign(Buffer.from(bytes), { keyId, mode, ...context });
    },
  };
}

export function requireConfiguredCustody(config = getKeyCustodyConfig()) {
  const result = assertProductionKeyCustody(config);
  if (!result.ok) {
    /** @type {Error & { code?: string }} */
    const err = new Error(result.detail);
    err.code = result.reason;
    throw err;
  }
  return result;
}

// ── Issuer signer resolution (KMS/HSM custody, wired into signing) ────────────
//
// An operator registers their KMS/HSM signer ONCE at boot (an AWS KMS, GCP KMS,
// or PKCS#11/HSM `sign(bytes)` callback wrapped via createExternalCustodySigner).
// resolveIssuerSigner() then returns that signer when custody mode is kms/hsm,
// throws if kms/hsm is configured but no signer was registered (fail closed),
// and returns null for local-dev/env to mean "use the built-in env-key path"
// (which itself fails closed under gov-strict). This is the seam the issuer
// (lib/commit.js) calls so signing goes through the custody boundary without
// binding EP to any one cloud vendor.

let _registeredCustodySigner = null;

/** Register the process-wide KMS/HSM custody signer (call once at boot). */
export function registerCustodySigner(signer) {
  if (!signer || typeof signer.sign !== 'function' || !signer.keyId) {
    throw new Error('registerCustodySigner requires a signer with { keyId, async sign(bytes) } (see createExternalCustodySigner)');
  }
  _registeredCustodySigner = signer;
  return signer;
}

export function getRegisteredCustodySigner() {
  return _registeredCustodySigner;
}

/** Test/ops hook: clear the registered signer. */
export function clearCustodySigner() {
  _registeredCustodySigner = null;
}

/**
 * Resolve the signer the issuer should use.
 * @returns {object|null} the custody signer for kms/hsm, or null to use the
 *   built-in env-key path (local-dev/env). Throws if kms/hsm is configured
 *   without a registered signer, or if local custody is forbidden (gov-strict).
 */
export function resolveIssuerSigner(config = getKeyCustodyConfig()) {
  const mode = config.mode || 'local-dev';
  if (mode === 'kms' || mode === 'hsm') {
    requireConfiguredCustody(config); // throws on missing keyId / unknown mode
    if (!_registeredCustodySigner) {
      /** @type {Error & { code?: string }} */
      const err = new Error(
        `EP_KEY_CUSTODY_MODE=${mode} but no custody signer is registered. `
        + 'Register one at boot: registerCustodySigner(createExternalCustodySigner({ mode, keyId, sign, getPublicKey })) '
        + 'backed by your KMS/HSM. Refusing to fall back to a local key (fail closed).',
      );
      err.code = 'custody_signer_not_registered';
      throw err;
    }
    return _registeredCustodySigner;
  }
  // local-dev / env: use the built-in env-key signer (null). KMS/HSM is OPT-IN —
  // forcing it here would break the supported env-key production path
  // (EP_COMMIT_SIGNING_KEY), whose own production requirement is enforced by the
  // issuer. The gov-strict "no local keys" posture is surfaced by
  // assertProductionKeyCustody / gov:check, not by hard-failing issuance here.
  return null;
}
