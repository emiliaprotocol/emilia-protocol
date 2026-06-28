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

export function createLocalDevSigner({ keyId = 'local-dev#1', seedB64, privateKey } = {}) {
  const key = privateKey || privateKeyFromSeedB64(seedB64);
  const publicKey = crypto.createPublicKey(key);
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
    const err = new Error(result.detail);
    err.code = result.reason;
    throw err;
  }
  return result;
}
