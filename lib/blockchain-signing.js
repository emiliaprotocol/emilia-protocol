// SPDX-License-Identifier: Apache-2.0

/**
 * Signing-provider boundary for Base anchoring.
 *
 * The anchor pipeline must not know whether an EVM transaction is signed by
 * an environment-held development key, KMS, HSM, Vault, or an enclave. The
 * provider owns that decision and exposes only the account adapter plus
 * auditable metadata. External custody is registration-only and fails closed
 * when the deployment selects it without wiring the provider at boot.
 */

const EXTERNAL_MODES = new Set(['kms', 'hsm']);
const ETH_TX_ALGORITHM = 'secp256k1/eth-transaction';

let registeredProvider = null;

function normalizePrivateKey(privateKey) {
  const normalized = String(privateKey || '').replace(/^0x/i, '');
  if (!/^[0-9a-f]{64}$/i.test(normalized)) {
    throw new Error('EP_WALLET_PRIVATE_KEY must be a 32-byte hexadecimal secp256k1 key');
  }
  return `0x${normalized}`;
}

function assertAccountFactory(factory, name) {
  if (typeof factory !== 'function') throw new Error(`${name} account factory is required`);
}

function metadata({ mode, keyId, address = null }) {
  return Object.freeze({
    provider: mode,
    keyId,
    algorithm: ETH_TX_ALGORITHM,
    address,
  });
}

/**
 * Current env-key provider. This is the compatibility path for development
 * and ordinary deployments; the private key remains contained in this
 * provider and never crosses into the anchor orchestration code.
 * @param {Object} [options]
 * @param {string} [options.privateKey]
 * @param {string} [options.keyId]
 * @returns {Object}
 */
export function createEnvBlockchainSigner({ privateKey, keyId = 'env:EP_WALLET_PRIVATE_KEY' } = {}) {
  const normalized = normalizePrivateKey(privateKey);
  return {
    mode: 'env',
    keyId,
    getAlgorithm: () => ETH_TX_ALGORITHM,
    getMetadata: () => metadata({ mode: 'env', keyId }),
    createAccount({ privateKeyToAccount }) {
      assertAccountFactory(privateKeyToAccount, 'privateKeyToAccount');
      return privateKeyToAccount(normalized);
    },
  };
}

/**
 * Adapter for a deployment-owned KMS/HSM/enclave signer.
 *
 * `signTransaction` receives the viem transaction object and must return the
 * serialized EIP-2718 transaction hex. No private key is accepted here.
 * @param {Object} [options]
 * @param {string} [options.mode]
 * @param {string} [options.keyId]
 * @param {string} [options.address]
 * @param {Function} [options.signTransaction]
 * @returns {Object}
 */
export function createExternalBlockchainSigner({
  mode = 'hsm',
  keyId,
  address,
  signTransaction,
} = {}) {
  if (!EXTERNAL_MODES.has(mode)) throw new Error('external blockchain signer mode must be "kms" or "hsm"');
  if (!keyId || typeof keyId !== 'string') throw new Error('external blockchain signer requires a stable keyId');
  if (!/^0x[0-9a-f]{40}$/i.test(String(address || ''))) {
    throw new Error('external blockchain signer requires a checksummed or hexadecimal EVM address');
  }
  if (typeof signTransaction !== 'function') throw new Error('external blockchain signer requires signTransaction(transaction)');

  return {
    mode,
    keyId,
    getAlgorithm: () => ETH_TX_ALGORITHM,
    getMetadata: () => metadata({ mode, keyId, address }),
    createAccount({ toAccount }) {
      assertAccountFactory(toAccount, 'toAccount');
      return toAccount({
        address,
        async signTransaction(transaction, options) {
          return signTransaction(transaction, options);
        },
      });
    },
  };
}

/** Register the process-wide external provider during deployment boot. */
export function registerBlockchainSigner(provider) {
  if (!provider || !EXTERNAL_MODES.has(provider.mode) || typeof provider.createAccount !== 'function') {
    throw new Error('registerBlockchainSigner requires a KMS/HSM provider with createAccount()');
  }
  registeredProvider = provider;
  return provider;
}

export function getRegisteredBlockchainSigner() {
  return registeredProvider;
}

/** Test/ops hook; production boot should never call this. */
export function clearBlockchainSigner() {
  registeredProvider = null;
}

/**
 * Resolve the configured provider. External modes never fall back to an env
 * key, even if one is present, because that would silently defeat custody.
 */
export function resolveBlockchainSigner(config = {}) {
  const mode = config.signingMode || 'env';
  if (EXTERNAL_MODES.has(mode)) {
    if (!config.signingKeyId) {
      const error = /** @type {Error & {code: string}} */ (new Error('EP_BLOCKCHAIN_SIGNING_KEY_ID is required for external blockchain custody'));
      error.code = 'blockchain_signer_key_id_required';
      throw error;
    }
    if (!registeredProvider || registeredProvider.mode !== mode) {
      const error = /** @type {Error & {code: string}} */ (new Error(
        `EP_BLOCKCHAIN_SIGNING_MODE=${mode} but no matching blockchain signer is registered; refusing env-key fallback`,
      ));
      error.code = 'blockchain_signer_not_registered';
      throw error;
    }
    if (config.signingKeyId && registeredProvider.keyId !== config.signingKeyId) {
      const error = /** @type {Error & {code: string}} */ (new Error('registered blockchain signer key id does not match EP_BLOCKCHAIN_SIGNING_KEY_ID'));
      error.code = 'blockchain_signer_key_mismatch';
      throw error;
    }
    return registeredProvider;
  }
  if (mode !== 'env') {
    const error = /** @type {Error & {code: string}} */ (new Error(`Unsupported EP_BLOCKCHAIN_SIGNING_MODE=${mode}`));
    error.code = 'blockchain_signer_mode_invalid';
    throw error;
  }
  if (!config.walletPrivateKey) return null;
  return createEnvBlockchainSigner({ privateKey: config.walletPrivateKey });
}
