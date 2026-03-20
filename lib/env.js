/**
 * EMILIA Protocol — Centralized Environment Configuration
 *
 * ALL environment variable access MUST go through this module.
 * No other file should read process.env directly (except next.config.js).
 *
 * This makes env dependencies explicit, testable, and auditable.
 *
 * @license Apache-2.0
 */

// =============================================================================
// VALIDATION HELPER (retained from original)
// =============================================================================

export function assertServerEnv({ required = [] } = {}) {
  const missing = required.filter(k => !process.env[k]);
  if (missing.length === 0) return { ok: true };

  const msg = `Missing required server env: ${missing.join(', ')}`;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(msg);
  }

  // In non-production, warn but allow startup for developer convenience
  // eslint-disable-next-line no-console
  console.warn('ENV WARNING:', msg);
  return { ok: false, missing };
}

// =============================================================================
// SUPABASE
// =============================================================================

/**
 * @returns {{ url: string|undefined, serviceRoleKey: string|undefined, anonKey: string|undefined }}
 */
export function getSupabaseConfig() {
  return {
    url: process.env.NEXT_PUBLIC_SUPABASE_URL,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    anonKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  };
}

// =============================================================================
// OPENAI
// =============================================================================

/**
 * @returns {string|null}
 */
export function getOpenAIKey() {
  return process.env.OPENAI_API_KEY || null;
}

// =============================================================================
// UPSTASH REDIS
// =============================================================================

/**
 * @returns {{ url: string, token: string }|null}
 */
export function getUpstashConfig() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return { url, token };
}

// =============================================================================
// BLOCKCHAIN
// =============================================================================

/**
 * @returns {{ network: string|undefined, walletPrivateKey: string|undefined }|null}
 */
export function getBlockchainConfig() {
  const network = process.env.BASE_NETWORK;
  const walletPrivateKey = process.env.EP_WALLET_PRIVATE_KEY;
  if (!network && !walletPrivateKey) return null;
  return { network: network || 'sepolia', walletPrivateKey };
}

// =============================================================================
// COMMIT SIGNING
// =============================================================================

/**
 * Returns commit signing configuration from environment.
 *
 * EP_COMMIT_SIGNING_KEY: base64-encoded 32-byte Ed25519 seed (primary signing key)
 * EP_COMMIT_SIGNING_KEYS: JSON map of kid → base64 public keys for key rotation
 *   e.g. '{"ep-signing-key-1":"base64pubkey","ep-signing-key-2":"base64pubkey"}'
 *
 * In production, EP_COMMIT_SIGNING_KEY is REQUIRED. Its absence is a fatal error.
 * In dev/test, an ephemeral key is generated if absent.
 *
 * @returns {{
 *   signingKey: string|null,
 *   trustedKeys: Record<string, string>|null,
 *   isProduction: boolean
 * }}
 */
export function getCommitSigningConfig() {
  const signingKey = process.env.EP_COMMIT_SIGNING_KEY || null;
  const isProductionEnv = process.env.NODE_ENV === 'production';

  let trustedKeys = null;
  const trustedKeysRaw = process.env.EP_COMMIT_SIGNING_KEYS;
  if (trustedKeysRaw) {
    try {
      trustedKeys = JSON.parse(trustedKeysRaw);
    } catch {
      if (isProductionEnv) {
        throw new Error('EP_COMMIT_SIGNING_KEYS contains invalid JSON');
      }
      // eslint-disable-next-line no-console
      console.warn('ENV WARNING: EP_COMMIT_SIGNING_KEYS contains invalid JSON, ignoring');
    }
  }

  return { signingKey, trustedKeys, isProduction: isProductionEnv };
}

// =============================================================================
// EP PLATFORM
// =============================================================================

/**
 * @returns {{ apiUrl: string, apiKey: string, baseUrl: string }}
 */
export function getEPConfig() {
  return {
    apiUrl: process.env.EP_AUTO_RECEIPT_URL || 'https://emiliaprotocol.ai',
    apiKey: process.env.EP_API_KEY || '',
    baseUrl: process.env.EP_BASE_URL || 'https://emiliaprotocol.ai',
  };
}

// =============================================================================
// AUTO-SUBMIT SECRET (machine credential for /api/receipts/auto-submit)
// =============================================================================

/**
 * Shared secret for authenticating machine-to-machine auto-submit requests.
 * Must be set in production. In development, a missing key causes requests
 * to be rejected with 401.
 *
 * @returns {string|null}
 */
export function getAutoSubmitSecret() {
  return process.env.EP_AUTO_SUBMIT_SECRET || null;
}

// =============================================================================
// CRON SECRET
// =============================================================================

/**
 * @returns {string|null}
 */
export function getCronSecret() {
  return process.env.CRON_SECRET || null;
}

// =============================================================================
// GITHUB TOKEN
// =============================================================================

/**
 * @returns {string|null}
 */
export function getGitHubToken() {
  return process.env.GITHUB_TOKEN || null;
}

// =============================================================================
// NODE_ENV HELPER
// =============================================================================

/**
 * @returns {boolean}
 */
export function isProduction() {
  return process.env.NODE_ENV === 'production';
}
