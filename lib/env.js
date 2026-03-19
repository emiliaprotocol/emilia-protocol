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
