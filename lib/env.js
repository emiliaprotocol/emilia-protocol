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
import { logger } from './logger.js';

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
  logger.warn('ENV WARNING:', msg);
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
      const parsed = JSON.parse(trustedKeysRaw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('EP_COMMIT_SIGNING_KEYS must be a JSON object of {kid: base64key}');
      }
      // Build a clean kid->key map: drop prototype-pollution keys and any
      // non-string values, so a malformed/hostile env var can't inject a key or
      // pollute Object.prototype. (HI-4)
      const clean = Object.create(null);
      for (const [kid, val] of Object.entries(parsed)) {
        if (kid === '__proto__' || kid === 'constructor' || kid === 'prototype') continue;
        if (typeof kid !== 'string' || typeof val !== 'string' || !val) continue;
        clean[kid] = val;
      }
      trustedKeys = clean;
    } catch (e) {
      if (isProductionEnv) {
        throw new Error('EP_COMMIT_SIGNING_KEYS contains invalid JSON or structure');
      }
      logger.warn(`ENV WARNING: EP_COMMIT_SIGNING_KEYS invalid (${e.message}), ignoring`);
    }
  }

  return { signingKey, trustedKeys, isProduction: isProductionEnv };
}

// =============================================================================
// GOVERNMENT / HIGH-ASSURANCE DEPLOYMENT
// =============================================================================

function splitKeyList(raw) {
  if (!raw) return [];
  if (raw.trim().startsWith('[')) {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('trusted issuer keys must be a JSON array or comma-separated list');
    return parsed.map((v) => String(v).trim()).filter(Boolean);
  }
  return raw.split(',').map((v) => v.trim()).filter(Boolean);
}

/**
 * Trusted receipt issuer keys for production "Receipt Required" verification.
 * Inline/self-asserted keys are demo-only; production callers pin these.
 *
 * @returns {{ trustedIssuerKeys: string[], govStrict: boolean, rpId: string|null, expectedPolicyHash: string|null }}
 */
export function getGovVerifierConfig() {
  const rawKeys = process.env.EP_TRUSTED_ISSUER_KEYS || process.env.EMILIA_TRUSTED_ISSUER_KEYS || '';
  let trustedIssuerKeys = [];
  try {
    trustedIssuerKeys = splitKeyList(rawKeys);
  } catch (e) {
    if (isProduction()) throw new Error(`EP_TRUSTED_ISSUER_KEYS invalid: ${e.message}`);
    logger.warn(`ENV WARNING: EP_TRUSTED_ISSUER_KEYS invalid (${e.message}), ignoring`);
  }
  return {
    trustedIssuerKeys,
    // Gov-strict is an EXPLICIT deployment mode (EP_GOV_STRICT=true), not auto-on
    // for any production build. Non-demo guarded endpoints still require pinned
    // issuer keys; /api/demo/* is the only self-signed playground.
    govStrict: process.env.EP_GOV_STRICT === 'true',
    rpId: process.env.EP_WEBAUTHN_RP_ID || null,
    expectedPolicyHash: process.env.EP_EXPECTED_POLICY_HASH || null,
  };
}

/**
 * Pinned approver public keys for high-assurance (Class-A / quorum) receipt
 * proof verification. A receipt's issuer may DESCRIBE a human signoff, but a
 * Class-A/quorum tier is only PROVEN when each signoff in the receipt's
 * assurance_proof verifies against a key pinned here.
 *
 * Shape: a JSON object keyed by approver_key_id, e.g.
 *   {"ep:key:cfo#1": {"public_key": "<base64url SPKI DER>", "key_class": "A"}}
 *
 * Returns {} when unset — which correctly forces every high-tier proof to fail
 * closed (no pinned keys ⇒ no signoff can verify ⇒ assurance_too_low).
 *
 * @returns {Record<string, { public_key: string, key_class?: 'A'|'B' }>}
 */
export function getPinnedApproverKeys() {
  const raw = process.env.EP_PINNED_APPROVER_KEYS || process.env.EMILIA_PINNED_APPROVER_KEYS || '';
  if (!raw.trim()) return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    if (isProduction()) throw new Error(`EP_PINNED_APPROVER_KEYS invalid JSON: ${e.message}`);
    logger.warn(`ENV WARNING: EP_PINNED_APPROVER_KEYS invalid JSON (${e.message}), ignoring`);
    return {};
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    if (isProduction()) throw new Error('EP_PINNED_APPROVER_KEYS must be a JSON object keyed by approver_key_id');
    logger.warn('ENV WARNING: EP_PINNED_APPROVER_KEYS must be a JSON object, ignoring');
    return {};
  }
  return parsed;
}

/**
 * Key-custody posture for government/high-assurance deployments.
 *
 * `local-dev` is only acceptable outside production/non-gov mode. `kms` and
 * `hsm` are abstractions: the deployment supplies the provider adapter while
 * this config records the expected custody boundary and key id.
 */
export function getKeyCustodyConfig() {
  return {
    mode: process.env.EP_KEY_CUSTODY_MODE || 'local-dev',
    keyId: process.env.EP_KMS_KEY_ID || process.env.EP_HSM_KEY_ID || null,
    fipsRequired: process.env.EP_FIPS_REQUIRED === 'true',
    govStrict: process.env.EP_GOV_STRICT === 'true' || isProduction(),
    isProduction: isProduction(),
  };
}

/**
 * Audit retention targets surfaced to the readiness packet and check script.
 */
export function getAuditRetentionConfig() {
  return {
    hotDays: Number(process.env.EP_AUDIT_HOT_DAYS || 365),
    coldDays: Number(process.env.EP_AUDIT_COLD_DAYS || 2190),
    exportEnabled: process.env.EP_AUDIT_EXPORT_ENABLED === 'true',
  };
}

/**
 * Rate limiter deployment posture. High-assurance deployments must use a
 * durable/shared backend, not per-instance memory.
 */
export function getRateLimitConfig() {
  return {
    durableRequired: process.env.EP_GOV_STRICT === 'true' || process.env.EP_REQUIRE_DURABLE_RATE_LIMIT === 'true',
  };
}

/**
 * Public self-serve key issuance posture. Production must not mint live API
 * keys from anonymous signup/playground forms unless the operator explicitly
 * opts in after adding an external proof step (email verification, CAPTCHA, or
 * approval workflow). Dev/test stays open so local demos and unit tests remain
 * usable without provisioning.
 */
export function isPublicEntityRegistrationEnabled() {
  return !isProduction() || process.env.EP_ENABLE_PUBLIC_ENTITY_REGISTRATION === 'true';
}

/**
 * Assurance-tier quorum enforcement at consume. A 'dual' value tier (e.g.
 * payment >= $1M) requires TWO distinct, individually-authorized Class-A
 * approvals before consume, not one. Default ON (fail-closed): a receipt the
 * policy labeled 'dual' must be enforced as dual, otherwise the tier is
 * cosmetic. Set EP_TIER_QUORUM_ENFORCE=false to explicitly opt out (a permissive
 * dev/demo posture). See docs/gov-readiness/ASSURANCE-TIER-ENFORCEMENT.md.
 */
export function isTierQuorumEnforced() {
  return process.env.EP_TIER_QUORUM_ENFORCE !== 'false';
}

/**
 * Require an org-pinned quorum template for any quorum-gated receipt.
 *
 * The meet-or-exceed enforcement (a submitted/stored quorum_policy may never be
 * weaker than the org template) is ALWAYS active when a template row exists.
 * This flag governs the stricter posture for the case where a quorum_policy is
 * submitted but NO template is configured for (org, action_type): when true, a
 * missing template fails closed (`quorum_template_missing`) — the creator cannot
 * declare an unbacked quorum. Default OFF (transitional, mirroring the two-step
 * tenant-binding rollout) so orgs that have not yet authored templates keep
 * issuing quorum receipts. Set EP_QUORUM_TEMPLATE_REQUIRED=true to require them.
 * A genuine store fault on the quorum path fails closed regardless of this flag;
 * a not-yet-migrated table is always treated as "no template."
 */
export function isQuorumTemplateRequired() {
  return process.env.EP_QUORUM_TEMPLATE_REQUIRED === 'true';
}

/**
 * At-rest secret-box key (lib/crypto/secret-box). EP_SECRET_KEY (64 hex = 32
 * bytes) when set; null otherwise (secret-box derives a stable fallback from
 * the service-role key so every deployment has a key with zero new config).
 * @returns {string|null}
 */
export function getSecretBoxKey() {
  const key = process.env.EP_SECRET_KEY;
  return key && /^[0-9a-f]{64}$/i.test(key) ? key : null;
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

/**
 * SCIM auto-approver flag (T3). When true, creating/re-activating a SCIM user
 * grants approver eligibility automatically; when false (default) eligibility
 * goes through the admin approval path, so a compromised SCIM token cannot mint
 * an approver.
 * @returns {boolean}
 */
export function isScimAutoApproverEnabled() {
  return process.env.EP_SCIM_AUTO_APPROVER === 'true';
}

/**
 * Canonical public origin (www host, so requests don't 307-redirect). Used by
 * the remote MCP server's read tools to reach EP's own public endpoints.
 * @returns {string}
 */
export function getPublicBaseUrl() {
  return process.env.EP_PUBLIC_BASE_URL || 'https://www.emiliaprotocol.ai';
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

// =============================================================================
// OPERATOR HMAC KEYS
// =============================================================================

/**
 * Parse the EP_OPERATOR_KEYS env var into a Map of operator_id -> Buffer
 * (HMAC secret bytes). Returns an empty Map if the env var is unset or
 * malformed; logs the parse failure so SIEM picks it up.
 *
 * Format: JSON object mapping operator_id to a hex-encoded HMAC secret,
 * e.g. `{"op_1": "deadbeef…", "op_2": "cafebabe…"}`.
 *
 * Used by lib/operator-auth.js to verify per-operator HMAC tokens.
 *
 * @returns {Map<string, Buffer>}
 */
export function getOperatorKeys() {
  const raw = process.env.EP_OPERATOR_KEYS;
  if (!raw) return new Map();

  try {
    const parsed = JSON.parse(raw);
    const keys = new Map();
    for (const [id, secret] of Object.entries(parsed)) {
      keys.set(id, Buffer.from(secret, 'hex'));
    }
    return keys;
  } catch (e) {
    logger.error('[env] Failed to parse EP_OPERATOR_KEYS — must be valid JSON', { error: e?.message });
    return new Map();
  }
}

/**
 * Parse the EP_OPERATOR_ROLES env var into a Map of operator_id -> role.
 *
 * Format: JSON object mapping operator_id to an OPERATOR_ROLES key, e.g.
 * `{"op_1": "reviewer", "op_2": "appeal_reviewer"}`.
 *
 * Operator keys prove identity. Operator roles prove authority. Keep the
 * mapping separate from EP_OPERATOR_KEYS so key rotation never silently changes
 * least-privilege assignment.
 *
 * @returns {Map<string, string>}
 */
export function getOperatorRoles() {
  const raw = process.env.EP_OPERATOR_ROLES;
  if (!raw) return new Map();

  try {
    const parsed = JSON.parse(raw);
    return new Map(Object.entries(parsed).filter(([, role]) => typeof role === 'string'));
  } catch (e) {
    logger.error('[env] Failed to parse EP_OPERATOR_ROLES — must be valid JSON', { error: e?.message });
    return new Map();
  }
}

/**
 * Feature flag — rules-engine v0 shadow signal. When 'enabled', the v1
 * trust-receipts route runs the new rules-engine alongside the live
 * evaluator and emits a side-by-side audit_event. Pure observability;
 * does not affect API responses.
 *
 * @returns {boolean}
 */
export function isRulesEngineV0Enabled() {
  return process.env.EP_RULES_ENGINE_V0 === 'enabled';
}
