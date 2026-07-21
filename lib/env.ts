/**
 * EMILIA Protocol — Centralized Environment Configuration
 *
 * Application runtime configuration should go through this module.
 * The structured logger consumes its bootstrap settings from this module too;
 * keeping that read here prevents scattered process.env access.
 *
 * This makes env dependencies explicit, testable, and auditable.
 *
 * @license Apache-2.0
 */
import { strictJsonGate } from './strict-json.js';

const MAX_ENV_JSON_BYTES = 1024 * 1024;

// Environment validation runs during module bootstrap, so it cannot depend on
// the structured logger without creating an env <-> logger import cycle.
const envLogger = {
  warn(...args: unknown[]) { console.warn(...args); },
  error(...args: unknown[]) { console.error(...args); },
};

/** Bootstrap-only configuration consumed by lib/logger.js. */
export function getLoggerConfig(): { version: string; isDevelopment: boolean; isTest: boolean; level: string } {
  return {
    version: process.env.npm_package_version ?? 'unknown',
    isDevelopment: process.env.NODE_ENV === 'development' || process.env.NODE_ENV === undefined,
    isTest: process.env.NODE_ENV === 'test',
    level: process.env.LOG_LEVEL ?? 'info',
  };
}

function parseStrictEnvJson(raw: unknown, label: string): any {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > MAX_ENV_JSON_BYTES) {
    throw new Error(`${label} exceeds the environment JSON size limit`);
  }
  const strict = strictJsonGate(raw);
  if (!strict.ok) throw new Error(`${label} must be strict JSON: ${strict.reason}`);
  return JSON.parse(raw);
}

// =============================================================================
// VALIDATION HELPER (retained from original)
// =============================================================================

export function assertServerEnv(
  { required = [] }: { required?: string[] } = {},
): { ok: boolean; missing?: string[] } {
  const missing = required.filter(k => !process.env[k]);
  if (missing.length === 0) return { ok: true };

  const msg = `Missing required server env: ${missing.join(', ')}`;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(msg);
  }

  // In non-production, warn but allow startup for developer convenience
  envLogger.warn('ENV WARNING:', msg);
  return { ok: false, missing };
}

// =============================================================================
// SUPABASE
// =============================================================================

export function getSupabaseConfig(): { url: string | undefined; serviceRoleKey: string | undefined; anonKey: string | undefined } {
  return {
    url: process.env.NEXT_PUBLIC_SUPABASE_URL,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    anonKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  };
}

// =============================================================================
// OPENAI
// =============================================================================

export function getOpenAIKey(): string | null {
  return process.env.OPENAI_API_KEY || null;
}

// =============================================================================
// UPSTASH REDIS
// =============================================================================

export function getUpstashConfig(): { url: string; token: string } | null {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return { url, token };
}

// =============================================================================
// SSO / WEBAUTHN / SIEM RUNTIME CONFIGURATION
// =============================================================================

/**
 * SSO signing configuration. Production callers must provide two separate
 * secrets: one for the transient state cookie and one for the session JWT.
 * Non-production callers may use the module-local random fallback in the SSO
 * helpers; no deployment credential or source-predictable literal is reused.
 */
export function getSsoConfig(): { stateSecret: string | null; sessionSecret: string | null; isProduction: boolean } {
  return {
    stateSecret: process.env.SSO_STATE_SECRET || null,
    sessionSecret: process.env.SSO_SESSION_SECRET || null,
    isProduction: isProduction(),
  };
}

/**
 * Deployment-held signing seed for the synthetic public demo surfaces.
 *
 * The public /r/example fixture is signed offline and does not need this
 * value. Dynamic crash-test receipts do: production refuses to generate them
 * without an explicitly configured seed, so demo signing can never silently
 * fall back to source-controlled key material.
 */
export function getDemoSigningKey(): string | null {
  return process.env.EP_DEMO_SIGNING_KEY || null;
}

/** WebAuthn RP overrides, kept separate from the EP_WEBAUTHN_* verifier pins. */
export function getWebAuthnConfig(): { rpId: string | null; origin: string | null; isDevelopment: boolean } {
  return {
    rpId: process.env.WEBAUTHN_RP_ID || null,
    origin: process.env.WEBAUTHN_ORIGIN || null,
    isDevelopment: process.env.NODE_ENV === 'development',
  };
}

/** SIEM forwarding configuration, read at call time so runtime env changes remain visible. */
export function getSiemConfig(): {
  webhookUrl: string | null;
  authHeader: string | null;
  format: string;
  source: string;
  index: string;
  disabled: boolean;
  host: string;
  isProduction: boolean;
} {
  return {
    webhookUrl: process.env.SIEM_WEBHOOK_URL ?? null,
    authHeader: process.env.SIEM_AUTH_HEADER ?? null,
    format: process.env.SIEM_FORMAT ?? 'splunk',
    source: process.env.SIEM_SOURCE ?? 'emilia-protocol',
    index: process.env.SIEM_INDEX ?? 'security',
    disabled: process.env.SIEM_DISABLED === 'true',
    host: process.env.VERCEL_URL ?? 'emilia-protocol',
    isProduction: isProduction(),
  };
}

// =============================================================================
// BLOCKCHAIN
// =============================================================================

export function getBlockchainConfig(): {
  network: string;
  walletPrivateKey: string | undefined;
  signingMode: string;
  signingKeyId: string | null;
} | null {
  const network = process.env.BASE_NETWORK;
  const walletPrivateKey = process.env.EP_WALLET_PRIVATE_KEY;
  const signingMode = process.env.EP_BLOCKCHAIN_SIGNING_MODE || 'env';
  const signingKeyId = process.env.EP_BLOCKCHAIN_SIGNING_KEY_ID || null;
  if (!network && !walletPrivateKey && !signingKeyId && signingMode === 'env') return null;
  return { network: network || 'sepolia', walletPrivateKey, signingMode, signingKeyId };
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
 */
export function getCommitSigningConfig(): {
  signingKey: string | null;
  trustedKeys: Record<string, string> | null;
  isProduction: boolean;
} {
  const signingKey = process.env.EP_COMMIT_SIGNING_KEY || null;
  const isProductionEnv = process.env.NODE_ENV === 'production';

  let trustedKeys: Record<string, string> | null = null;
  const trustedKeysRaw = process.env.EP_COMMIT_SIGNING_KEYS;
  if (trustedKeysRaw) {
    try {
      const parsed = parseStrictEnvJson(trustedKeysRaw, 'EP_COMMIT_SIGNING_KEYS');
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('EP_COMMIT_SIGNING_KEYS must be a JSON object of {kid: base64key}');
      }
      // Build a clean kid->key map: drop prototype-pollution keys and any
      // non-string values, so a malformed/hostile env var can't inject a key or
      // pollute Object.prototype. (HI-4)
      const clean: Record<string, string> = Object.create(null);
      for (const [kid, val] of Object.entries(parsed)) {
        if (kid === '__proto__' || kid === 'constructor' || kid === 'prototype') continue;
        if (typeof kid !== 'string' || typeof val !== 'string' || !val) continue;
        clean[kid] = val;
      }
      trustedKeys = clean;
    } catch (e: any) {
      if (isProductionEnv) {
        throw new Error('EP_COMMIT_SIGNING_KEYS contains invalid JSON or structure');
      }
      envLogger.warn(`ENV WARNING: EP_COMMIT_SIGNING_KEYS invalid (${e.message}), ignoring`);
    }
  }

  return { signingKey, trustedKeys, isProduction: isProductionEnv };
}

// =============================================================================
// GOVERNMENT / HIGH-ASSURANCE DEPLOYMENT
// =============================================================================

function splitKeyList(raw: string): string[] {
  if (!raw) return [];
  if (raw.trim().startsWith('[')) {
    const parsed = parseStrictEnvJson(raw, 'trusted issuer keys');
    if (!Array.isArray(parsed)) throw new Error('trusted issuer keys must be a JSON array or comma-separated list');
    return parsed.map((v) => String(v).trim()).filter(Boolean);
  }
  return raw.split(',').map((v) => v.trim()).filter(Boolean);
}

/**
 * Trusted receipt issuer keys for production "Receipt Required" verification.
 * Inline/self-asserted keys are demo-only; production callers pin these.
 */
export function getGovVerifierConfig(): {
  trustedIssuerKeys: string[];
  govStrict: boolean;
  rpId: string | null;
  allowedOrigins: string[];
  expectedPolicyHash: string | null;
} {
  const rawKeys = process.env.EP_TRUSTED_ISSUER_KEYS || process.env.EMILIA_TRUSTED_ISSUER_KEYS || '';
  let trustedIssuerKeys: string[] = [];
  let allowedOrigins: string[] = [];
  try {
    trustedIssuerKeys = splitKeyList(rawKeys);
  } catch (e: any) {
    if (isProduction()) throw new Error(`EP_TRUSTED_ISSUER_KEYS invalid: ${e.message}`);
    envLogger.warn(`ENV WARNING: EP_TRUSTED_ISSUER_KEYS invalid (${e.message}), ignoring`);
  }
  try {
    allowedOrigins = splitKeyList(process.env.EP_WEBAUTHN_ALLOWED_ORIGINS || '');
  } catch (e: any) {
    if (isProduction()) throw new Error(`EP_WEBAUTHN_ALLOWED_ORIGINS invalid: ${e.message}`);
    envLogger.warn(`ENV WARNING: EP_WEBAUTHN_ALLOWED_ORIGINS invalid (${e.message}), ignoring`);
  }
  return {
    trustedIssuerKeys,
    // Gov-strict is an EXPLICIT deployment mode (EP_GOV_STRICT=true), not auto-on
    // for any production build. Non-demo guarded endpoints still require pinned
    // issuer keys; /api/demo/* is the only self-signed playground.
    govStrict: process.env.EP_GOV_STRICT === 'true',
    rpId: process.env.EP_WEBAUTHN_RP_ID || null,
    allowedOrigins,
    expectedPolicyHash: process.env.EP_EXPECTED_POLICY_HASH || null,
  };
}

/** Relying-party-pinned quorum policies keyed by canonical action_type. */
export function getPinnedQuorumPolicies(): Record<string, Record<string, unknown>> {
  const raw = process.env.EP_QUORUM_POLICIES || '';
  if (!raw.trim()) return {};
  try {
    const parsed = parseStrictEnvJson(raw, 'EP_QUORUM_POLICIES');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('must be a JSON object keyed by action_type');
    }
    const clean: Record<string, Record<string, unknown>> = Object.create(null);
    for (const [action, policy] of Object.entries(parsed)) {
      if (['__proto__', 'constructor', 'prototype'].includes(action)) continue;
      if (typeof action === 'string' && action && policy && typeof policy === 'object' && !Array.isArray(policy)) {
        clean[action] = policy as Record<string, unknown>;
      }
    }
    return clean;
  } catch (e: any) {
    if (isProduction()) throw new Error(`EP_QUORUM_POLICIES invalid: ${e.message}`);
    envLogger.warn(`ENV WARNING: EP_QUORUM_POLICIES invalid (${e.message}), ignoring`);
    return {};
  }
}

/**
 * Declared crypto-profile id (EP-CRYPTO-PROFILE). Returns the raw env value or
 * null; resolution (default + fail-closed validation) lives in
 * lib/crypto/profile.js. Kept here so the EP_ read goes through the env layer
 * (protocol-discipline: no direct process.env.EP_ reads outside lib/env.js).
 */
export function getCryptoProfileId(): string | null {
  return process.env.EP_CRYPTO_PROFILE || null;
}

/**
 * Deployment-held key for PHI-minimized Rx appeal-bundle projections. The key
 * is distinct from all signing keys; the identifier is non-secret and travels
 * in the bundle so authorized holders can reproduce commitments after rotation.
 * Invalid or incomplete configuration is unavailable, never weakened.
 */
export function getRxPrivacyConfig(): { key: Buffer; keyId: string } | null {
  const encoded = process.env.EP_RX_PRIVACY_KEY_B64U || '';
  const keyId = process.env.EP_RX_PRIVACY_KEY_ID || '';
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(keyId)) return null;
  let key: Buffer;
  try { key = Buffer.from(encoded, 'base64url'); } catch { return null; }
  if (key.length < 32 || key.toString('base64url') !== encoded) return null;
  return { key, keyId };
}

/**
 * Pinned approver public keys for high-assurance (Class-A / quorum) receipt
 * proof verification. A receipt's issuer may DESCRIBE a human signoff, but a
 * Class-A/quorum tier is only PROVEN when each signoff in the receipt's
 * assurance_proof verifies against a key pinned here.
 *
 * Shape: a JSON object keyed by approver_key_id, e.g.
 *   {"ep:key:cfo#1": {"approver_id": "ep:approver:cfo", "public_key": "<base64url SPKI DER>", "key_class": "A"}}
 *
 * Returns {} when unset — which correctly forces every high-tier proof to fail
 * closed (no pinned keys ⇒ no signoff can verify ⇒ assurance_too_low).
 *
 */
export function getPinnedApproverKeys(): Record<string, { approver_id: string; public_key: string; key_class?: 'A' | 'B' }> {
  const raw = process.env.EP_PINNED_APPROVER_KEYS || process.env.EMILIA_PINNED_APPROVER_KEYS || '';
  if (!raw.trim()) return {};
  let parsed;
  try {
    parsed = parseStrictEnvJson(raw, 'EP_PINNED_APPROVER_KEYS');
  } catch (e: any) {
    if (isProduction()) throw new Error(`EP_PINNED_APPROVER_KEYS invalid JSON: ${e.message}`);
    envLogger.warn(`ENV WARNING: EP_PINNED_APPROVER_KEYS invalid JSON (${e.message}), ignoring`);
    return {};
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    if (isProduction()) throw new Error('EP_PINNED_APPROVER_KEYS must be a JSON object keyed by approver_key_id');
    envLogger.warn('ENV WARNING: EP_PINNED_APPROVER_KEYS must be a JSON object, ignoring');
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
export function getKeyCustodyConfig(): {
  mode: string;
  keyId: string | null;
  fipsRequired: boolean;
  govStrict: boolean;
  isProduction: boolean;
} {
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
export function getAuditRetentionConfig(): { hotDays: number; coldDays: number; exportEnabled: boolean } {
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
export function getRateLimitConfig(): { durableRequired: boolean } {
  return {
    // Production has no safe cross-instance memory fallback for sensitive
    // categories. lib/rate-limit.js uses this flag to refuse those requests
    // when Upstash is unavailable; read-only traffic retains its availability
    // posture there by design.
    durableRequired: isProduction()
      || process.env.EP_GOV_STRICT === 'true'
      || process.env.EP_REQUIRE_DURABLE_RATE_LIMIT === 'true',
  };
}

/**
 * Public self-serve key issuance posture. Production must not mint live API
 * keys from anonymous signup/playground forms unless the operator explicitly
 * opts in after adding an external proof step (email verification, CAPTCHA, or
 * approval workflow). Dev/test stays open so local demos and unit tests remain
 * usable without provisioning.
 */
export function isPublicEntityRegistrationEnabled(): boolean {
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
export function isTierQuorumEnforced(): boolean {
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
export function isQuorumTemplateRequired(): boolean {
  return process.env.EP_QUORUM_TEMPLATE_REQUIRED === 'true';
}

/**
 * EP-AUTHORITY-REGISTRY-v1 staged-enforcement mode (server-pinned, NEVER
 * caller-selectable — unlike the guard enforcement mode, which the caller sets
 * in the request body). Rollout order:
 *   shadow -> warn -> enforce_critical -> enforce_default
 * Default 'shadow': resolve real authority, bind it into the receipt, and log
 * what WOULD have been denied, without blocking any action. Only enforce_*
 * modes fail closed (enforce_critical blocks critical actions on a non-authorized
 * verdict; enforce_default blocks all). An unset or unrecognized value is
 * treated as 'shadow' (fail-safe: never accidentally enforce a half-populated
 * registry). Set EP_AUTHORITY_ENFORCEMENT to advance the rollout once the
 * shadow logs show the registry denies nothing legitimate.
 */
export function authorityEnforcementMode(): 'shadow' | 'warn' | 'enforce_critical' | 'enforce_default' {
  const raw = process.env.EP_AUTHORITY_ENFORCEMENT;
  const allowed: ReadonlyArray<string | undefined> = ['shadow', 'warn', 'enforce_critical', 'enforce_default'];
  return allowed.includes(raw)
    ? (raw as 'shadow' | 'warn' | 'enforce_critical' | 'enforce_default')
    : 'shadow';
}

/**
 * At-rest secret-box key (lib/crypto/secret-box). EP_SECRET_KEY (64 hex = 32
 * bytes) when set; null otherwise (secret-box derives a stable fallback from
 * the service-role key so every deployment has a key with zero new config).
 */
export function getSecretBoxKey(): string | null {
  const key = process.env.EP_SECRET_KEY;
  return key && /^[0-9a-f]{64}$/i.test(key) ? key : null;
}

// =============================================================================
// EP PLATFORM
// =============================================================================

export function getEPConfig(): { apiUrl: string; apiKey: string; baseUrl: string } {
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
 */
export function isScimAutoApproverEnabled(): boolean {
  return process.env.EP_SCIM_AUTO_APPROVER === 'true';
}

/**
 * Canonical public origin (www host, so requests don't 307-redirect). Used by
 * the remote MCP server's read tools to reach EP's own public endpoints.
 */
export function getPublicBaseUrl(): string {
  return process.env.EP_PUBLIC_BASE_URL || 'https://www.emiliaprotocol.ai';
}

/**
 * EP-APPROVAL-v1 server configuration. The encryption key protects the
 * recoverable polling capability at rest; the public origin is used only to
 * construct the same-origin human review URL returned to the requester.
 */
export function getApprovalAcquisitionConfig(): {
  tokenEncryptionKey: string | null;
  publicOrigin: string | null;
} {
  return {
    tokenEncryptionKey: process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY || null,
    publicOrigin: process.env.EP_APPROVAL_PUBLIC_ORIGIN || null,
  };
}

// =============================================================================
// AUTO-SUBMIT SECRET (machine credential for /api/receipts/auto-submit)
// =============================================================================

/**
 * Shared secret for authenticating machine-to-machine auto-submit requests.
 * Must be set in production. In development, a missing key causes requests
 * to be rejected with 401.
 */
export function getAutoSubmitSecret(): string | null {
  return process.env.EP_AUTO_SUBMIT_SECRET || null;
}

// =============================================================================
// CRON SECRET
// =============================================================================

export function getCronSecret(): string | null {
  return process.env.CRON_SECRET || null;
}

// =============================================================================
// GITHUB TOKEN
// =============================================================================

export function getGitHubToken(): string | null {
  return process.env.GITHUB_TOKEN || null;
}

// =============================================================================
// NODE_ENV HELPER
// =============================================================================

export function isProduction(): boolean {
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
 */
export function getOperatorKeys(): Map<string, Buffer> {
  const raw = process.env.EP_OPERATOR_KEYS;
  if (!raw) return new Map<string, Buffer>();

  try {
    const parsed = parseStrictEnvJson(raw, 'EP_OPERATOR_KEYS');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('EP_OPERATOR_KEYS must be an object');
    const keys = new Map<string, Buffer>();
    for (const [id, secret] of Object.entries(parsed)) {
      if (!id || id.length > 128 || ['__proto__', 'constructor', 'prototype'].includes(id)
          || typeof secret !== 'string' || secret.length < 64 || secret.length > 256
          || secret.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(secret)) {
        throw new Error('EP_OPERATOR_KEYS contains an invalid operator id or secret');
      }
      keys.set(id, Buffer.from(secret, 'hex'));
    }
    return keys;
  } catch (e: any) {
    envLogger.error('[env] Failed to parse EP_OPERATOR_KEYS — must be valid JSON', { error: e?.message });
    return new Map<string, Buffer>();
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
 */
export function getOperatorRoles(): Map<string, string> {
  const raw = process.env.EP_OPERATOR_ROLES;
  if (!raw) return new Map<string, string>();

  try {
    const parsed = parseStrictEnvJson(raw, 'EP_OPERATOR_ROLES');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('EP_OPERATOR_ROLES must be an object');
    return new Map<string, string>(Object.entries(parsed).filter(([id, role]) => id && id.length <= 128
      && !['__proto__', 'constructor', 'prototype'].includes(id)
      && typeof role === 'string' && role.length > 0 && role.length <= 128) as [string, string][]);
  } catch (e: any) {
    envLogger.error('[env] Failed to parse EP_OPERATOR_ROLES — must be valid JSON', { error: e?.message });
    return new Map<string, string>();
  }
}

/**
 * Feature flag — rules-engine v0 shadow signal. When 'enabled', the v1
 * trust-receipts route runs the new rules-engine alongside the live
 * evaluator and emits a side-by-side audit_event. Pure observability;
 * does not affect API responses.
 */
export function isRulesEngineV0Enabled(): boolean {
  return process.env.EP_RULES_ENGINE_V0 === 'enabled';
}
