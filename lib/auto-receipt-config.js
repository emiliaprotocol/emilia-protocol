/**
 * EMILIA Protocol — Auto-Receipt Configuration
 *
 * Manages per-entity opt-in state for automatic receipt generation from MCP
 * tool calls. Configuration is stored in the entities table (two columns:
 * auto_receipt_enabled BOOLEAN and auto_receipt_config JSONB).
 *
 * When the database is unavailable (e.g. during local development or tests)
 * the module falls back to an in-memory store so callers are never hard-blocked.
 *
 * Privacy contract:
 *   - Sensitive fields are ALWAYS stripped before a receipt is persisted.
 *   - Callers can extend the redaction list via entity config.
 *   - anonymous privacy_mode additionally hashes counterparty_id so the
 *     counterparty identity cannot be reconstructed from receipt data alone.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { logger } from './logger.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Fields that are unconditionally redacted from any receipt produced by the
 * auto-receipt pipeline. These are field *names* (case-insensitive match
 * applied against both top-level keys and nested keys in plain objects).
 *
 * @type {readonly string[]}
 */
export const DEFAULT_REDACT_FIELDS = Object.freeze([
  'password',
  'token',
  'api_key',
  'key',
  'secret',
  'auth',
  'credential',
  'private_key',
  'access_token',
  'refresh_token',
  'bearer',
]);

/** @type {'standard'|'anonymous'} */
const DEFAULT_PRIVACY_MODE = 'standard';

// ---------------------------------------------------------------------------
// In-memory fallback store
// ---------------------------------------------------------------------------

/**
 * Simple in-memory store used when the Supabase entities table is unavailable.
 * Keys are entity IDs; values are the same shape returned by getAutoReceiptConfig.
 * @type {Map<string, AutoReceiptConfig>}
 */
const _memoryStore = new Map();

// ---------------------------------------------------------------------------
// Type definitions (JSDoc)
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} AutoReceiptConfig
 * @property {boolean}           enabled      - Whether auto-receipt is enabled for this entity.
 * @property {string[]}          redact_fields - Additional fields to redact beyond the defaults.
 * @property {'standard'|'anonymous'} privacy_mode - Level of anonymisation applied to receipts.
 * @property {string}            last_updated - ISO 8601 timestamp of the last config change.
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Retrieve the auto-receipt configuration for an entity.
 *
 * Returns a sensible disabled-by-default config if the entity has never
 * configured auto-receipt. Falls back to in-memory state if the DB is
 * unreachable or the columns do not yet exist.
 *
 * @param {string} entityId - The entity's stable string identifier (entity_id column).
 * @returns {Promise<AutoReceiptConfig>}
 */
export async function getAutoReceiptConfig(entityId) {
  if (!entityId) {
    throw new Error('entityId is required');
  }

  try {
    const supabase = getServiceClient();

    const { data, error } = await supabase
      .from('entities')
      .select('auto_receipt_enabled, auto_receipt_config, updated_at')
      .eq('entity_id', entityId)
      .maybeSingle();

    if (error) {
      // Column missing (42703) or table missing (42P01) — fall back gracefully
      if (error.code === '42703' || error.code === '42P01') {
        logger.warn('[EP auto-receipt] DB columns not yet available — using in-memory fallback');
        return _memoryGet(entityId);
      }
      throw error;
    }

    if (!data) {
      return _defaultConfig();
    }

    const cfg = data.auto_receipt_config || {};
    return {
      enabled: data.auto_receipt_enabled ?? false,
      redact_fields: Array.isArray(cfg.redact_fields) ? cfg.redact_fields : [],
      privacy_mode: cfg.privacy_mode === 'anonymous' ? 'anonymous' : DEFAULT_PRIVACY_MODE,
      last_updated: data.updated_at || new Date().toISOString(),
    };
  } catch (err) {
    // Network / env error — fall back to in-memory
    logger.warn('[EP auto-receipt] DB unavailable, using in-memory fallback:', err.message);
    return _memoryGet(entityId);
  }
}

/**
 * Persist (upsert) the auto-receipt configuration for an entity.
 *
 * Only updates the auto-receipt columns; all other entity fields are left
 * untouched. Falls back to in-memory storage when the DB is unavailable.
 *
 * @param {string} entityId - The entity's stable string identifier.
 * @param {Object} opts
 * @param {boolean}  opts.enabled       - Whether to enable auto-receipt.
 * @param {string[]} [opts.redact_fields=[]] - Additional fields to redact.
 * @param {'standard'|'anonymous'} [opts.privacy_mode='standard'] - Privacy mode.
 * @returns {Promise<AutoReceiptConfig>} The updated configuration.
 */
export async function setAutoReceiptConfig(entityId, { enabled, redact_fields = [], privacy_mode = DEFAULT_PRIVACY_MODE } = {}) {
  if (!entityId) {
    throw new Error('entityId is required');
  }
  if (typeof enabled !== 'boolean') {
    throw new Error('enabled must be a boolean');
  }
  if (!Array.isArray(redact_fields)) {
    throw new Error('redact_fields must be an array of strings');
  }
  if (privacy_mode !== 'standard' && privacy_mode !== 'anonymous') {
    throw new Error("privacy_mode must be 'standard' or 'anonymous'");
  }

  const now = new Date().toISOString();
  const configPayload = {
    redact_fields: redact_fields.map(String),
    privacy_mode,
  };

  try {
    const supabase = getServiceClient();

    const { error } = await supabase
      .from('entities')
      .update({
        auto_receipt_enabled: enabled,
        auto_receipt_config: configPayload,
        updated_at: now,
      })
      .eq('entity_id', entityId);

    if (error) {
      if (error.code === '42703' || error.code === '42P01') {
        logger.warn('[EP auto-receipt] DB columns not yet available — persisting to in-memory fallback');
        return _memorySet(entityId, { enabled, redact_fields, privacy_mode, last_updated: now });
      }
      throw error;
    }

    return {
      enabled,
      redact_fields: configPayload.redact_fields,
      privacy_mode,
      last_updated: now,
    };
  } catch (err) {
    logger.warn('[EP auto-receipt] DB unavailable, persisting to in-memory fallback:', err.message);
    return _memorySet(entityId, { enabled, redact_fields, privacy_mode, last_updated: now });
  }
}

/**
 * Build a privacy filter function from an entity's auto-receipt config.
 *
 * The returned function accepts a raw receipt data object and returns a
 * sanitised copy with all sensitive fields removed (or replaced with
 * "[REDACTED]") and, in anonymous mode, counterparty_id hashed.
 *
 * Redaction is applied to:
 *   1. All keys in DEFAULT_REDACT_FIELDS (case-insensitive).
 *   2. All keys in config.redact_fields (case-insensitive).
 *
 * The filter never mutates the original object.
 *
 * @param {AutoReceiptConfig} config - Config returned by getAutoReceiptConfig.
 * @returns {(receiptData: Record<string, unknown>) => Record<string, unknown>}
 */
export function buildPrivacyFilter(config) {
  const { redact_fields: customFields = [], privacy_mode = DEFAULT_PRIVACY_MODE } = config || {};

  // Build a unified lowercase set for O(1) lookups
  const redactSet = new Set([
    ...DEFAULT_REDACT_FIELDS.map(f => f.toLowerCase()),
    ...customFields.map(f => String(f).toLowerCase()),
  ]);

  /**
   * Recursively sanitise a plain object.
   * @param {unknown} value
   * @param {number} depth - Guards against circular references / deep objects.
   * @returns {unknown}
   */
  function sanitise(value, depth = 0) {
    if (depth > 10) return value; // safety cap
    if (value === null || value === undefined) return value;
    if (typeof value !== 'object' || Array.isArray(value)) return value;

    const sanitised = {};
    for (const [k, v] of Object.entries(value)) {
      if (redactSet.has(k.toLowerCase())) {
        sanitised[k] = '[REDACTED]';
      } else if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
        sanitised[k] = sanitise(v, depth + 1);
      } else {
        sanitised[k] = v;
      }
    }
    return sanitised;
  }

  /**
   * Privacy filter — call with raw receipt data.
   * @param {Record<string, unknown>} receiptData
   * @returns {Record<string, unknown>}
   */
  return function privacyFilter(receiptData) {
    if (!receiptData || typeof receiptData !== 'object') return receiptData;

    // Deep sanitise all fields
    const result = sanitise(receiptData);

    // Anonymous mode: hash counterparty_id
    if (privacy_mode === 'anonymous' && result.counterparty_id != null) {
      result.counterparty_id = _hashAnonymous(String(result.counterparty_id));
    }

    return result;
  };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * @returns {AutoReceiptConfig}
 */
function _defaultConfig() {
  return {
    enabled: false,
    redact_fields: [],
    privacy_mode: DEFAULT_PRIVACY_MODE,
    last_updated: new Date().toISOString(),
  };
}

/**
 * @param {string} entityId
 * @returns {AutoReceiptConfig}
 */
function _memoryGet(entityId) {
  return _memoryStore.get(entityId) || _defaultConfig();
}

/**
 * @param {string} entityId
 * @param {AutoReceiptConfig} cfg
 * @returns {AutoReceiptConfig}
 */
function _memorySet(entityId, cfg) {
  _memoryStore.set(entityId, cfg);
  return cfg;
}

/**
 * One-way SHA-256 hash of a counterparty ID for anonymous mode.
 * Prefixed so the value is clearly a hash, not a real ID.
 *
 * @param {string} id
 * @returns {string} e.g. "anon_sha256_abc123..."
 */
function _hashAnonymous(id) {
  const hash = crypto.createHash('sha256').update(id).digest('hex');
  return `anon_sha256_${hash}`;
}
