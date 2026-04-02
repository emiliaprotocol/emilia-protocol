/**
 * EMILIA Protocol — Auto-Receipt Middleware
 * @license Apache-2.0
 *
 * Wraps MCP tool call handlers and automatically generates behavioral receipts
 * from every tool invocation outcome. This closes the data loop: every tool call
 * becomes a potential trust signal without requiring manual receipt submission.
 *
 * Design principles:
 *   - Opt-in by default. Auto-receipt is disabled unless explicitly enabled.
 *   - Non-blocking. Receipt submission is fire-and-forget; it never delays the tool response.
 *   - Privacy-preserving. Sensitive fields are redacted before any data leaves the process.
 *   - Provenance-honest. Auto-generated receipts are always marked unilateral — they cannot
 *     be bilateral without counterparty confirmation.
 *
 * Usage:
 *   import { AutoReceiptMiddleware } from './auto-receipt.js';
 *
 *   const middleware = new AutoReceiptMiddleware({
 *     epApiUrl: 'https://api.emiliaprotocol.com',
 *     epApiKey: process.env.EP_API_KEY,
 *     optIn: true,
 *     entityId: 'my-mcp-server',
 *   });
 *
 *   const safeHandler = middleware.wrap('ep_trust_profile', originalHandler);
 *   const result = await safeHandler(args);
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default fields whose values should never appear in a stored receipt.
 * Matched case-insensitively against all keys in input/output objects.
 */
const DEFAULT_SENSITIVE_FIELDS = [
  'password',
  'token',
  'key',
  'secret',
  'api_key',
  'apikey',
  'auth',
  'credential',
  'credentials',
  'authorization',
  'private_key',
  'access_token',
  'refresh_token',
  'client_secret',
  'bearer',
  'ssn',
  'credit_card',
  'card_number',
  'cvv',
  'pin',
];

/** Sentinel value replacing redacted field contents. */
const REDACTED_SENTINEL = '[REDACTED]';

/** Maximum auto-submit batch size (matches /api/receipts/auto-submit limit). */
const BATCH_MAX = 100;

/** Auto-submit endpoint path. */
const AUTO_SUBMIT_PATH = '/api/receipts/auto-submit';

// ---------------------------------------------------------------------------
// AutoReceiptMiddleware
// ---------------------------------------------------------------------------

export class AutoReceiptMiddleware {
  /**
   * Create an AutoReceiptMiddleware instance.
   *
   * @param {object} config
   * @param {string}   [config.epApiUrl='https://api.emiliaprotocol.com']
   *   Base URL of the EP API. Must not include a trailing slash.
   * @param {string}   [config.epApiKey='']
   *   Bearer token for auto-submission. If omitted, receipts are generated
   *   locally but submission silently skips.
   * @param {boolean}  [config.optIn=false]
   *   Master switch. Auto-receipt does nothing unless this is true.
   *   Agents must explicitly call ep_configure_auto_receipt to enable.
   * @param {string[]} [config.sensitiveFields=[]]
   *   Additional field names to redact, merged with the built-in defaults.
   * @param {string}   [config.entityId='']
   *   The entity ID attributed as the submitter of every auto-generated receipt.
   *   Typically the MCP server operator's entity slug.
   */
  constructor(config = {}) {
    this.epApiUrl = (config.epApiUrl || 'https://api.emiliaprotocol.com').replace(/\/$/, '');
    this.epApiKey = config.epApiKey || '';
    this.optIn = config.optIn === true;
    this.entityId = config.entityId || '';
    this.sensitiveFields = [
      ...DEFAULT_SENSITIVE_FIELDS,
      ...(config.sensitiveFields || []).map(f => f.toLowerCase()),
    ];

    /** Pending receipts buffer — drained asynchronously. @type {object[]} */
    this._pending = [];
    this._flushScheduled = false;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Wrap a tool handler function with auto-receipt instrumentation.
   *
   * The returned wrapper is a drop-in replacement: it accepts the same
   * arguments, returns the same result, and throws the same errors.
   * Auto-receipt runs asynchronously in the background.
   *
   * @param {string}   toolName  The MCP tool name (used as context.task_type).
   * @param {Function} handler   Original async tool handler: (args) => Promise<any>.
   * @returns {Function}         Wrapped handler with identical signature.
   */
  wrap(toolName, handler) {
    if (typeof handler !== 'function') {
      throw new TypeError(`AutoReceiptMiddleware.wrap: handler for "${toolName}" must be a function`);
    }

    return async (args) => {
      const start = Date.now();
      let result;
      let error = null;

      try {
        result = await handler(args);
        return result;
      } catch (err) {
        error = err;
        throw err;
      } finally {
        // Always runs — even if the handler throws.
        const latencyMs = Date.now() - start;

        if (this.optIn) {
          // Generate the receipt draft outside the hot path.
          // Errors here must never surface to the tool caller.
          try {
            const receipt = this.generateReceiptDraft(toolName, args, result, latencyMs, error);
            this._enqueue(receipt);
          } catch (draftErr) {
            // Silently swallow — receipt generation must never affect tool behavior.
            if (process.env.EP_AUTO_RECEIPT_DEBUG) {
              console.warn('[AutoReceipt] Draft generation failed:', draftErr.message);
            }
          }
        }
      }
    };
  }

  /**
   * Generate a receipt draft from a tool call's metadata.
   *
   * The draft conforms to the EP receipt schema and is marked
   * auto_generated: true with provenance 'unilateral'.
   *
   * @param {string}  toolName   MCP tool name.
   * @param {object}  input      Tool input arguments (will be redacted).
   * @param {any}     output     Tool output (will be redacted if object).
   * @param {number}  latencyMs  Wall-clock latency in milliseconds.
   * @param {Error|null} error   The error thrown by the handler, if any.
   * @returns {object}           EP receipt draft.
   */
  generateReceiptDraft(toolName, input, output, latencyMs, error) {
    const completed = error == null;
    const errorOccurred = !completed;

    // Sanitize inputs before storing.
    const safeInput = input && typeof input === 'object'
      ? this.redactSensitive(input)
      : {};

    // Only include output metadata (type + size), never raw output content,
    // to prevent inadvertent PII storage in receipt payloads.
    const outputMeta = this._outputMeta(output);

    const draft = {
      // Who is submitting this receipt (the MCP server operator).
      entity_id: this.entityId || 'unknown',

      // Counterparty is unknown in unilateral auto-receipts.
      counterparty_id: 'auto',

      // Synthetic transaction reference: tool + timestamp + random suffix
      // for idempotency on the EP side.
      transaction_ref: `auto_${toolName}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,

      // Behavioral context.
      context: {
        task_type: toolName,
        input_keys: Object.keys(safeInput),
        modality: 'mcp_tool',
      },

      // Observable outcome signals.
      outcome: {
        completed,
        latency_ms: latencyMs,
        error_occurred: errorOccurred,
        error_type: errorOccurred ? (error.name || 'Error') : null,
        output_type: outputMeta.type,
        output_size_chars: outputMeta.sizeChars,
      },

      // Provenance: unilateral — submitted by one party without counterparty confirmation.
      provenance: 'unilateral',

      // Metadata markers.
      auto_generated: true,
      generated_at: new Date().toISOString(),
    };

    return draft;
  }

  /**
   * Deep-clone an object and replace sensitive field values with REDACTED_SENTINEL.
   *
   * Matching is case-insensitive and checks whether any sensitive term appears
   * as a substring of the field name, to catch variants like `api_key_v2` or
   * `authorizationHeader`.
   *
   * @param {object} obj  Object to sanitize. Must be a plain object or array.
   * @returns {object}    Deep-cloned object with sensitive values replaced.
   */
  redactSensitive(obj) {
    return this._deepRedact(obj);
  }

  /**
   * Update the opt-in state and entity ID at runtime.
   * Called by the ep_configure_auto_receipt tool handler.
   *
   * @param {boolean} enabled   Whether to enable auto-receipt.
   * @param {string}  entityId  Entity ID to attribute receipts to.
   */
  configure(enabled, entityId) {
    this.optIn = Boolean(enabled);
    if (entityId) this.entityId = entityId;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * Enqueue a receipt draft for async submission.
   * Schedules a microtask flush if one is not already pending.
   *
   * @param {object} receipt
   */
  _enqueue(receipt) {
    this._pending.push(receipt);

    if (!this._flushScheduled) {
      this._flushScheduled = true;
      // Use setImmediate (Node) or Promise.resolve (browsers) to stay
      // outside the current call stack without blocking I/O.
      setImmediate(() => this._flush());
    }
  }

  /**
   * Drain the pending queue and submit to the EP auto-submit endpoint.
   * Batches receipts up to BATCH_MAX per HTTP request.
   * Never throws — errors are swallowed to protect the calling MCP tool.
   */
  async _flush() {
    this._flushScheduled = false;

    if (!this._pending.length) return;
    if (!this.epApiKey) {
      // No key configured — drop receipts silently.
      this._pending = [];
      return;
    }

    // Drain a snapshot; new receipts may arrive while we await.
    const batch = this._pending.splice(0, BATCH_MAX);

    try {
      await this._submitBatch(batch);
    } catch (err) {
      if (process.env.EP_AUTO_RECEIPT_DEBUG) {
        console.warn('[AutoReceipt] Batch submission failed:', err.message);
      }
      // Do not re-enqueue — dropped receipts are preferable to infinite retries
      // that could destabilise the MCP server under network partitions.
    }

    // If more accumulated during the flush, schedule another pass.
    if (this._pending.length > 0 && !this._flushScheduled) {
      this._flushScheduled = true;
      setImmediate(() => this._flush());
    }
  }

  /**
   * HTTP POST a batch of receipts to the EP auto-submit endpoint.
   *
   * @param {object[]} receipts
   * @returns {Promise<object>} API response body.
   */
  async _submitBatch(receipts) {
    const url = `${this.epApiUrl}${AUTO_SUBMIT_PATH}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Key is included for rate-limiting attribution, not authentication.
        'X-EP-Auto-Key': this.epApiKey,
      },
      body: JSON.stringify({ receipts }),
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Auto-submit returned ${res.status}: ${body.slice(0, 200)}`);
    }

    return res.json();
  }

  /**
   * Recursively redact sensitive keys from a value.
   *
   * @param {any}    value       Current node being traversed.
   * @param {number} [depth=0]  Recursion depth guard.
   * @returns {any}              Sanitized clone.
   */
  _deepRedact(value, depth = 0) {
    // Guard against circular structures and extremely deep objects.
    if (depth > 10) return '[DEPTH_LIMIT]';

    if (Array.isArray(value)) {
      return value.map(item => this._deepRedact(item, depth + 1));
    }

    if (value !== null && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) {
        if (this._isSensitiveKey(k)) {
          out[k] = REDACTED_SENTINEL;
        } else {
          out[k] = this._deepRedact(v, depth + 1);
        }
      }
      return out;
    }

    // Primitives pass through unchanged.
    return value;
  }

  /**
   * Return true if a field name matches any sensitive term.
   *
   * @param {string} key
   * @returns {boolean}
   */
  _isSensitiveKey(key) {
    const lower = key.toLowerCase();
    return this.sensitiveFields.some(term => lower.includes(term));
  }

  /**
   * Produce safe metadata about tool output without storing its contents.
   *
   * @param {any} output
   * @returns {{ type: string, sizeChars: number|null }}
   */
  _outputMeta(output) {
    if (output === undefined || output === null) {
      return { type: 'null', sizeChars: 0 };
    }
    if (typeof output === 'string') {
      return { type: 'string', sizeChars: output.length };
    }
    if (typeof output === 'object') {
      try {
        const serialized = JSON.stringify(output);
        return { type: 'object', sizeChars: serialized.length };
      } catch {
        return { type: 'object', sizeChars: null };
      }
    }
    return { type: typeof output, sizeChars: null };
  }
}
