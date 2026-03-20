/**
 * POST /api/receipts/auto-submit
 *
 * Lightweight, high-throughput endpoint for ingesting auto-generated behavioral receipts
 * from the EMILIA Protocol MCP server's AutoReceiptMiddleware.
 *
 * SECURITY MODEL:
 *   - Authenticated via Bearer token OR x-ep-auto-key header.
 *     Bearer token: standard EP API key (Authorization: Bearer ep_live_...).
 *     x-ep-auto-key: a shared machine secret (EP_AUTO_SUBMIT_SECRET env var).
 *     At least one MUST be present and valid.
 *   - All writes go through the canonical writer (lib/canonical-writer.js),
 *     which enforces fraud checks, self-score prevention, dedup/idempotency,
 *     quota logic, attribution chains, and materialization.
 *   - Batch-first. Accepts up to 100 receipts per request to minimize HTTP overhead
 *     from high-frequency tool calls.
 *   - Immutable provenance. All auto-generated receipts are forced to provenance='unilateral'.
 *     They cannot claim bilateral status without counterparty confirmation via the
 *     standard bilateral confirmation flow.
 *   - Fails open per receipt. A single invalid receipt never blocks the entire batch.
 *
 * Request body:
 *   { receipts: [receipt, ...] }   max 100 items
 *
 * Response:
 *   { accepted: N, rejected: M, receipt_ids: ['ep_rcpt_...', ...], errors: [...] }
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { authenticateRequest } from '@/lib/supabase';
import { canonicalSubmitAutoReceipt } from '@/lib/canonical-writer';
import { epProblem } from '@/lib/errors';
import { getAutoSubmitSecret } from '@/lib/env';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum receipts accepted per request. */
const BATCH_MAX = 100;

/** Required top-level fields on every auto-receipt. */
const REQUIRED_FIELDS = ['entity_id', 'transaction_ref'];

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Authenticate the request via either:
 *   1. Standard Bearer token (Authorization: Bearer ep_live_...) — preferred.
 *   2. Shared machine secret (x-ep-auto-key header matching EP_AUTO_SUBMIT_SECRET).
 *
 * Returns an entity object usable as the `submitter` parameter for the
 * canonical writer, or an error object.
 *
 * @param {Request} request
 * @returns {Promise<{ entity: object } | { error: string }>}
 */
async function authenticateAutoSubmit(request) {
  // Path 1: standard Bearer token (full API key auth with entity lookup)
  const authHeader = request.headers.get('authorization');
  if (authHeader?.startsWith('Bearer ep_')) {
    const auth = await authenticateRequest(request);
    if (!auth.error) {
      return { entity: auth.entity };
    }
    // If Bearer was provided but invalid, fail immediately — don't fall through
    return { error: auth.error };
  }

  // Path 2: shared machine secret via x-ep-auto-key header
  const autoKey = request.headers.get('x-ep-auto-key');
  const secret = getAutoSubmitSecret();

  if (!autoKey) {
    return {
      error: 'Authentication required. Provide Authorization: Bearer ep_live_... or a valid x-ep-auto-key header.',
    };
  }

  if (!secret) {
    // Server-side misconfiguration — EP_AUTO_SUBMIT_SECRET not set
    console.error('[auto-submit] EP_AUTO_SUBMIT_SECRET is not configured');
    return { error: 'Auto-submit authentication is not configured on this server' };
  }

  // Constant-time comparison to prevent timing attacks
  if (autoKey.length !== secret.length || !timingSafeEqual(autoKey, secret)) {
    return { error: 'Invalid x-ep-auto-key credential' };
  }

  // Machine credential authenticated — return a synthetic machine entity.
  // The canonical writer uses submitter.id for self-score checks and
  // dedup keys. The machine entity ID is a well-known sentinel that
  // cannot collide with real entity UUIDs.
  return {
    entity: {
      id: 'ep_machine_auto_submit',
      entity_id: 'ep_machine_auto_submit',
      status: 'active',
      emilia_score: 50,
    },
  };
}

/**
 * Constant-time string comparison (prevents timing side-channels).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  const { timingSafeEqual: tse } = require('crypto');
  return tse(Buffer.from(a), Buffer.from(b));
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

/**
 * POST /api/receipts/auto-submit
 *
 * Ingest a batch of auto-generated behavioral receipts.
 * This route is a thin transport adapter — all trust-bearing logic is
 * delegated to the canonical writer.
 *
 * @param {Request} request  Next.js request object.
 * @returns {Response}       JSON response with accepted/rejected counts.
 */
export async function POST(request) {
  try {
    // -----------------------------------------------------------------
    // Authenticate
    // -----------------------------------------------------------------
    const auth = await authenticateAutoSubmit(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    // -----------------------------------------------------------------
    // Parse body
    // -----------------------------------------------------------------
    let body;
    try {
      body = await request.json();
    } catch {
      return epProblem(400, 'bad_request', 'Invalid JSON body');
    }

    if (!body || !Array.isArray(body.receipts)) {
      return epProblem(400, 'bad_request', 'Body must be { receipts: [...] }');
    }

    if (body.receipts.length === 0) {
      return epProblem(400, 'bad_request', 'receipts array is empty');
    }

    if (body.receipts.length > BATCH_MAX) {
      return epProblem(400, 'batch_too_large', `Batch exceeds maximum of ${BATCH_MAX} receipts. Split into smaller batches.`);
    }

    // -----------------------------------------------------------------
    // Validate each receipt (input validation is route responsibility)
    // -----------------------------------------------------------------
    const validated = [];
    const validationErrors = [];

    for (let i = 0; i < body.receipts.length; i++) {
      const raw = body.receipts[i];

      // Type guard
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        validationErrors.push({ index: i, reason: 'Receipt must be a plain object' });
        continue;
      }

      // Required field check
      const missing = REQUIRED_FIELDS.filter(f => !raw[f] || typeof raw[f] !== 'string' || !raw[f].trim());
      if (missing.length > 0) {
        validationErrors.push({
          index: i,
          reason: `Missing required fields: ${missing.join(', ')}`,
          entity_id: raw.entity_id || null,
        });
        continue;
      }

      // Sanitize entity_id
      const entityId = String(raw.entity_id).trim();
      if (entityId.length > 200) {
        validationErrors.push({ index: i, reason: 'entity_id exceeds 200 characters', entity_id: entityId.slice(0, 50) });
        continue;
      }

      // transaction_ref length guard
      const txRef = String(raw.transaction_ref).trim();
      if (txRef.length > 500) {
        validationErrors.push({ index: i, reason: 'transaction_ref exceeds 500 characters', entity_id: entityId });
        continue;
      }

      // Sanitize context and outcome to plain objects
      const sanitizedReceipt = {
        ...raw,
        entity_id: entityId,
        transaction_ref: txRef,
        context: sanitizeJson(raw.context) || null,
        outcome: sanitizeJson(raw.outcome) || null,
      };

      // Compute a deterministic idempotency key so callers can safely retry
      const idempotency_key = computeIdempotencyKey(sanitizedReceipt);
      sanitizedReceipt.idempotency_key = idempotency_key;

      validated.push({
        index: i,
        idempotency_key,
        receipt: sanitizedReceipt,
      });
    }

    // -----------------------------------------------------------------
    // Delegate each validated receipt to the canonical writer
    // -----------------------------------------------------------------
    const receiptResults = [];
    const canonicalErrors = [];

    for (const { receipt, index, idempotency_key } of validated) {
      try {
        const result = await canonicalSubmitAutoReceipt(receipt, auth.entity);

        if (result.error) {
          canonicalErrors.push({
            index,
            reason: result.error,
            entity_id: receipt.entity_id,
            idempotency_key,
          });
          continue;
        }

        const rid = result.receipt?.receipt_id;
        if (rid) {
          receiptResults.push({
            receipt_id: rid,
            idempotency_key,
            deduplicated: !!result.deduplicated,
          });
        }
      } catch (err) {
        console.error('[auto-submit] Canonical write failed for receipt %d: %s', index, err.message);
        canonicalErrors.push({
          index,
          reason: 'Internal write error',
          entity_id: receipt.entity_id,
          idempotency_key,
        });
      }
    }

    // -----------------------------------------------------------------
    // Response
    // -----------------------------------------------------------------
    const allErrors = [...validationErrors, ...canonicalErrors];
    const totalAccepted = receiptResults.length;
    const totalRejected = allErrors.length;

    return NextResponse.json(
      {
        accepted: totalAccepted,
        rejected: totalRejected,
        receipt_ids: receiptResults.map(r => r.receipt_id),
        receipts: receiptResults,
        ...(validationErrors.length > 0 ? { validation_errors: validationErrors } : {}),
        ...(canonicalErrors.length > 0 ? { db_errors: canonicalErrors } : {}),
      },
      // 207 Multi-Status: some receipts may have been accepted while others were rejected.
      { status: totalAccepted > 0 ? 207 : 422 },
    );
  } catch (err) {
    console.error('[auto-submit] Unhandled error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute a deterministic idempotency key for a receipt.
 * This allows callers to safely retry failed bulk submissions without
 * creating duplicates. The key is derived from content-addressing fields
 * so identical receipts always produce the same key.
 *
 * @param {object} receipt - The validated receipt object
 * @returns {string} Hex-encoded SHA-256 hash
 */
function computeIdempotencyKey(receipt) {
  const parts = [
    receipt.entity_id || '',
    receipt.counterparty_id || receipt.counterparty_entity_id || '',
    receipt.transaction_type || receipt.interaction_type || '',
    receipt.transaction_ref || '',
  ].join('|');
  return crypto.createHash('sha256').update(parts).digest('hex');
}

/**
 * Safely serialize an unknown value to a plain object suitable for JSON storage.
 * Returns null for primitives, undefined, or values that cannot be serialized.
 *
 * @param {any} value
 * @returns {object|null}
 */
function sanitizeJson(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    // Round-trip through JSON to strip non-serializable values
    return JSON.parse(JSON.stringify(value));
  } catch {
    return null;
  }
}
