/**
 * POST /api/receipts/auto-submit
 *
 * Lightweight, high-throughput endpoint for ingesting auto-generated behavioral receipts
 * from the EMILIA Protocol MCP server's AutoReceiptMiddleware.
 *
 * Design rationale:
 *   - No bearer-token authentication. Entity identity comes from the receipt body.
 *     Rate-limiting is enforced per entity_id to prevent abuse.
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
 * Rate limiting:
 *   Enforced via the X-EP-Auto-Key header. The key is tied to an entity; EP
 *   infra (edge middleware or Supabase RLS) handles per-entity rate caps.
 *   This route does NOT authenticate the key — it only uses it for attribution.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum receipts accepted per request. */
const BATCH_MAX = 100;

/** Required top-level fields on every auto-receipt. */
const REQUIRED_FIELDS = ['entity_id', 'transaction_ref'];

/** Fields that are always forced regardless of what the sender provides. */
const FORCED_VALUES = {
  auto_generated: true,
  provenance: 'unilateral',
  // Bilateral status cannot be claimed unilaterally.
  bilateral_status: null,
};

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

/**
 * POST /api/receipts/auto-submit
 *
 * Ingest a batch of auto-generated behavioral receipts.
 *
 * @param {Request} request  Next.js request object.
 * @returns {Response}       JSON response with accepted/rejected counts.
 */
export async function POST(request) {
  try {
    // -----------------------------------------------------------------------
    // Parse body
    // -----------------------------------------------------------------------
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON body', code: 'BAD_REQUEST', status: 400 },
        { status: 400 },
      );
    }

    if (!body || !Array.isArray(body.receipts)) {
      return NextResponse.json(
        { error: 'Body must be { receipts: [...] }', code: 'BAD_REQUEST', status: 400 },
        { status: 400 },
      );
    }

    if (body.receipts.length === 0) {
      return NextResponse.json(
        { error: 'receipts array is empty', code: 'BAD_REQUEST', status: 400 },
        { status: 400 },
      );
    }

    if (body.receipts.length > BATCH_MAX) {
      return NextResponse.json(
        {
          error: `Batch exceeds maximum of ${BATCH_MAX} receipts. Split into smaller batches.`,
          code: 'BAD_REQUEST',
          status: 400,
        },
        { status: 400 },
      );
    }

    // -----------------------------------------------------------------------
    // Extract attribution key for rate limiting (informational only here —
    // actual rate enforcement lives in edge middleware or Supabase policies).
    // -----------------------------------------------------------------------
    const autoKey = request.headers.get('x-ep-auto-key') || null;

    // -----------------------------------------------------------------------
    // Validate and prepare each receipt
    // -----------------------------------------------------------------------
    const now = new Date().toISOString();
    const accepted = [];
    const errors = [];

    for (let i = 0; i < body.receipts.length; i++) {
      const raw = body.receipts[i];

      // Type guard
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        errors.push({ index: i, reason: 'Receipt must be a plain object' });
        continue;
      }

      // Required field check
      const missing = REQUIRED_FIELDS.filter(f => !raw[f] || typeof raw[f] !== 'string' || !raw[f].trim());
      if (missing.length > 0) {
        errors.push({
          index: i,
          reason: `Missing required fields: ${missing.join(', ')}`,
          entity_id: raw.entity_id || null,
        });
        continue;
      }

      // Sanitize entity_id — must be a non-empty slug-safe string
      const entityId = String(raw.entity_id).trim();
      if (entityId.length > 200) {
        errors.push({ index: i, reason: 'entity_id exceeds 200 characters', entity_id: entityId.slice(0, 50) });
        continue;
      }

      // transaction_ref length guard
      const txRef = String(raw.transaction_ref).trim();
      if (txRef.length > 500) {
        errors.push({ index: i, reason: 'transaction_ref exceeds 500 characters', entity_id: entityId });
        continue;
      }

      // Build the normalized receipt row
      const receiptId = `ep_rcpt_${crypto.randomBytes(16).toString('hex')}`;

      /** @type {object} */
      const row = {
        receipt_id: receiptId,
        entity_id: entityId,
        transaction_ref: txRef,

        // Context — optional structured metadata from the MCP tool call
        context: sanitizeJson(raw.context) || null,

        // Outcome — observable signals from the tool invocation
        outcome: sanitizeJson(raw.outcome) || null,

        // Forced immutable values
        ...FORCED_VALUES,

        // Source attribution (informational)
        auto_key_prefix: autoKey ? autoKey.slice(0, 16) : null,

        // Timestamps
        created_at: now,
        updated_at: now,

        // Provenance tier: always self_attested for auto-generated receipts
        provenance_tier: 'self_attested',

        // Agent behavior extracted from outcome if available
        agent_behavior: raw.outcome?.completed === true
          ? 'completed'
          : raw.outcome?.error_occurred === true
            ? 'abandoned'
            : null,

        // graph_weight starts at 1.0; disputes can zero it out via canonical writer
        graph_weight: 1.0,
      };

      accepted.push({ row, index: i });
    }

    // -----------------------------------------------------------------------
    // Write accepted receipts to Supabase
    // -----------------------------------------------------------------------
    const receiptIds = [];
    const dbErrors = [];

    if (accepted.length > 0) {
      const supabase = getServiceClient();
      const rows = accepted.map(({ row }) => row);

      const { data: inserted, error: insertError } = await supabase
        .from('receipts')
        .insert(rows)
        .select('receipt_id');

      if (insertError) {
        // If the bulk insert fails entirely, surface it but don't 500 —
        // return partial results so the caller can retry.
        console.error('[auto-submit] Bulk insert error:', insertError.message);
        dbErrors.push({
          reason: `Database write failed: ${insertError.message}`,
          affected_count: accepted.length,
        });
      } else {
        for (const r of inserted || []) {
          receiptIds.push(r.receipt_id);
        }
      }
    }

    // -----------------------------------------------------------------------
    // Response
    // -----------------------------------------------------------------------
    const totalAccepted = receiptIds.length;
    const totalRejected = errors.length + dbErrors.length;

    return NextResponse.json(
      {
        accepted: totalAccepted,
        rejected: totalRejected,
        receipt_ids: receiptIds,
        ...(errors.length > 0 ? { validation_errors: errors } : {}),
        ...(dbErrors.length > 0 ? { db_errors: dbErrors } : {}),
      },
      // 207 Multi-Status: some receipts may have been accepted while others were rejected.
      { status: totalAccepted > 0 ? 207 : 422 },
    );
  } catch (err) {
    console.error('[auto-submit] Unhandled error:', err);
    return NextResponse.json(
      { error: 'Internal server error', code: 'INTERNAL_ERROR', status: 500 },
      { status: 500 },
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    // Round-trip through JSON to strip non-serializable values (functions, Dates become strings, etc.)
    return JSON.parse(JSON.stringify(value));
  } catch {
    return null;
  }
}
