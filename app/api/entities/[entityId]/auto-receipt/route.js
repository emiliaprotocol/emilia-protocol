// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — /api/entities/[entityId]/auto-receipt
//
// GET  /api/entities/:entityId/auto-receipt
//   → Returns the current auto-receipt config for the entity.
//   → Requires a valid API key that belongs to the requested entity.
//
// POST /api/entities/:entityId/auto-receipt
//   → Updates the auto-receipt config for the entity.
//   → Body: { enabled: boolean, redact_fields?: string[], privacy_mode?: 'standard'|'anonymous' }
//   → Requires a valid API key that belongs to the requested entity.
//
// Auth model:
//   Every request must carry a Bearer API key. The key is resolved to an
//   entity and compared against the path parameter — an entity may only read
//   or update its own config. This prevents cross-entity config pollution.

import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getAutoReceiptConfig, setAutoReceiptConfig } from '@/lib/auto-receipt-config';
import { EP_ERRORS } from '@/lib/errors';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';

// ---------------------------------------------------------------------------
// GET — retrieve current config
// ---------------------------------------------------------------------------

/**
 * GET /api/entities/[entityId]/auto-receipt
 *
 * Returns the auto-receipt configuration for the specified entity.
 * The caller must authenticate as that entity (their API key's entity_id
 * must match the path parameter).
 *
 * @param {import('next/server').NextRequest} request
 * @param {{ params: { entityId: string } }} ctx
 * @returns {Promise<NextResponse>}
 */
export async function GET(request, { params }) {
  try {
    const { entityId } = await params;

    // Rate limit — reads are cheaper but still gated
    const ip = getClientIP(request);
    const rl = await checkRateLimit(ip, 'read');
    if (!rl.allowed) {
      return EP_ERRORS.RATE_LIMITED();
    }

    // Authenticate
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    // Entity-scoped access: callers may only access their own config
    if (auth.entity.entity_id !== entityId) {
      return EP_ERRORS.FORBIDDEN('You may only read your own auto-receipt configuration.');
    }

    const config = await getAutoReceiptConfig(entityId);

    return NextResponse.json({
      entity_id: entityId,
      ...config,
    });
  } catch (err) {
    console.error('[auto-receipt GET] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

// ---------------------------------------------------------------------------
// POST — update config
// ---------------------------------------------------------------------------

/**
 * POST /api/entities/[entityId]/auto-receipt
 *
 * Updates the auto-receipt configuration for the specified entity.
 *
 * Request body:
 * ```json
 * {
 *   "enabled": true,
 *   "redact_fields": ["my_internal_id", "billing_ref"],
 *   "privacy_mode": "anonymous"
 * }
 * ```
 *
 * `enabled` is required. `redact_fields` and `privacy_mode` are optional
 * and default to `[]` and `"standard"` respectively.
 *
 * @param {import('next/server').NextRequest} request
 * @param {{ params: { entityId: string } }} ctx
 * @returns {Promise<NextResponse>}
 */
export async function POST(request, { params }) {
  try {
    const { entityId } = await params;

    // Rate limit — writes
    const ip = getClientIP(request);
    const rl = await checkRateLimit(ip, 'write');
    if (!rl.allowed) {
      return EP_ERRORS.RATE_LIMITED();
    }

    // Authenticate
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    // Entity-scoped access: callers may only update their own config
    if (auth.entity.entity_id !== entityId) {
      return EP_ERRORS.FORBIDDEN('You may only update your own auto-receipt configuration.');
    }

    // Parse body
    const body = await request.json().catch(() => ({}));
    const { enabled, redact_fields, privacy_mode } = body;

    // Validate required field
    if (typeof enabled !== 'boolean') {
      return EP_ERRORS.BAD_REQUEST('"enabled" is required and must be a boolean.');
    }

    // Validate optional fields
    if (redact_fields !== undefined) {
      if (!Array.isArray(redact_fields) || redact_fields.some(f => typeof f !== 'string')) {
        return EP_ERRORS.BAD_REQUEST('"redact_fields" must be an array of strings.');
      }
    }

    if (privacy_mode !== undefined && privacy_mode !== 'standard' && privacy_mode !== 'anonymous') {
      return EP_ERRORS.BAD_REQUEST('"privacy_mode" must be "standard" or "anonymous".');
    }

    const updated = await setAutoReceiptConfig(entityId, {
      enabled,
      redact_fields: redact_fields ?? [],
      privacy_mode: privacy_mode ?? 'standard',
    });

    return NextResponse.json(
      { entity_id: entityId, ...updated },
      { status: 200 },
    );
  } catch (err) {
    console.error('[auto-receipt POST] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
