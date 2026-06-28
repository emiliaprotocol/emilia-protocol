import { NextResponse } from 'next/server';
import { authenticateRequest, generateApiKey, getServiceClient } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * POST /api/keys/rotate
 *
 * Rotates the caller's API key. The old key is revoked immediately
 * and a new key is issued. The entity's identity, score, and history
 * are preserved — only the credential changes.
 *
 * Auth: Bearer ep_live_... (current key)
 * Returns: { new_key, rotated_at, old_key_invalidated, manual_cleanup_required? }
 *
 * The new key is shown ONCE. Store it securely.
 */
export async function POST(request) {
  try {
    // ── Authenticate with current key ────────────────────────────────
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(auth.status, auth.code, auth.error);
    }

    const { entity } = auth;

    // ── Derive old key hash from the request header ──────────────────
    const apiKey = request.headers.get('authorization').replace('Bearer ', '');
    const { hashApiKey } = await import('@/lib/supabase');
    const oldKeyHash = hashApiKey(apiKey);

    // ── Generate new key ─────────────────────────────────────────────
    const { key: newKey, hash: newKeyHash, prefix } = generateApiKey();

    const serviceClient = getServiceClient();
    const now = new Date().toISOString();

    // Order matters (T2): create the NEW key and repoint the entity to it BEFORE
    // revoking the old one, so there is never a window where the entity has zero
    // valid keys (which would 401 every in-flight request — an auth blackout).
    // If a later step fails, the old key is still valid, so the worst case is two
    // valid keys briefly (a soft, safe failure), never an outage.

    // ── 1. Insert new key record ─────────────────────────────────────
    const { error: insertError } = await serviceClient
      .from('api_keys')
      .insert({
        entity_id: entity.id,
        key_hash: newKeyHash,
        key_prefix: prefix,
        label: 'Rotated key',
      });

    if (insertError) {
      logger.error('[key-rotation] Failed to insert new key:', insertError);
      return epProblem(500, 'rotation_failed', 'Failed to create new key');
    }

    // ── 2. Repoint entity to the new hash (new key now fully live) ────
    const { error: entityUpdateError } = await serviceClient
      .from('entities')
      .update({ api_key_hash: newKeyHash })
      .eq('id', entity.id);

    if (entityUpdateError) {
      logger.error('[key-rotation] Failed to update entity key hash:', entityUpdateError);
      // New key exists but entity still points at the old (still-valid) key — no
      // outage. Abort without revoking the old key so the caller stays authable.
      return epProblem(500, 'rotation_failed', 'Failed to update entity key reference');
    }

    // ── 3. Revoke the old key LAST (new key is already live) ─────────
    const { error: revokeError } = await serviceClient
      .from('api_keys')
      .update({ revoked_at: now, invalidated_at: now })
      .eq('key_hash', oldKeyHash)
      .eq('entity_id', entity.id);

    const oldKeyInvalidated = !revokeError;
    if (revokeError) {
      // New key is live; the old key just wasn't revoked. Log loudly but do NOT
      // fail the rotation — the caller already has a working new key.
      logger.error('[key-rotation] New key live but old key not revoked (manual cleanup needed):', revokeError);
    }

    return NextResponse.json({
      new_key: newKey,
      rotated_at: now,
      old_key_invalidated: oldKeyInvalidated,
      manual_cleanup_required: !oldKeyInvalidated,
    }, { status: 201 });
  } catch (err) {
    logger.error('[key-rotation] Unexpected error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
