import { NextResponse } from 'next/server';
import { authenticateRequest, generateApiKey, getServiceClient } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
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
 * Returns: { new_key, rotated_at, old_key_invalidated: true }
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

    // ── Revoke old key (sets revoked_at so RPC rejects it) ───────────
    const { error: revokeError } = await serviceClient
      .from('api_keys')
      .update({ revoked_at: now, invalidated_at: now })
      .eq('key_hash', oldKeyHash)
      .eq('entity_id', entity.id);

    if (revokeError) {
      logger.error('[key-rotation] Failed to revoke old key:', revokeError);
      return epProblem(500, 'rotation_failed', 'Failed to revoke old key');
    }

    // ── Insert new key record ────────────────────────────────────────
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

    // ── Update entity's api_key_hash to the new hash ─────────────────
    const { error: entityUpdateError } = await serviceClient
      .from('entities')
      .update({ api_key_hash: newKeyHash })
      .eq('id', entity.id);

    if (entityUpdateError) {
      logger.error('[key-rotation] Failed to update entity key hash:', entityUpdateError);
      return epProblem(500, 'rotation_failed', 'Failed to update entity key reference');
    }

    return NextResponse.json({
      new_key: newKey,
      rotated_at: now,
      old_key_invalidated: true,
    }, { status: 201 });
  } catch (err) {
    logger.error('[key-rotation] Unexpected error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
