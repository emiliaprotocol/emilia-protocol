import { NextResponse } from 'next/server';
import { authenticateRequest, generateApiKey, hashApiKey } from '@/lib/supabase';
import { authEntityDbId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { hasApiPermission } from '@/lib/auth-permissions.js';
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
    if (!hasApiPermission(auth, 'keys.rotate')) {
      return epProblem(403, 'insufficient_permissions', 'Key rotation requires keys.rotate or admin permission');
    }

    // ── Derive old key hash from the request header ──────────────────
    const apiKey = request.headers.get('authorization').replace('Bearer ', '');
    const oldKeyHash = hashApiKey(apiKey);

    // ── Generate new key ─────────────────────────────────────────────
    const { key: newKey, hash: newKeyHash, prefix } = generateApiKey();

    const guardedClient = getGuardedClient();
    const { data, error: rotateError } = await guardedClient.rpc('rotate_api_key_atomic', {
      p_entity_id: authEntityDbId(auth),
      p_old_key_hash: oldKeyHash,
      p_new_key_hash: newKeyHash,
      p_new_key_prefix: prefix,
      p_label: 'Rotated key',
    });

    if (rotateError || data?.error) {
      logger.error('[key-rotation] Atomic rotation failed:', rotateError || data);
      return epProblem(500, 'rotation_failed', 'Failed to rotate key');
    }

    const rotatedAt = data?.rotated_at || new Date().toISOString();

    return NextResponse.json({
      new_key: newKey,
      rotated_at: rotatedAt,
      old_key_invalidated: true,
      manual_cleanup_required: false,
    }, { status: 201 });
  } catch (err) {
    logger.error('[key-rotation] Unexpected error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
