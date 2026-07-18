// @license Apache-2.0
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { getSupabaseConfig } from '@/lib/env';
import { sha256 } from '@/lib/crypto';
import { siemEvent } from './siem.js';
import { logger } from './logger.js';

let _serviceClient = null;

export function getServiceClient() {
  if (!_serviceClient) {
    const { url, serviceRoleKey } = getSupabaseConfig();
    if (!url || !serviceRoleKey) {
      throw new Error('Missing Supabase environment variables');
    }
    _serviceClient = createClient(url, serviceRoleKey);
  }
  return _serviceClient;
}

export function generateApiKey() {
  const key = `ep_live_${crypto.randomBytes(32).toString('hex')}`;
  const hash = sha256(key);
  return { key, hash, prefix: key.slice(0, 16) };
}

export function hashApiKey(key) {
  return sha256(key);
}

/**
 * The stable string identity of an authenticated actor.
 *
 * authenticateRequest returns the FULL entity row as auth.entity (older
 * surfaces like createReceipt use its fields). The v1 guard family used the
 * bare object where a string id belonged — which (a) stored the serialized
 * row (api_key_hash and all) into actor/initiator columns, and (b) made the
 * separation-of-duties comparison `auth.entity === initiatorId` an
 * object-vs-string check that could NEVER fire, silently allowing
 * self-approval on the bearer path. Every v1 caller now derives identity
 * through this helper; string-mocked tests keep working via the fallback.
 */
export function authEntityId(auth) {
  const e = auth?.entity;
  if (typeof e === 'string') return e;
  return e?.entity_id || e?.id || '';
}

/**
 * Resolve the database primary key for an authenticated entity.
 *
 * Route handlers must not pass the full auth row through write commands. This
 * helper keeps database foreign-key inputs explicit while retaining support for
 * string-shaped test/auth adapters.
 */
export function authEntityDbId(auth) {
  const e = auth?.entity;
  if (typeof e === 'string') return e;
  return e?.id || e?.entity_id || '';
}

/**
 * Return the minimum actor shape required by canonical writers.
 *
 * The authenticated entity row may grow fields over time; forwarding it as an
 * actor couples route boundaries to that row and can leak unrelated context.
 * Canonical dispute writes only need the database id and stable entity ref.
 */
export function authEntityActor(auth) {
  const e = auth?.entity;
  if (!e) return null;
  if (typeof e === 'string') return { id: e, entity_id: e };

  const id = e.id || e.entity_id || '';
  const entity_id = e.entity_id || e.id || '';
  return { id, entity_id };
}

export async function authenticateRequest(request) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ep_')) {
    return {
      error: 'Missing or invalid API key. Use: Authorization: Bearer ep_live_...',
      code: 'missing_key',
      status: 401,
    };
  }

  const apiKey = authHeader.replace('Bearer ', '');
  const keyHash = hashApiKey(apiKey);

  let supabase;
  try {
    supabase = getServiceClient();
  } catch (err) {
    logger.error('[auth] Failed to initialize Supabase client:', err);
    return {
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    };
  }

  // Single-roundtrip auth: api_keys lookup + last_used_at update + entity fetch
  // via resolve_authenticated_actor RPC (replaces 3 serial REST calls).
  const { data: authResult, error: rpcError } = await supabase.rpc('resolve_authenticated_actor', {
    p_key_hash: keyHash,
  });

  if (rpcError) {
    logger.error('[auth] RPC error:', rpcError.message);
    return {
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    };
  }

  if (!authResult || authResult.error) {
    const reason = authResult?.reason || 'unknown';
    const code = authResult?.error || 'auth_failed';
    logger.warn(`[auth] Auth failed: ${code} (${reason}), hash prefix ${keyHash.slice(0, 8)}`);

    // SIEM: unauthorized access attempts are high-severity security events
    siemEvent('UNAUTHORIZED_ACCESS_ATTEMPT', {
      code,
      reason,
      key_hash_prefix: keyHash.slice(0, 8),
    });

    if (code === 'malformed_key_record') {
      return { error: 'Internal error during authentication', code, status: 500 };
    }
    return { error: 'Authentication failed', code, status: 401 };
  }

  return { entity: authResult.entity, permissions: authResult.permissions };
}
