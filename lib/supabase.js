import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { getSupabaseConfig } from '@/lib/env';
import { sha256 } from '@/lib/crypto';

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
    console.error('[auth] Failed to initialize Supabase client:', err);
    return {
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    };
  }

  // Look up ALL matching rows (not .single()) so we can distinguish
  // not-found vs revoked vs duplicate-key scenarios.
  const { data: allRows, error: dbError } = await supabase
    .from('api_keys')
    .select('entity_id, permissions, revoked_at')
    .eq('key_hash', keyHash);

  // Database-level failure — do NOT masquerade as "invalid key"
  if (dbError) {
    console.error('[auth] Database error during API key lookup:', dbError);
    return {
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    };
  }

  // No rows at all — the key simply does not exist
  if (!allRows || allRows.length === 0) {
    console.warn('[auth] API key not found for hash prefix', keyHash.slice(0, 8));
    return {
      error: 'Authentication failed',
      code: 'auth_failed',
      status: 401,
    };
  }

  // Separate active vs revoked rows
  const activeRows = allRows.filter(r => r.revoked_at === null || r.revoked_at === undefined);
  const revokedRows = allRows.filter(r => r.revoked_at !== null && r.revoked_at !== undefined);

  // All records for this hash are revoked
  if (activeRows.length === 0 && revokedRows.length > 0) {
    console.warn('[auth] Revoked API key used, hash prefix', keyHash.slice(0, 8));
    return {
      error: 'Authentication failed',
      code: 'auth_failed',
      status: 401,
    };
  }

  // Duplicate active records — warn and use the first one
  if (activeRows.length > 1) {
    console.warn(
      `[auth] Duplicate active API key records found for hash prefix ${keyHash.slice(0, 8)}… — using first record`,
    );
  }

  const keyRecord = activeRows[0];

  // Validate that the row has the required fields
  if (!keyRecord.entity_id || typeof keyRecord.entity_id !== 'string') {
    console.error('[auth] Malformed API key record: missing or invalid entity_id', {
      hashPrefix: keyHash.slice(0, 8),
    });
    return {
      error: 'Internal error during authentication',
      code: 'malformed_key_record',
      status: 500,
    };
  }

  await supabase
    .from('api_keys')
    .update({ last_used_at: new Date().toISOString() })
    .eq('key_hash', keyHash);

  const { data: entity, error: entityError } = await supabase
    .from('entities')
    .select('*')
    .eq('id', keyRecord.entity_id)
    .maybeSingle();

  if (entityError) {
    console.error('[auth] Database error during entity lookup:', entityError);
    return {
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    };
  }

  if (!entity || entity.status !== 'active') {
    console.warn('[auth] Entity inactive or not found for key hash prefix', keyHash.slice(0, 8));
    return { error: 'Authentication failed', code: 'auth_failed', status: 401 };
  }

  return { entity, permissions: keyRecord.permissions };
}
