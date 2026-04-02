// @license Apache-2.0
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

  // Single-roundtrip auth: api_keys lookup + last_used_at update + entity fetch
  // via resolve_authenticated_actor RPC (replaces 3 serial REST calls).
  const { data: authResult, error: rpcError } = await supabase.rpc('resolve_authenticated_actor', {
    p_key_hash: keyHash,
  });

  if (rpcError) {
    console.error('[auth] RPC error:', rpcError.message);
    return {
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    };
  }

  if (!authResult || authResult.error) {
    const reason = authResult?.reason || 'unknown';
    const code = authResult?.error || 'auth_failed';
    console.warn(`[auth] Auth failed: ${code} (${reason}), hash prefix ${keyHash.slice(0, 8)}`);

    if (code === 'malformed_key_record') {
      return { error: 'Internal error during authentication', code, status: 500 };
    }
    return { error: 'Authentication failed', code, status: 401 };
  }

  return { entity: authResult.entity, permissions: authResult.permissions };
}
