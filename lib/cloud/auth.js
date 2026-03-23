/**
 * Cloud Control Plane — Authentication Middleware
 *
 * Authenticates incoming requests against the tenant_api_keys table.
 * Extracts the API key from `Authorization: Bearer ep_...` (or `ept_...`),
 * hashes it, and looks up the active (non-revoked, non-expired) record.
 *
 * Uses getGuardedClient() so the lookup is read-only and cannot
 * accidentally mutate trust-bearing tables.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getGuardedClient } from '@/lib/write-guard';

/**
 * Authenticate a cloud control plane request.
 *
 * @param {Request} request - The incoming HTTP request
 * @returns {Promise<{ tenantId: string, environment: string, permissions: string[] } | null>}
 *   Returns the auth context on success, or null on failure.
 */
export async function authenticateCloudRequest(request) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader) return null;

    // Accept both ep_ and ept_ prefixed keys
    const bearerMatch = authHeader.match(/^Bearer\s+(e?pt?_\S+)$/i);
    if (!bearerMatch) return null;

    const rawKey = bearerMatch[1];
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const supabase = getGuardedClient();

    const { data: keyRow, error } = await supabase
      .from('tenant_api_keys')
      .select('key_id, tenant_id, environment, permissions, expires_at, revoked_at')
      .eq('key_hash', keyHash)
      .is('revoked_at', null)
      .maybeSingle();

    if (error) {
      console.error('[cloud/auth] Key lookup error:', error.message);
      return null;
    }

    if (!keyRow) return null;

    // Check expiry
    if (keyRow.expires_at && new Date(keyRow.expires_at) <= new Date()) {
      return null;
    }

    // Verify the tenant is active
    const { data: tenant, error: tenantErr } = await supabase
      .from('tenants')
      .select('tenant_id, status')
      .eq('tenant_id', keyRow.tenant_id)
      .maybeSingle();

    if (tenantErr || !tenant || tenant.status !== 'active') {
      return null;
    }

    // Normalize permissions — the column may be an array or null.
    // Default to empty (no permissions) for safety; explicit grants required.
    const permissions = Array.isArray(keyRow.permissions) ? keyRow.permissions : [];

    return {
      tenantId: keyRow.tenant_id,
      environment: keyRow.environment,
      permissions,
      keyId: keyRow.key_id,
    };
  } catch (err) {
    console.error('[cloud/auth] Unexpected error during authentication:', err.message);
    return null;
  }
}
