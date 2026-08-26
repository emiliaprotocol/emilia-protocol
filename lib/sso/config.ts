/**
 * SSO connection storage — load/upsert per-tenant SAML/OIDC config.
 *
 * @license Apache-2.0
 */

import { getGuardedClient } from '@/lib/write-guard';
import { open as openSecret } from '@/lib/crypto/secret-box';
import { getSsoOriginConfig } from '@/lib/env';

export async function loadConnection(tenantId: string, protocol: string): Promise<{ connection?: any; error?: any }> {
  const supabase = getGuardedClient();
  const { data, error } = await supabase
    .from('sso_connections')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('protocol', protocol)
    .eq('enabled', true)
    .maybeSingle();
  if (error) return { error };
  if (data?.oidc_client_secret) {
    // Sealed at rest; pre-encryption plaintext rows pass through unchanged.
    data.oidc_client_secret = openSecret(data.oidc_client_secret);
  }
  return { connection: data };
}

export async function upsertConnection(tenantId: string, protocol: string, fields: Record<string, unknown>): Promise<{ connection?: any; error?: any }> {
  const supabase = getGuardedClient();
  const { data, error } = await supabase
    .from('sso_connections')
    .upsert(
      { tenant_id: tenantId, protocol, ...fields, updated_at: new Date().toISOString() },
      { onConflict: 'tenant_id,protocol' },
    )
    .select('id, tenant_id, protocol, enabled, created_at, updated_at')
    .single();
  if (error) return { error };
  return { connection: data };
}

export async function listConnections(tenantId: string): Promise<{ connections?: any[]; error?: any }> {
  const supabase = getGuardedClient();
  const { data, error } = await supabase
    .from('sso_connections')
    .select('id, protocol, enabled, saml_idp_entry_point, oidc_issuer, oidc_client_id, created_at, updated_at')
    .eq('tenant_id', tenantId);
  if (error) return { error };
  return { connections: data || [] };
}

const DEVELOPMENT_SSO_ORIGIN = 'http://localhost:3000';

function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost'
    || hostname === '127.0.0.1'
    || hostname === '[::1]';
}

/**
 * The canonical SP entityID / OIDC redirect base for this deployment.
 *
 * This is deliberately server-configured. Request Host/Forwarded headers are
 * untrusted routing metadata and must never choose an identity-provider return
 * target. Production refuses to construct SSO URLs when the deployment origin
 * is absent or unsafe; development and tests use one stable loopback origin so
 * their behavior is deterministic without trusting the request.
 */
export function spOrigin(_request?: Request): string {
  const { origin: configured, isProduction } = getSsoOriginConfig();

  if (!configured) {
    if (isProduction) {
      throw new Error('SSO service origin is not configured');
    }
    return DEVELOPMENT_SSO_ORIGIN;
  }

  let url: URL;
  try {
    url = new URL(configured);
  } catch {
    throw new Error('SSO service origin must be an absolute URL');
  }

  const originOnly = url.pathname === '/'
    && !url.username
    && !url.password
    && !url.search
    && !url.hash;
  const developmentLoopback = !isProduction
    && url.protocol === 'http:'
    && isLoopbackHostname(url.hostname);
  if (!originOnly || (url.protocol !== 'https:' && !developmentLoopback)) {
    throw new Error('SSO service origin must be an HTTPS origin (HTTP loopback is allowed outside production)');
  }

  return url.origin;
}
