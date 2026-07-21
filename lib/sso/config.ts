/**
 * SSO connection storage — load/upsert per-tenant SAML/OIDC config.
 *
 * @license Apache-2.0
 */

import { getGuardedClient } from '@/lib/write-guard';
import { open as openSecret } from '@/lib/crypto/secret-box';

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

/** The SP entityID / OIDC redirect base for this deployment. */
export function spOrigin(request: Request): string {
  try {
    const u = new URL(request.url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return 'https://www.emiliaprotocol.ai';
  }
}
