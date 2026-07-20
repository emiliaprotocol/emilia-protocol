/**
 * SSO connection storage — load/upsert per-tenant SAML/OIDC config.
 *
 * @license Apache-2.0
 */

import { getGuardedClient } from '@/lib/write-guard';
import { open as openSecret } from '@/lib/crypto/secret-box';

/**
 * @param {string} tenantId
 * @param {string} protocol
 */
export async function loadConnection(tenantId, protocol) {
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

/**
 * @param {string} tenantId
 * @param {string} protocol
 * @param {object} fields - protocol-specific connection fields to persist (e.g.
 *   saml_idp_entry_point/saml_idp_cert/saml_audience/enabled, or
 *   oidc_issuer/oidc_client_id/oidc_client_secret/oidc_redirect_uri/enabled)
 */
export async function upsertConnection(tenantId, protocol, fields) {
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

/** @param {string} tenantId */
export async function listConnections(tenantId) {
  const supabase = getGuardedClient();
  const { data, error } = await supabase
    .from('sso_connections')
    .select('id, protocol, enabled, saml_idp_entry_point, oidc_issuer, oidc_client_id, created_at, updated_at')
    .eq('tenant_id', tenantId);
  if (error) return { error };
  return { connections: data || [] };
}

/**
 * The SP entityID / OIDC redirect base for this deployment.
 * @param {Request} request
 */
export function spOrigin(request) {
  try {
    const u = new URL(request.url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return 'https://www.emiliaprotocol.ai';
  }
}
