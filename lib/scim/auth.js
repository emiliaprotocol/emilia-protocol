/**
 * SCIM provisioning-token authentication.
 *
 * An IdP (Okta, Azure AD, Ping) authenticates to EP's SCIM endpoints with a
 * long-lived bearer token EP issued for one tenant. Tokens carry the prefix
 * `ep_scim_` so they are never confused with EP API keys (`ep_live_`), and are
 * stored only as SHA-256 hashes.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';

export const SCIM_TOKEN_PREFIX = 'ep_scim_';

export function generateScimToken() {
  return `${SCIM_TOKEN_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
}

export function hashScimToken(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Resolve the SCIM bearer token on a request to its tenant.
 *
 * @returns {Promise<{ tenantId: string, tokenId: string } | { error: string, status: number }>}
 */
export async function authenticateScim(request) {
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Bearer ')) {
    return { error: 'Missing bearer token', status: 401 };
  }
  const token = header.slice('Bearer '.length).trim();
  if (!token.startsWith(SCIM_TOKEN_PREFIX)) {
    return { error: 'Invalid SCIM token', status: 401 };
  }

  const tokenHash = hashScimToken(token);
  let supabase;
  try {
    supabase = getGuardedClient();
  } catch (err) {
    logger.error('[scim/auth] client init failed:', err);
    return { error: 'Authentication service unavailable', status: 503 };
  }

  const { data, error } = await supabase
    .from('scim_provisioning_tokens')
    .select('id, tenant_id, organization_id, revoked_at')
    .eq('token_hash', tokenHash)
    .is('revoked_at', null)
    .maybeSingle();

  if (error) {
    logger.error('[scim/auth] token lookup failed:', error);
    return { error: 'Authentication service unavailable', status: 503 };
  }
  if (!data) {
    return { error: 'Invalid SCIM token', status: 401 };
  }

  // Best-effort last-used stamp; never blocks the request.
  supabase
    .from('scim_provisioning_tokens')
    .update({ last_used_at: new Date().toISOString() })
    .eq('id', data.id)
    .then(() => {}, () => {});

  // organizationId is the protocol org this SCIM tenant provisions into; it
  // scopes credential revocation. Falls back to tenant_id when unset (#6).
  return {
    tenantId: data.tenant_id,
    organizationId: data.organization_id || data.tenant_id,
    tokenId: data.id,
  };
}
