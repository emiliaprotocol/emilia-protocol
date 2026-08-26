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

export function generateScimToken(): string {
  return `${SCIM_TOKEN_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
}

export function hashScimToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

export interface ScimAuthSuccess {
  tenantId: string;
  organizationId: string;
  tokenId: string;
}

export interface ScimAuthFailure {
  error: string;
  status: number;
}

export type ScimAuthResult = ScimAuthSuccess | ScimAuthFailure;

/**
 * Resolve the SCIM bearer token on a request to its tenant.
 */
export async function authenticateScim(request: Request): Promise<ScimAuthResult> {
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

  // A token proves possession of a provisioned secret, but its tenant/org
  // provenance can become stale if the tenant is disabled or rebound. Re-check
  // that immutable relationship on every use. Public registrations receive an
  // @org: identifier outside the registrable entity-id alphabet, so a caller
  // cannot squat this server-owned namespace.
  const { data: tenant, error: tenantError } = await supabase
    .from('entities')
    .select('entity_id, organization_id, status')
    .eq('entity_id', data.tenant_id)
    .maybeSingle();
  // organization_id is the only authority-bearing provenance. tenant_id is an
  // entity label and may be attacker-selected, so a legacy NULL organization
  // must be reissued after migration rather than silently promoted to an org.
  const organizationId = typeof data.organization_id === 'string' && data.organization_id.length > 0
    ? data.organization_id
    : null;
  if (tenantError) {
    logger.error('[scim/auth] organization verification lookup failed:', tenantError);
    return { error: 'Authentication service unavailable', status: 503 };
  }
  if (!organizationId
      || !tenant
      || tenant.status !== 'active'
      || organizationId === data.tenant_id
      || tenant.organization_id !== organizationId) {
    return { error: 'SCIM token tenant binding is no longer valid', status: 403 };
  }

  // Best-effort last-used stamp; never blocks the request.
  supabase
    .from('scim_provisioning_tokens')
    .update({ last_used_at: new Date().toISOString() })
    .eq('id', data.id)
    .then(() => {}, () => {});

  // organizationId is the exact protocol org this SCIM tenant provisions into;
  // it scopes directory lookup and credential revocation.
  return {
    tenantId: data.tenant_id,
    organizationId,
    tokenId: data.id,
  };
}
