/**
 * Tenant Manager — Core library for multi-tenant operations
 *
 * All tenant CRUD, membership, environment, and API key operations
 * are centralized here. Route handlers delegate to these functions.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { logger } from '../logger.js';

// ── Tenant CRUD ──────────────────────────────────────────────────────────────

/**
 * Create a new tenant with a default production environment.
 * The creating user is added as the owner.
 */
export async function createTenant({ name, slug, plan = 'free', settings = {}, userRef }) {
  const supabase = getServiceClient();

  // Create the tenant
  const { data: tenant, error: tenantErr } = await supabase
    .from('tenants')
    .insert({ name, slug, plan, settings })
    .select()
    .single();

  if (tenantErr) {
    if (tenantErr.code === '23505') {
      return { error: 'Tenant slug already exists', status: 409 };
    }
    logger.error('[tenant-manager] createTenant error:', tenantErr);
    return { error: 'Failed to create tenant', status: 500 };
  }

  // Create default production environment
  const { error: envErr } = await supabase
    .from('tenant_environments')
    .insert({ tenant_id: tenant.tenant_id, name: 'production' });

  if (envErr) {
    logger.error('[tenant-manager] createTenant environment error:', envErr);
    // Tenant was created but env failed — still return tenant
  }

  // Add the creator as owner
  if (userRef) {
    const { error: memberErr } = await supabase
      .from('tenant_members')
      .insert({
        tenant_id: tenant.tenant_id,
        user_ref: userRef,
        role: 'owner',
        accepted_at: new Date().toISOString(),
      });

    if (memberErr) {
      logger.error('[tenant-manager] createTenant owner membership error:', memberErr);
    }
  }

  return { tenant };
}

/**
 * Get tenant details with member count and environment list.
 */
export async function getTenant(tenantId) {
  const supabase = getServiceClient();

  const { data: tenant, error: tenantErr } = await supabase
    .from('tenants')
    .select('*')
    .eq('tenant_id', tenantId)
    .maybeSingle();

  if (tenantErr) {
    logger.error('[tenant-manager] getTenant error:', tenantErr);
    return { error: 'Failed to fetch tenant', status: 500 };
  }

  if (!tenant) {
    return { error: 'Tenant not found', status: 404 };
  }

  // Fetch environments
  const { data: environments } = await supabase
    .from('tenant_environments')
    .select('environment_id, name, config, created_at')
    .eq('tenant_id', tenantId)
    .order('created_at');

  // Fetch member count
  const { count: memberCount } = await supabase
    .from('tenant_members')
    .select('member_id', { count: 'exact', head: true })
    .eq('tenant_id', tenantId);

  return {
    ...tenant,
    environments: environments || [],
    member_count: memberCount || 0,
  };
}

/**
 * Update tenant settings/plan/name.
 */
export async function updateTenant(tenantId, updates) {
  const supabase = getServiceClient();

  // Only allow safe fields
  const allowed: { name?: string; plan?: string; settings?: Record<string, unknown> } = {};
  if (updates.name !== undefined) allowed.name = updates.name;
  if (updates.plan !== undefined) allowed.plan = updates.plan;
  if (updates.settings !== undefined) allowed.settings = updates.settings;

  if (Object.keys(allowed).length === 0) {
    return { error: 'No valid fields to update', status: 400 };
  }

  const { data: tenant, error } = await supabase
    .from('tenants')
    .update(allowed)
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .select()
    .single();

  if (error) {
    logger.error('[tenant-manager] updateTenant error:', error);
    return { error: 'Failed to update tenant', status: 500 };
  }

  if (!tenant) {
    return { error: 'Tenant not found or not active', status: 404 };
  }

  return { tenant };
}

/**
 * Soft-delete: archive the tenant.
 */
export async function archiveTenant(tenantId) {
  const supabase = getServiceClient();

  const { data: tenant, error } = await supabase
    .from('tenants')
    .update({ status: 'archived' })
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .select()
    .single();

  if (error) {
    logger.error('[tenant-manager] archiveTenant error:', error);
    return { error: 'Failed to archive tenant', status: 500 };
  }

  if (!tenant) {
    return { error: 'Tenant not found or already archived', status: 404 };
  }

  return { tenant };
}

// ── Members ──────────────────────────────────────────────────────────────────

/**
 * Invite a member to the tenant.
 */
export async function inviteMember(tenantId, userRef, role = 'member') {
  const supabase = getServiceClient();

  const { data: member, error } = await supabase
    .from('tenant_members')
    .insert({ tenant_id: tenantId, user_ref: userRef, role })
    .select()
    .single();

  if (error) {
    if (error.code === '23505') {
      return { error: 'User is already a member of this tenant', status: 409 };
    }
    logger.error('[tenant-manager] inviteMember error:', error);
    return { error: 'Failed to invite member', status: 500 };
  }

  return { member };
}

/**
 * List members for a tenant.
 */
export async function listMembers(tenantId) {
  const supabase = getServiceClient();

  const { data: members, error } = await supabase
    .from('tenant_members')
    .select('member_id, user_ref, role, invited_at, accepted_at')
    .eq('tenant_id', tenantId)
    .order('invited_at');

  if (error) {
    logger.error('[tenant-manager] listMembers error:', error);
    return { error: 'Failed to list members', status: 500 };
  }

  return { members: members || [] };
}

// ── Environments ─────────────────────────────────────────────────────────────

/**
 * Create an environment for the tenant.
 */
export async function createEnvironment(tenantId, name, config = {}) {
  const supabase = getServiceClient();

  const { data: environment, error } = await supabase
    .from('tenant_environments')
    .insert({ tenant_id: tenantId, name, config })
    .select()
    .single();

  if (error) {
    if (error.code === '23505') {
      return { error: `Environment '${name}' already exists for this tenant`, status: 409 };
    }
    logger.error('[tenant-manager] createEnvironment error:', error);
    return { error: 'Failed to create environment', status: 500 };
  }

  return { environment };
}

/**
 * List environments for a tenant.
 */
export async function listEnvironments(tenantId) {
  const supabase = getServiceClient();

  const { data: environments, error } = await supabase
    .from('tenant_environments')
    .select('environment_id, name, config, created_at')
    .eq('tenant_id', tenantId)
    .order('created_at');

  if (error) {
    logger.error('[tenant-manager] listEnvironments error:', error);
    return { error: 'Failed to list environments', status: 500 };
  }

  return { environments: environments || [] };
}

// ── API Keys ─────────────────────────────────────────────────────────────────

export const TENANT_API_KEY_PERMISSIONS = Object.freeze([
  'read',
  'write',
  'admin',
  'policy_rollout',
  'approval_request',
]);
const TENANT_API_KEY_PERMISSION_SET = new Set(TENANT_API_KEY_PERMISSIONS);

/**
 * Validate and de-duplicate an explicit tenant API-key permission grant.
 * An omitted grant is handled by generateApiKey so existing callers retain
 * the database default of read + write.
 */
export function validateTenantApiKeyPermissions(permissions) {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    return {
      error: 'permissions must be a non-empty array containing only read, write, admin, policy_rollout, or approval_request',
      status: 400,
    };
  }

  const normalized: string[] = [];
  for (const permission of permissions) {
    if (typeof permission !== 'string' || !TENANT_API_KEY_PERMISSION_SET.has(permission)) {
      return {
        error: 'permissions must be a non-empty array containing only read, write, admin, policy_rollout, or approval_request',
        status: 400,
      };
    }
    if (!normalized.includes(permission)) normalized.push(permission);
  }

  return { permissions: normalized };
}

/**
 * Generate a new API key for a tenant + environment.
 * Returns the full key exactly once — it is never stored.
 *
 * When permissions is omitted, the tenant_api_keys database default is used
 * for backward compatibility. New issuance routes should pass an explicit,
 * validated least-privilege grant.
 *
 * @param {string} tenantId
 * @param {string} environment
 * @param {string} name
 * @param {string[]|undefined} permissions
 * @param {{expiresAt?: string, issuedBy?: string}} options
 */
export async function generateApiKey(
  tenantId,
  environment = 'production',
  name,
  permissions,
  { expiresAt, issuedBy }: { expiresAt?: string; issuedBy?: string } = {},
) {
  let normalizedPermissions;
  if (permissions !== undefined) {
    const validation = validateTenantApiKeyPermissions(permissions);
    if (validation.error) return validation;
    normalizedPermissions = validation.permissions;
  }

  const supabase = getServiceClient();

  const rawKeyPrefix = environment === 'production' ? 'ept_live_' : 'ept_test_';
  const rawKey = `${rawKeyPrefix}${crypto.randomBytes(32).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKeyPrefix.slice(0, -1);

  const keyRecord = {
      tenant_id: tenantId,
      environment,
      key_hash: keyHash,
      key_prefix: keyPrefix,
      name,
      ...(normalizedPermissions ? { permissions: normalizedPermissions } : {}),
      ...(expiresAt ? { expires_at: expiresAt } : {}),
  };

  let apiKey;
  let error;
  if (issuedBy) {
    ({ data: apiKey, error } = await supabase.rpc('issue_tenant_api_key_audited', {
      p_tenant_id: tenantId,
      p_environment: environment,
      p_key_hash: keyHash,
      p_key_prefix: keyPrefix,
      p_name: name,
      p_permissions: normalizedPermissions,
      p_expires_at: expiresAt,
      p_issued_by: issuedBy,
    }));
  } else {
    ({ data: apiKey, error } = await supabase
      .from('tenant_api_keys')
      .insert(keyRecord)
      .select('key_id, tenant_id, environment, key_prefix, name, permissions, created_at, expires_at')
      .single());
  }

  if (error) {
    logger.error('[tenant-manager] generateApiKey error:', error);
    return { error: 'Failed to generate API key', status: 500 };
  }

  // Return full key only on creation
  return { api_key: { ...apiKey, key: rawKey } };
}

/**
 * List API keys for a tenant (prefix only, never the full key).
 */
export async function listApiKeys(tenantId) {
  const supabase = getServiceClient();

  const { data: keys, error } = await supabase
    .from('tenant_api_keys')
    .select('key_id, environment, key_prefix, name, permissions, created_at, expires_at, revoked_at')
    .eq('tenant_id', tenantId)
    .is('revoked_at', null)
    .order('created_at', { ascending: false });

  if (error) {
    logger.error('[tenant-manager] listApiKeys error:', error);
    return { error: 'Failed to list API keys', status: 500 };
  }

  return { api_keys: keys || [] };
}

/**
 * Revoke an API key by setting revoked_at.
 */
export async function revokeApiKey(keyId) {
  const supabase = getServiceClient();

  const { data: key, error } = await supabase
    .from('tenant_api_keys')
    .update({ revoked_at: new Date().toISOString() })
    .eq('key_id', keyId)
    .is('revoked_at', null)
    .select('key_id, key_prefix, name, revoked_at')
    .single();

  if (error) {
    logger.error('[tenant-manager] revokeApiKey error:', error);
    return { error: 'Failed to revoke API key', status: 500 };
  }

  if (!key) {
    return { error: 'API key not found or already revoked', status: 404 };
  }

  return { key };
}

/**
 * Resolve tenant and environment from a key hash.
 * Used for authenticating tenant-scoped API requests.
 */
export async function resolveApiKey(keyHash) {
  const supabase = getServiceClient();

  const { data: key, error } = await supabase
    .from('tenant_api_keys')
    .select('key_id, tenant_id, environment, permissions, expires_at, revoked_at')
    .eq('key_hash', keyHash)
    .maybeSingle();

  if (error) {
    logger.error('[tenant-manager] resolveApiKey error:', error);
    return { error: 'Key resolution failed', status: 500 };
  }

  if (!key) {
    return { error: 'API key not found', status: 401 };
  }

  if (key.revoked_at) {
    return { error: 'API key has been revoked', status: 403 };
  }

  if (key.expires_at && new Date(key.expires_at) < new Date()) {
    return { error: 'API key has expired', status: 403 };
  }

  // Fetch tenant to check status
  const { data: tenant } = await supabase
    .from('tenants')
    .select('tenant_id, name, slug, status, plan')
    .eq('tenant_id', key.tenant_id)
    .maybeSingle();

  if (!tenant || tenant.status !== 'active') {
    return { error: 'Tenant is not active', status: 403 };
  }

  return {
    tenant,
    environment: key.environment,
    permissions: key.permissions,
    key_id: key.key_id,
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * List tenants for a given user (by user_ref).
 */
export async function listTenantsForUser(userRef) {
  const supabase = getServiceClient();

  const { data: memberships, error } = await supabase
    .from('tenant_members')
    .select(`
      role,
      tenants (
        tenant_id, name, slug, status, plan, created_at, updated_at
      )
    `)
    .eq('user_ref', userRef);

  if (error) {
    logger.error('[tenant-manager] listTenantsForUser error:', error);
    return { error: 'Failed to list tenants', status: 500 };
  }

  const tenants = (memberships || [])
    .filter((m) => m.tenants)
    .map((m) => ({ ...m.tenants, role: m.role }));

  return { tenants };
}

/**
 * Check if a user has the required role (or higher) on a tenant.
 */
const ROLE_HIERARCHY = { owner: 4, admin: 3, member: 2, viewer: 1 };

export async function checkMemberRole(tenantId, userRef, requiredRole = 'member') {
  const supabase = getServiceClient();

  const { data: member, error } = await supabase
    .from('tenant_members')
    .select('role')
    .eq('tenant_id', tenantId)
    .eq('user_ref', userRef)
    .maybeSingle();

  if (error) {
    logger.error('[tenant-manager] checkMemberRole error:', error);
    return { authorized: false, error: 'Failed to check membership' };
  }

  if (!member) {
    return { authorized: false, error: 'Not a member of this tenant' };
  }

  const hasRole = (ROLE_HIERARCHY[member.role] || 0) >= (ROLE_HIERARCHY[requiredRole] || 0);
  return { authorized: hasRole, role: member.role };
}
