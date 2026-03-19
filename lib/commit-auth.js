/**
 * EMILIA Protocol — Commit Authorization Helpers
 *
 * Shared authorization checks for commit routes. Every commit route
 * authenticates via API key, but authentication != authorization.
 * These helpers enforce that the caller actually has the right to
 * act on a given commit.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';

/**
 * Check whether the authenticated caller may access/act on a commit.
 *
 * Authorized callers are:
 *   1. The issuing entity  (commit.entity_id === auth.entity.entity_id)
 *   2. The principal on the commit (commit.principal_id === auth.entity.entity_id)
 *
 * @param {Object} auth  - The auth object from authenticateRequest()
 * @param {Object} commit - The commit record from the database
 * @param {string} action - Human-readable action for the error message (e.g. "view", "revoke")
 * @returns {{ authorized: boolean, reason?: string }}
 */
export function authorizeCommitAccess(auth, commit, action) {
  const isIssuer = commit.entity_id === auth.entity.entity_id;
  const isPrincipal = commit.principal_id && commit.principal_id === auth.entity.entity_id;
  if (!isIssuer && !isPrincipal) {
    return { authorized: false, reason: `Only the issuing entity or principal can ${action} this commit` };
  }
  return { authorized: true };
}

/**
 * Check whether the caller may issue a commit on behalf of `targetEntityId`.
 *
 * The caller is allowed if:
 *   1. They ARE the target entity, OR
 *   2. They hold a verified, active delegation from the target entity
 *      that permits the requested action type.
 *
 * @param {Object} auth - The auth object from authenticateRequest()
 * @param {string} targetEntityId - The entity_id the commit is being issued for
 * @param {string|null} delegationId - Optional delegation_id supplied in the request
 * @param {string|null} actionType - The action_type for scope checking
 * @returns {Promise<{ authorized: boolean, reason?: string }>}
 */
export async function authorizeCommitIssuance(auth, targetEntityId, delegationId, actionType) {
  // Self-issuance is always allowed
  if (targetEntityId === auth.entity.entity_id) {
    return { authorized: true };
  }

  // Not self — must have a verified delegation
  if (!delegationId) {
    return {
      authorized: false,
      reason: 'Cannot issue commits for other entities without a verified delegation',
    };
  }

  // Verify the delegation exists, is active, and covers this action
  const supabase = getServiceClient();
  const { data: delegation, error } = await supabase
    .from('delegations')
    .select('*')
    .eq('delegation_id', delegationId)
    .maybeSingle();

  // If delegations table doesn't exist yet, deny (fail closed)
  if (error?.code === '42P01' || !delegation) {
    return {
      authorized: false,
      reason: 'Cannot issue commits for other entities without a verified delegation',
    };
  }

  // The delegation must grant the caller (agent) the right to act for the target (principal)
  if (delegation.agent_entity_id !== auth.entity.entity_id) {
    return {
      authorized: false,
      reason: 'Delegation does not authorize this caller',
    };
  }

  if (delegation.principal_id !== targetEntityId) {
    return {
      authorized: false,
      reason: 'Delegation principal does not match target entity',
    };
  }

  if (delegation.status !== 'active') {
    return {
      authorized: false,
      reason: `Delegation is ${delegation.status}`,
    };
  }

  // Check expiry
  if (new Date(delegation.expires_at) < new Date()) {
    return {
      authorized: false,
      reason: 'Delegation has expired',
    };
  }

  // Check scope covers the action type
  if (actionType && !delegation.scope.includes(actionType) && !delegation.scope.includes('*')) {
    return {
      authorized: false,
      reason: `Delegation scope does not include action type "${actionType}"`,
    };
  }

  return { authorized: true };
}
