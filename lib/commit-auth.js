/**
 * EMILIA Protocol — Commit Authorization Helpers
 *
 * Shared authorization checks for commit routes. Every commit route
 * authenticates via API key, but authentication != authorization.
 * These helpers enforce that the caller actually has the right to
 * act on a given commit.
 *
 * Delegation verification is delegated to lib/delegation.js — the single
 * canonical source of truth for delegation logic. This file does NOT
 * query the delegations table directly.
 *
 * @license Apache-2.0
 */

import { verifyDelegation } from '@/lib/delegation';

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
 * Delegation verification uses lib/delegation.js — the same canonical logic
 * used by lib/commit.js issueCommit() and all other delegation-aware surfaces.
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

  // Use the canonical delegation verification from lib/delegation.js
  const result = await verifyDelegation(delegationId, actionType);

  if (!result.valid) {
    return {
      authorized: false,
      reason: result.reason || 'Delegation verification failed',
    };
  }

  // Verify the delegation grants the caller (agent) the right to act for the target (principal)
  if (result.agent_entity_id !== auth.entity.entity_id) {
    return {
      authorized: false,
      reason: 'Delegation does not authorize this caller',
    };
  }

  if (result.principal_id !== targetEntityId) {
    return {
      authorized: false,
      reason: 'Delegation principal does not match target entity',
    };
  }

  // If action type was checked and not permitted
  if (actionType && result.action_permitted === false) {
    return {
      authorized: false,
      reason: result.reason || `Action "${actionType}" not permitted by delegation`,
    };
  }

  return { authorized: true };
}
