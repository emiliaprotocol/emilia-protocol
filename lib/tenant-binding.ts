// SPDX-License-Identifier: Apache-2.0
// Tenant/org binding: derive the organization from the AUTHENTICATED entity,
// never trust it from the request body.
//
// Root cause this addresses: the v1 API authenticates a protocol entity
// (api_keys -> resolve_authenticated_actor -> entities row) and historically
// took organization_id from the request body. An authenticated caller could
// therefore scope receipts to ANY org by passing it. resolve_authenticated_actor
// returns the full entities row, so once entities.organization_id is set
// (migration 101), it surfaces on auth.entity.organization_id and becomes the
// authoritative source.
//
// Rollout is two-step and SAFE by construction:
//   1. (this) Enforce binding whenever the entity IS org-bound; for an
//      not-yet-bound entity, fall back to the body value (transitional) so
//      existing callers/tests are unaffected.
//   2. After backfilling entities.organization_id, set requireBound=true at the
//      call sites (or globally) to make an unbound entity fail closed.

/* eslint-disable ep-security/no-raw-auth-entity -- this file is the audited tenant projection boundary */

import type { AuthResult } from './supabase.js';

/** The shape every function here needs from an authenticateRequest() result. */
export type AuthLike = Pick<AuthResult, 'entity' | 'permissions'>;

export interface ResolveAuthorizedOrgOpts {
  /** Reject unbound entities instead of falling back to the body value (fail-closed). */
  requireBound?: boolean;
}

export interface ResolveAuthorizedOrgResult {
  organizationId?: string;
  unbound?: boolean;
  error?: { status: number; code: string; detail: string };
}

/**
 * Resolve the organization a request is authorized to act under.
 *
 * @param auth  the authenticateRequest() result
 * @param bodyOrgId organization_id from the request body
 * @param opts requireBound rejects unbound entities (fail-closed)
 */
export function resolveAuthorizedOrg(
  auth: AuthLike | null | undefined,
  bodyOrgId: string | undefined,
  opts: ResolveAuthorizedOrgOpts = {},
): ResolveAuthorizedOrgResult {
  const entity = auth?.entity;
  const authedOrg = (entity && typeof entity === 'object')
    ? (entity.organization_id || null)
    : null;

  if (authedOrg) {
    // The authenticated entity's org is the source of truth. If the caller
    // also supplied one, it is a cross-check that MUST match — a mismatch is a
    // cross-tenant attempt, not a typo.
    if (bodyOrgId && bodyOrgId !== authedOrg) {
      return {
        error: {
          status: 403,
          code: 'organization_mismatch',
          detail: 'organization_id does not match the authenticated entity',
        },
      };
    }
    return { organizationId: authedOrg };
  }

  // Entity is not org-bound yet.
  if (opts.requireBound) {
    return {
      error: {
        status: 403,
        code: 'entity_not_org_bound',
        detail: 'Authenticated entity is not bound to an organization',
      },
    };
  }
  if (!bodyOrgId) {
    return {
      error: { status: 400, code: 'missing_organization_id', detail: 'organization_id is required' },
    };
  }
  return { organizationId: bodyOrgId, unbound: true };
}

/** The stable string identity of the authenticated entity (mirrors authEntityId). */
function callerEntityId(auth: AuthLike | null | undefined): string {
  const e = auth?.entity;
  if (typeof e === 'string') return e;
  return (e && (e.entity_id || e.id)) || '';
}

export interface ReceiptScope {
  organizationId?: string;
  creatorActorId?: string;
}

/**
 * Read-side tenant scoping. The write path binds receipts to the authenticated
 * entity's org (resolveAuthorizedOrg + requireBound); the read paths must scope
 * the same way or they leak cross-tenant (IDOR). Fail-closed:
 *   - an org-bound caller may read ONLY receipts in its own organization;
 *   - an unbound caller (transitional) may read ONLY receipts it created.
 * Callers should map a false result to 404 (don't reveal the receipt exists).
 *
 * @param auth   authenticateRequest() result
 * @returns true if the caller is authorized to read this receipt
 */
export function canReadReceipt(
  auth: AuthLike | null | undefined,
  { organizationId, creatorActorId }: ReceiptScope = {},
): boolean {
  const callerId = callerEntityId(auth);
  // The creator may always read its own receipt (it can't be another tenant's).
  if (callerId && creatorActorId && callerId === creatorActorId) return true;
  // Otherwise an org-bound caller may read only receipts in its own organization.
  const entity = auth?.entity;
  const callerOrg = (entity && typeof entity === 'object') ? (entity.organization_id || null) : null;
  if (callerOrg && organizationId) return callerOrg === organizationId;
  // Unbound non-creator, or a receipt with no org to scope against: fail closed.
  return false;
}

/**
 * Mutation-side receipt authorization. Organization membership is sufficient
 * to inspect a receipt, but it must not also grant consume or execution
 * authority. The creator remains compatible with the existing receipt flow;
 * peer services need an explicit capability.
 */
export function canMutateReceipt(
  auth: AuthLike | null | undefined,
  receipt: ReceiptScope,
  permission: string,
): boolean {
  if (!canReadReceipt(auth, receipt)) return false;
  const callerId = callerEntityId(auth);
  if (callerId && receipt?.creatorActorId && callerId === receipt.creatorActorId) return true;
  const permissions = auth?.permissions;
  return Array.isArray(permissions)
    && (permissions.includes(permission) || permissions.includes('admin'));
}
