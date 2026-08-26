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

function callerOrganizationId(auth: AuthLike | null | undefined): string {
  const entity = auth?.entity;
  return (entity && typeof entity === 'object') ? (entity.organization_id || '') : '';
}

function hasReceiptCapability(
  auth: AuthLike | null | undefined,
  permission: string,
): boolean {
  const permissions = auth?.permissions;
  return Array.isArray(permissions)
    && (permissions.includes(permission) || permissions.includes('admin'));
}

function isReceiptCreator(
  auth: AuthLike | null | undefined,
  { creatorActorId }: ReceiptScope,
): boolean {
  const callerId = callerEntityId(auth);
  return Boolean(callerId && creatorActorId && callerId === creatorActorId);
}

function isSameOrganization(
  auth: AuthLike | null | undefined,
  { organizationId }: ReceiptScope,
): boolean {
  const callerOrg = callerOrganizationId(auth);
  return Boolean(callerOrg && organizationId && callerOrg === organizationId);
}

/**
 * Read-side actor and tenant scoping. Organization membership is a necessary
 * tenant boundary, not receipt-level authorization. Fail-closed:
 *   - the creating actor may read its own receipt;
 *   - a same-organization peer needs the named receipt capability (or admin);
 *   - cross-organization callers are refused even if they hold admin.
 * Callers should map a false result to 404 (don't reveal the receipt exists).
 *
 * @param auth   authenticateRequest() result
 * @returns true if the caller is authorized to read this receipt
 */
export function canReadReceipt(
  auth: AuthLike | null | undefined,
  { organizationId, creatorActorId }: ReceiptScope = {},
  permission = 'receipt.read',
): boolean {
  const receipt = { organizationId, creatorActorId };
  if (isReceiptCreator(auth, receipt)) return true;
  return isSameOrganization(auth, receipt) && hasReceiptCapability(auth, permission);
}

/**
 * Mutation-side receipt authorization. The creator remains compatible with
 * the existing receipt flow. A peer service must be in the same organization
 * and hold the exact operation capability (or admin).
 */
export function canMutateReceipt(
  auth: AuthLike | null | undefined,
  receipt: ReceiptScope,
  permission: string,
): boolean {
  if (isReceiptCreator(auth, receipt)) return true;
  return isSameOrganization(auth, receipt) && hasReceiptCapability(auth, permission);
}
