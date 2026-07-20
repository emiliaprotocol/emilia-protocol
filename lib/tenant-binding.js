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

/**
 * @typedef {{organization_id?: string, entity_id?: string, id?: string}} AuthEntityRow
 *   projected shape of the entities row returned by resolve_authenticated_actor
 * @typedef {{entity?: AuthEntityRow|string, permissions?: string[]}} AuthResult
 *   the authenticateRequest() result
 */

/**
 * Resolve the organization a request is authorized to act under.
 *
 * @param {AuthResult} auth                the authenticateRequest() result
 * @param {string|undefined} bodyOrgId     organization_id from the request body
 * @param {{requireBound?: boolean}} [opts] requireBound rejects unbound entities (fail-closed)
 * @returns {{organizationId?: string, unbound?: boolean,
 *            error?: {status:number, code:string, detail:string}}}
 */
export function resolveAuthorizedOrg(auth, bodyOrgId, opts = {}) {
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

/**
 * The stable string identity of the authenticated entity (mirrors authEntityId).
 * @param {AuthResult} auth
 * @returns {string}
 */
function callerEntityId(auth) {
  const e = auth?.entity;
  if (typeof e === 'string') return e;
  return (e && (e.entity_id || e.id)) || '';
}

/**
 * Read-side tenant scoping. The write path binds receipts to the authenticated
 * entity's org (resolveAuthorizedOrg + requireBound); the read paths must scope
 * the same way or they leak cross-tenant (IDOR). Fail-closed:
 *   - an org-bound caller may read ONLY receipts in its own organization;
 *   - an unbound caller (transitional) may read ONLY receipts it created.
 * Callers should map a false result to 404 (don't reveal the receipt exists).
 *
 * @param {AuthResult} auth   authenticateRequest() result
 * @param {{organizationId?: string, creatorActorId?: string}} receipt
 * @returns {boolean} true if the caller is authorized to read this receipt
 */
export function canReadReceipt(auth, { organizationId, creatorActorId } = {}) {
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
 *
 * @param {AuthResult} auth
 * @param {{organizationId?: string, creatorActorId?: string}} receipt
 * @param {string} permission
 * @returns {boolean}
 */
export function canMutateReceipt(auth, receipt, permission) {
  if (!canReadReceipt(auth, receipt)) return false;
  const callerId = callerEntityId(auth);
  if (callerId && receipt?.creatorActorId && callerId === receipt.creatorActorId) return true;
  const permissions = auth?.permissions;
  return Array.isArray(permissions)
    && (permissions.includes(permission) || permissions.includes('admin'));
}
