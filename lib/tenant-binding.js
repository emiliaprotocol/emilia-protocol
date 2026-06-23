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

/**
 * Resolve the organization a request is authorized to act under.
 *
 * @param {{entity?: object|string}} auth  the authenticateRequest() result
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
