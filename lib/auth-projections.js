/**
 * Authenticated-actor projections.
 *
 * Route handlers must not forward the complete authenticated entity row. This
 * module exposes the narrow identity and capability projections each caller
 * needs, keeping api_key_hash and future sensitive columns out of write paths.
 *
 * @license Apache-2.0
 */

/* eslint-disable ep-security/no-raw-auth-entity -- this file is the audited projection boundary */

/** Resolve the stable protocol identity of an authenticated entity. */
export function authEntityId(auth) {
  const e = auth?.entity;
  if (typeof e === 'string') return e;
  return e?.entity_id || e?.id || '';
}

/** Resolve the database primary key of an authenticated entity. */
export function authEntityDbId(auth) {
  const e = auth?.entity;
  if (typeof e === 'string') return e;
  return e?.id || e?.entity_id || '';
}

/** Return the minimum actor shape required by canonical writers. */
export function authEntityActor(auth) {
  const e = auth?.entity;
  if (!e) return null;
  if (typeof e === 'string') return { id: e, entity_id: e };

  const id = e.id || e.entity_id || '';
  const entity_id = e.entity_id || e.id || '';
  return { id, entity_id };
}

/** Resolve the authenticated entity's organization without forwarding its row. */
export function authEntityOrganizationId(auth) {
  const e = auth?.entity;
  return typeof e === 'object' ? (e?.organization_id || null) : null;
}

/** Resolve the reviewed operator bit without exposing the authenticated row. */
export function authEntityIsOperator(auth) {
  const e = auth?.entity;
  return typeof e === 'object' && e?.is_operator === true;
}

/** Resolve the score needed by the legacy needs compatibility path. */
export function authEntityScore(auth) {
  const e = auth?.entity;
  return typeof e === 'object' && Number.isFinite(e?.emilia_score) ? e.emilia_score : 50;
}

/** Whitelisted submitter projection for the legacy receipt helper. */
export function authEntityReceiptSubmitter(auth) {
  const e = auth?.entity;
  if (!e) return null;
  if (typeof e === 'string') return { id: e, entity_id: e };
  return {
    id: e.id || e.entity_id || '',
    entity_id: e.entity_id || e.id || '',
    emilia_score: Number.isFinite(e.emilia_score) ? e.emilia_score : 50,
    public_key: e.public_key || null,
  };
}
