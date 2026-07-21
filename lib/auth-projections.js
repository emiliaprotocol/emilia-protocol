// Generated from auth-projections.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Authenticated-actor projections.
 *
 * Route handlers must not forward the complete authenticated entity row. This
 * module exposes the narrow identity and capability projections each caller
 * needs, keeping api_key_hash and future sensitive columns out of write paths.
 *
 * @license Apache-2.0
 */
/**
 * Every function here accepts `unknown` for `auth`: callers across the repo
 * pass whatever authenticateRequest()/authenticateCloudRequest() produced,
 * and those authenticators are not themselves typed yet. This is the single
 * narrowing point — every function below reads `.entity` through this cast
 * rather than widening (or wrongly narrowing) its own public parameter type.
 */
function entityOf(auth) {
    return auth?.entity;
}
/** Resolve the stable protocol identity of an authenticated entity. */
export function authEntityId(auth) {
    const e = entityOf(auth);
    if (typeof e === 'string')
        return e;
    return e?.entity_id || e?.id || '';
}
/** Resolve the database primary key of an authenticated entity. */
export function authEntityDbId(auth) {
    const e = entityOf(auth);
    if (typeof e === 'string')
        return e;
    return e?.id || e?.entity_id || '';
}
/** Return the minimum actor shape required by canonical writers. */
export function authEntityActor(auth) {
    const e = entityOf(auth);
    if (!e)
        return null;
    if (typeof e === 'string')
        return { id: e, entity_id: e };
    const id = e.id || e.entity_id || '';
    const entity_id = e.entity_id || e.id || '';
    return { id, entity_id };
}
/** Resolve the authenticated entity's organization without forwarding its row. */
export function authEntityOrganizationId(auth) {
    const e = entityOf(auth);
    return typeof e === 'object' ? (e?.organization_id || null) : null;
}
/**
 * Return only the non-secret fields needed to classify a pilot observe key.
 * This keeps raw authenticated entity rows out of route authorization code.
 */
export function authEntityObserveProfile(auth) {
    const e = entityOf(auth);
    if (!e || typeof e !== 'object' || Array.isArray(e))
        return null;
    return {
        metadata: e.metadata,
        entity_id: e.entity_id,
        organization_id: e.organization_id,
        display_name: e.display_name,
        description: e.description,
        entity_type: e.entity_type,
    };
}
/** Resolve the reviewed operator bit without exposing the authenticated row. */
export function authEntityIsOperator(auth) {
    const e = entityOf(auth);
    return typeof e === 'object' && e?.is_operator === true;
}
/** Resolve the score needed by the legacy needs compatibility path. */
export function authEntityScore(auth) {
    const e = entityOf(auth);
    return typeof e === 'object' && Number.isFinite(e?.emilia_score) ? e?.emilia_score : 50;
}
/** Whitelisted submitter projection for the legacy receipt helper. */
export function authEntityReceiptSubmitter(auth) {
    const e = entityOf(auth);
    if (!e)
        return null;
    if (typeof e === 'string')
        return { id: e, entity_id: e };
    return {
        id: e.id || e.entity_id || '',
        entity_id: e.entity_id || e.id || '',
        emilia_score: Number.isFinite(e.emilia_score) ? e.emilia_score : 50,
        public_key: e.public_key || null,
    };
}
