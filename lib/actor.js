/**
 * Shared actor resolution utility.
 *
 * Normalizes the many shapes an "actor" reference can take across the
 * protocol (string ID, entity object, null/undefined) into a single
 * string entity ID.
 *
 * @license Apache-2.0
 */

/**
 * Resolve an actor reference to a string entity ID.
 * Accepts: string, { entity_id }, { id }, null/undefined.
 * Returns: string (never null/undefined).
 *
 * @param {string|object|null|undefined} actor
 * @param {string} [fallback='system'] — value when actor is falsy or unresolvable
 * @returns {string}
 */
export function resolveActorRef(actor, fallback = 'system') {
  if (!actor) return fallback;
  if (typeof actor === 'string') return actor;
  if (typeof actor === 'object') return actor.entity_id || actor.id || fallback;
  return fallback;
}
