/**
 * Shared actor resolution utility.
 *
 * Normalizes the many shapes an "actor" reference can take across the
 * protocol (string ID, entity object, null/undefined) into a single
 * string entity ID.
 *
 * @license Apache-2.0
 */

export type ActorRef = string | { entity_id?: string; id?: string } | null | undefined;

/**
 * Resolve an actor reference to a string entity ID.
 * Accepts: string, { entity_id }, { id }, null/undefined.
 * Returns: string (never null/undefined).
 *
 * @param actor
 * @param fallback - value when actor is falsy or unresolvable
 */
export function resolveActorRef(actor: ActorRef, fallback: string = 'system'): string {
  if (!actor) return fallback;
  if (typeof actor === 'string') return actor;
  if (typeof actor === 'object') return actor.entity_id || actor.id || fallback;
  return fallback;
}
