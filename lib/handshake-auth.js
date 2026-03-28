/**
 * EP Handshake — Authorization helpers.
 *
 * Canonical authorization layer for handshake access control.
 * Addresses audit Finding 2: "Routes authenticate but do not authorize
 * by party membership."
 *
 * Every handshake operation must pass through one of these guards before
 * executing. The system actor ('system') bypasses all checks.
 *
 * @license Apache-2.0
 */

import { HandshakeError } from '@/lib/handshake/errors.js';

const SYSTEM_ACTOR = 'system';
const UNAUTHORIZED_CODE = 'UNAUTHORIZED_HANDSHAKE_ACCESS';

/**
 * Normalize an actor (object or string) to a string entity ID.
 * Accepts: string, { entity_id }, { id }, { entity_ref }.
 */
export function resolveAuthEntityId(actor) {
  if (!actor) return null;
  if (typeof actor === 'string') return actor;
  return actor.entity_id || actor.id || actor.entity_ref || null;
}

/**
 * Fetch all party rows for a given handshake.
 * @private
 */
async function fetchHandshakeParties(supabase, handshakeId) {
  const { data, error } = await supabase
    .from('handshake_parties')
    .select('entity_ref, party_role')
    .eq('handshake_id', handshakeId);

  if (error) {
    throw new HandshakeError(
      `Failed to look up handshake parties: ${error.message}`,
      500,
      'HANDSHAKE_PARTY_LOOKUP_FAILED',
    );
  }

  return data || [];
}

/**
 * Reject with a 403 HandshakeError.
 * @private
 */
function denyAccess(detail) {
  throw new HandshakeError(detail, 403, UNAUTHORIZED_CODE);
}

// ── Public authorization guards ─────────────────────────────────────────────

/**
 * Authorize read access to a handshake.
 * Caller must be a party on the handshake (any role).
 */
export async function authorizeHandshakeRead(supabase, authEntityId, handshakeId) {
  if (authEntityId === SYSTEM_ACTOR) return;

  const parties = await fetchHandshakeParties(supabase, handshakeId);
  const isMember = parties.some((p) => p.entity_ref === authEntityId);

  if (!isMember) {
    denyAccess('Caller is not a party on this handshake');
  }
}

/**
 * Authorize presentation to a handshake.
 * Caller must own the specific party_role's entity_ref.
 */
export async function authorizeHandshakePresent(supabase, authEntityId, handshakeId, partyRole) {
  if (authEntityId === SYSTEM_ACTOR) return;

  const parties = await fetchHandshakeParties(supabase, handshakeId);
  const roleParty = parties.find((p) => p.party_role === partyRole);

  if (!roleParty) {
    denyAccess(`No party with role '${partyRole}' exists on this handshake`);
  }

  if (roleParty.entity_ref !== authEntityId) {
    denyAccess(`Caller does not own the '${partyRole}' party role on this handshake`);
  }
}

/**
 * Authorize verification of a handshake.
 * Caller must be the initiator, responder, or a policy-designated verifier.
 */
export async function authorizeHandshakeVerify(supabase, authEntityId, handshakeId) {
  if (authEntityId === SYSTEM_ACTOR) return;

  const parties = await fetchHandshakeParties(supabase, handshakeId);
  const VERIFY_ROLES = new Set(['initiator', 'responder', 'verifier']);
  const isAuthorized = parties.some(
    (p) => p.entity_ref === authEntityId && VERIFY_ROLES.has(p.party_role),
  );

  if (!isAuthorized) {
    denyAccess('Caller is not authorized to verify this handshake');
  }
}

/**
 * Authorize revocation of a handshake.
 * Only the initiator or the system actor may revoke.
 */
export async function authorizeHandshakeRevoke(supabase, authEntityId, handshakeId) {
  if (authEntityId === SYSTEM_ACTOR) return;

  const parties = await fetchHandshakeParties(supabase, handshakeId);
  const isInitiator = parties.some(
    (p) => p.entity_ref === authEntityId && p.party_role === 'initiator',
  );

  if (!isInitiator) {
    denyAccess('Only the initiator may revoke a handshake');
  }
}
